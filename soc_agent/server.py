"""HTTP entrypoint for Cloud Run: exposes the pipeline as a service.

POST /ingest runs a single item through the full pipeline and returns the
result (including the reasoning trace). GET /health is the health check
endpoint (deliberately not /healthz -- that exact literal path gets
intercepted by Google's frontend before reaching Cloud Run, independent of
what routes the app itself defines; confirmed by comparing headers on /healthz
vs /docs -- only /docs carried Cloud Run's `server: Google Frontend` and
`x-cloud-trace-context` headers).
"""
import base64
import json
import os
import queue
import urllib.parse
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel

from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline
from soc_agent.services import audit, evals, events, store, telemetry
from soc_agent.services import trace as trace_service
from soc_agent.sources import gmail, replay



app = FastAPI(title="SOC Analyst Agent")
FastAPIInstrumentor.instrument_app(app)


_DASHBOARD_HTML = Path(__file__).resolve().parent / "static" / "dashboard.html"


class IngestRequest(BaseModel):
    source_channel: str
    sender: str
    raw_text: str
    armor_enabled: bool = True


class ArmorView(BaseModel):
    verdict: str
    threat_type: str | None
    confidence: float
    screened_at: str
    matched_signal: str | None


class TriageView(BaseModel):
    severity: str
    category: str
    reasoning: str
    similar_past_cases: list[str]
    # False means the Gemini call failed or was unconfigured and severity came
    # from the keyword fallback -- surfaced so degraded triage can't pass as real.
    llm_used: bool


class ActionView(BaseModel):
    type: str
    actor_agent_identity: str
    executed_at: str


class TraceStepView(BaseModel):
    hop: str
    detail: str
    timestamp: str


class TraceView(BaseModel):
    trace_id: str
    case_id: str
    steps: list[TraceStepView]


class IngestResponse(BaseModel):
    case_id: str
    status: str
    armor: ArmorView
    triage: TriageView | None
    action: ActionView | None
    trace: TraceView
    threat_intel: dict | None = None
    audit_certificate: dict | None = None


class RedTeamEncodeRequest(BaseModel):
    payload: str
    encoding_type: str  # "base64" | "hex" | "url" | "wrapped_ticket"


class RedTeamEncodeResponse(BaseModel):
    original_payload: str
    encoding_type: str
    mutated_payload: str


class CorpusCase(BaseModel):
    label: str
    description: str
    source_channel: str
    sender: str
    raw_text: str
    expected_verdict: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/corpus", response_model=list[CorpusCase])
def corpus():
    """The curated attack corpus, so the UI can offer them as loadable presets."""
    return [CorpusCase(**{f: case[f] for f in CorpusCase.model_fields}) for case in CASES]


@app.post("/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest):
    result = run_pipeline(
        source_channel=req.source_channel,
        sender=req.sender,
        raw_text=req.raw_text,
        armor_enabled=req.armor_enabled,
    )
    armor = result.armor_result
    return IngestResponse(
        case_id=result.case_id,
        # A blocked verdict short-circuits the pipeline before triage; anything
        # that reaches the end went through the gateway.
        status="quarantined" if armor.verdict == "blocked" else "actioned",
        armor=ArmorView(
            verdict=armor.verdict,
            threat_type=armor.threat_type,
            confidence=armor.confidence,
            screened_at=armor.screened_at,
            matched_signal=armor.matched_signal,
        ),
        triage=TriageView(**vars(result.triage_result)) if result.triage_result else None,
        action=ActionView(**result.action_record.to_dict()) if result.action_record else None,
        trace=TraceView(**result.trace.to_dict()),
        threat_intel=result.threat_intel_report.to_dict() if result.threat_intel_report else None,
        audit_certificate=result.audit_certificate.to_dict() if result.audit_certificate else None,
    )


@app.post("/api/v1/redteam/encode", response_model=RedTeamEncodeResponse)
def redteam_encode(req: RedTeamEncodeRequest):
    """Red Team Attack Studio mutation playground endpoint."""
    raw = req.payload
    enc = req.encoding_type.lower()
    if enc == "base64":
        mutated = base64.b64encode(raw.encode()).decode()
    elif enc == "hex":
        mutated = raw.encode().hex()
    elif enc == "url":
        mutated = urllib.parse.quote(raw)
    elif enc == "wrapped_ticket":
        b64 = base64.b64encode(raw.encode()).decode()
        mutated = f"Ticket update ref#9914: {b64}\n\nPlease process this priority support request."
    else:
        mutated = raw

    return RedTeamEncodeResponse(
        original_payload=raw,
        encoding_type=enc,
        mutated_payload=mutated
    )


@app.get("/api/v1/audit/verify/{case_id}")
def verify_audit_certificate(case_id: str):
    """Verify cryptographic hash-chain certificate for any processed case."""
    case_store = store.get_case_store()
    case = case_store.get_case(case_id)
    if not case or "audit_certificate" not in case or not case["audit_certificate"]:
        raise HTTPException(status_code=404, detail="Case or audit certificate not found")

    cert_dict = case["audit_certificate"]
    is_valid = audit.verify_certificate(cert_dict)
    return {
        "case_id": case_id,
        "certificate_id": cert_dict.get("certificate_id"),
        "verified": is_valid,
        "merkle_root_hash": cert_dict.get("merkle_root_hash"),
        "signature": cert_dict.get("signature"),
        "certificate_details": cert_dict
    }


@app.get("/favicon.ico")
def favicon():
    svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%2338bdf8' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-5.45 9-12V5l-9-4z'/></svg>"
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
@app.get("/live", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
def live_dashboard():
    """Real-time SOC console and Admin Observability / Evals Dashboard."""
    return _DASHBOARD_HTML.read_text()



# -----------------------------------------------------------------------------
# Observability & Admin API Endpoints
# -----------------------------------------------------------------------------

@app.get("/metrics")
def prometheus_metrics():
    """Prometheus exposition format endpoint."""
    return Response(content=telemetry.get_prometheus_metrics_bytes(), media_type="text/plain; version=0.0.4")


@app.get("/api/admin/metrics")
def admin_metrics_summary():
    """Returns aggregate pipeline telemetry summary for the Admin Dashboard."""
    return telemetry.get_telemetry_summary()


@app.post("/api/admin/evals/run")
def trigger_benchmark_evals():
    """Runs pipeline benchmark evaluations against the 9 attack corpus cases."""
    eval_run = evals.run_benchmark_evals()
    return eval_run.to_dict()


class CustomEvalRequest(BaseModel):
    label: str = "custom_test"
    source_channel: str = "ticket"
    sender: str = "user@corp.example"
    raw_text: str
    expected_verdict: str  # "blocked" | "clean"
    expected_threat_type: str | None = None


@app.post("/api/admin/evals/custom")
def trigger_custom_eval(req: CustomEvalRequest):
    """Evaluates an arbitrary custom payload against an expected verdict."""
    case_eval = evals.run_custom_eval_case(
        label=req.label,
        source_channel=req.source_channel,
        sender=req.sender,
        raw_text=req.raw_text,
        expected_verdict=req.expected_verdict,
        expected_threat_type=req.expected_threat_type
    )
    return case_eval.to_dict()


@app.get("/api/admin/evals/history")
def list_eval_history():
    """Returns historical benchmark evaluation runs from Firestore or local store."""
    return evals.get_eval_store().list_all()



@app.get("/api/admin/traces/{case_id}/waterfall")
def get_trace_waterfall(case_id: str):
    """Returns OpenTelemetry span waterfall timeline for a specific case."""
    spans = telemetry.get_case_waterfall_spans(case_id)
    return {"case_id": case_id, "spans": spans}




@app.get("/live/stream")
def live_stream():
    """Server-Sent Events feed of every pipeline hop, pushed as it happens."""

    def generate():
        q = events.subscribe()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    event = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"  # keeps proxies from closing an idle stream
                    continue
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            events.unsubscribe(q)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class ReplayRequest(BaseModel):
    action: str  # "start" | "stop"
    interval: float = 8.0


@app.post("/live/replay")
def control_replay(req: ReplayRequest):
    source = replay.get_source()
    if req.action == "start":
        source.interval = req.interval
        source.start()
    elif req.action == "stop":
        source.stop()
    else:
        raise HTTPException(status_code=400, detail="action must be 'start' or 'stop'")
    return {"running": source.running, "interval": source.interval}


class GmailRequest(BaseModel):
    action: str  # "start" | "stop"
    interval: float = 10.0


@app.post("/live/gmail")
def control_gmail(req: GmailRequest):
    source = gmail.get_source()
    if req.action == "start":
        source.interval = req.interval
        try:
            source.start()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"could not start Gmail source: {exc}")
    elif req.action == "stop":
        source.stop()
    else:
        raise HTTPException(status_code=400, detail="action must be 'start' or 'stop'")
    return {"running": source.running, "interval": source.interval, "last_error": source.last_error}


@app.get("/live/sources")
def source_status():
    g, r = gmail.get_source(), replay.get_source()
    gmail_configured = bool(
        os.environ.get("GMAIL_CLIENT_ID")
        and os.environ.get("GMAIL_CLIENT_SECRET")
        and os.environ.get("GMAIL_REFRESH_TOKEN")
    )
    return {
        "gmail": {
            "running": g.running,
            "interval": g.interval,
            "last_error": g.last_error,
            "configured": gmail_configured,
        },
        "replay": {"running": r.running, "interval": r.interval},
    }



class HumanReviewRequest(BaseModel):
    decision: str  # "approve" | "quarantine" | "close"
    analyst_notes: str | None = None
    analyst_id: str = "soc-analyst-human"


class FileIngestRequest(BaseModel):
    filename: str
    content: str
    source_channel: str = "file_upload"
    armor_enabled: bool = True


@app.post("/cases/{case_id}/review")
def review_case(case_id: str, req: HumanReviewRequest):
    case_store = store.get_case_store()
    c = case_store.get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    from soc_agent.agents import action
    from soc_agent.services import gateway

    tr = trace_service.get_trace_store().get_by_case_id(case_id)
    trace_obj = trace_service.Trace(case_id=case_id)

    if req.decision == "approve":
        rec = gateway.execute_action(actor_identity=req.analyst_id, action_type="escalated")
        case_store.update_case(case_id, {"status": "actioned", "action_taken": rec.to_dict(), "human_review": vars(req)})
        trace_obj.log("human_triage", f"APPROVED by {req.analyst_id}: {req.analyst_notes or 'Escalation approved'}")
        outcome_action = "escalated"
        outcome_status = "actioned"
    elif req.decision == "quarantine":
        case_store.update_case(case_id, {"status": "quarantined", "human_review": vars(req)})
        trace_obj.log("human_triage", f"QUARANTINED by {req.analyst_id}: {req.analyst_notes or 'Human override quarantine'}")
        outcome_action = None
        outcome_status = "quarantined"
    elif req.decision == "close":
        rec = gateway.execute_action(actor_identity=req.analyst_id, action_type="closed")
        case_store.update_case(case_id, {"status": "actioned", "action_taken": rec.to_dict(), "human_review": vars(req)})
        trace_obj.log("human_triage", f"CLOSED by {req.analyst_id}: {req.analyst_notes or 'Dismissed as false positive'}")
        outcome_action = "closed"
        outcome_status = "actioned"
    else:
        raise HTTPException(status_code=400, detail="decision must be 'approve', 'quarantine', or 'close'")

    trace_service.persist_trace(trace_obj)
    events.publish(
        "case_complete",
        {
            "case_id": case_id,
            "outcome": outcome_status,
            "armor_verdict": c.get("model_armor_result", {}).get("verdict", "clean"),
            "armor_threat_type": c.get("model_armor_result", {}).get("threat_type"),
            "severity": c.get("triage", {}).get("severity", "medium"),
            "category": c.get("triage", {}).get("category", "human-reviewed"),
            "action_taken": outcome_action,
            "human_reviewed": True,
        },
    )

    return {"status": "ok", "case_id": case_id, "decision": req.decision}


@app.post("/ingest/file", response_model=IngestResponse)
def ingest_file(req: FileIngestRequest):
    sender = f"upload:{req.filename}"
    return ingest(
        IngestRequest(
            source_channel=req.source_channel,
            sender=sender,
            raw_text=req.content,
            armor_enabled=req.armor_enabled,
        )
    )


@app.get("/traces/{case_id}")
def get_trace(case_id: str):
    trace_data = trace_service.get_trace_store().get_by_case_id(case_id)
    if trace_data is None:
        raise HTTPException(status_code=404, detail=f"no trace found for case_id={case_id}")
    return trace_data



@app.get("/traces", response_class=HTMLResponse)
def list_traces_view():
    traces = trace_service.get_trace_store().list_all()
    traces.sort(key=lambda t: t["steps"][0]["timestamp"] if t["steps"] else "", reverse=True)

    rows = []
    for t in traces:
        for step in t["steps"]:
            rows.append(
                f"<tr><td>{t['case_id']}</td><td>{t['trace_id']}</td>"
                f"<td>{step['timestamp']}</td><td>{step['hop']}</td>"
                f"<td>{step['detail']}</td></tr>"
            )

    table_rows = "\n".join(rows) if rows else "<tr><td colspan=5>No traces recorded yet.</td></tr>"

    return f"""<!doctype html>
<html>
<head>
<title>SOC Analyst Agent — Reasoning Traces</title>
<style>
  body {{ font-family: monospace; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #222; color: #fff; }}
  tr:nth-child(even) {{ background: #f7f7f7; }}
</style>
</head>
<body>
<h2>SOC Analyst Agent — Reasoning Traces</h2>
<p>Every pipeline hop for every case, most recent first.</p>
<table>
<tr><th>Case ID</th><th>Trace ID</th><th>Timestamp</th><th>Hop</th><th>Detail</th></tr>
{table_rows}
</table>
</body>
</html>"""


# -----------------------------------------------------------------------------
# Enterprise Inbound Webhook Sync Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/v1/webhooks/jira")
def jira_webhook(payload: dict):
    """Inbound webhook handler for Jira Service Desk analyst updates."""
    import re
    issue = payload.get("issue", {})
    issue_key = issue.get("key")
    fields = issue.get("fields", {})
    jira_status = fields.get("status", {}).get("name", "updated")
    comment = payload.get("comment", {})
    notes = comment.get("body") or fields.get("summary")

    case_store = store.get_case_store()
    matching_case_id = None

    text_to_search = f"{fields.get('summary', '')} {fields.get('description', '')}"
    case_match = re.search(r"case_[a-f0-9]{12}", text_to_search)
    if case_match:
        matching_case_id = case_match.group(0)
    elif issue_key:
        for c in case_store.list_cases():
            jira_info = (c.get("integrations") or {}).get("jira", {})
            if jira_info.get("issue_key") == issue_key:
                matching_case_id = c["case_id"]
                break

    if not matching_case_id:
        matching_case_id = payload.get("case_id")

    if not matching_case_id:
        raise HTTPException(status_code=404, detail="Could not map Jira issue to a valid case_id")

    update_entry = case_store.add_webhook_update(
        case_id=matching_case_id,
        source="jira",
        status=jira_status,
        notes=notes,
        payload=payload,
    )

    events.publish(
        "webhook_received",
        {
            "case_id": matching_case_id,
            "source": "jira",
            "external_status": jira_status,
            "analyst_notes": notes,
        },
    )

    return {"status": "ok", "case_id": matching_case_id, "update": update_entry}


@app.post("/api/v1/webhooks/servicenow")
def servicenow_webhook(payload: dict):
    """Inbound webhook handler for ServiceNow incident status updates."""
    correlation_id = payload.get("correlation_id")
    incident_number = payload.get("number")
    snow_status = payload.get("incident_state") or payload.get("state") or payload.get("stage") or "updated"
    notes = payload.get("work_notes") or payload.get("comments") or payload.get("short_description")

    case_store = store.get_case_store()
    matching_case_id = correlation_id

    if not matching_case_id and incident_number:
        for c in case_store.list_cases():
            snow_info = (c.get("integrations") or {}).get("servicenow", {})
            if snow_info.get("number") == incident_number:
                matching_case_id = c["case_id"]
                break

    if not matching_case_id:
        matching_case_id = payload.get("case_id")

    if not matching_case_id:
        raise HTTPException(status_code=404, detail="Could not map ServiceNow incident to a valid case_id")

    update_entry = case_store.add_webhook_update(
        case_id=matching_case_id,
        source="servicenow",
        status=str(snow_status),
        notes=notes,
        payload=payload,
    )

    events.publish(
        "webhook_received",
        {
            "case_id": matching_case_id,
            "source": "servicenow",
            "external_status": str(snow_status),
            "analyst_notes": notes,
        },
    )

    return {"status": "ok", "case_id": matching_case_id, "update": update_entry}


@app.post("/api/v1/webhooks/{source}")
def generic_source_webhook(source: str, payload: dict):
    """Generic webhook endpoint for custom SIEM/ITSM tools."""
    case_id = payload.get("case_id")
    if not case_id:
        raise HTTPException(status_code=400, detail="Missing required 'case_id' in webhook payload")

    status_val = payload.get("status") or payload.get("external_status") or "updated"
    notes = payload.get("notes") or payload.get("analyst_notes")

    case_store = store.get_case_store()
    c = case_store.get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    update_entry = case_store.add_webhook_update(
        case_id=case_id,
        source=source,
        status=status_val,
        notes=notes,
        payload=payload,
    )

    events.publish(
        "webhook_received",
        {
            "case_id": case_id,
            "source": source,
            "external_status": status_val,
            "analyst_notes": notes,
        },
    )

    return {"status": "ok", "case_id": case_id, "update": update_entry}

