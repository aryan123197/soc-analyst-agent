"""HTTP entrypoint for Cloud Run: exposes the pipeline as a service.

POST /ingest runs a single item through the full pipeline and returns the
result (including the reasoning trace). GET /health is the health check
endpoint (deliberately not /healthz -- that exact literal path gets
intercepted by Google's frontend before reaching Cloud Run, independent of
what routes the app itself defines; confirmed by comparing headers on /healthz
vs /docs -- only /docs carried Cloud Run's `server: Google Frontend` and
`x-cloud-trace-context` headers).
"""
import json
import os
import queue
from pathlib import Path


from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline
from soc_agent.services import events
from soc_agent.services import trace as trace_service
from soc_agent.sources import gmail, replay

app = FastAPI(title="SOC Analyst Agent")

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
    )


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
@app.get("/live", response_class=HTMLResponse)
def live_dashboard():
    """Real-time SOC console — renders cases as the pipeline processes them."""
    return _DASHBOARD_HTML.read_text()



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
