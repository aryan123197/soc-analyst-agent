"""HTTP entrypoint for Cloud Run: exposes the pipeline as a service.

POST /ingest runs a single item through the full pipeline and returns the
result (including the reasoning trace). GET /health is the health check
endpoint (deliberately not /healthz -- that exact literal path gets
intercepted by Google's frontend before reaching Cloud Run, independent of
what routes the app itself defines; confirmed by comparing headers on /healthz
vs /docs -- only /docs carried Cloud Run's `server: Google Frontend` and
`x-cloud-trace-context` headers).
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline
from soc_agent.services import trace as trace_service

app = FastAPI(title="SOC Analyst Agent")


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
