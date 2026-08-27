"""HTTP entrypoint for Cloud Run: exposes the pipeline as a service.

POST /ingest runs a single item through the full pipeline and returns the
result (including the reasoning trace). GET /healthz is the Cloud Run health
check.
"""
from fastapi import FastAPI
from pydantic import BaseModel

from soc_agent.pipeline import run_pipeline

app = FastAPI(title="SOC Analyst Agent")


class IngestRequest(BaseModel):
    source_channel: str
    sender: str
    raw_text: str
    armor_enabled: bool = True


class IngestResponse(BaseModel):
    case_id: str
    armor_verdict: str
    armor_threat_type: str | None
    triage_severity: str | None
    triage_category: str | None
    action_taken: str | None
    trace: str


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest):
    result = run_pipeline(
        source_channel=req.source_channel,
        sender=req.sender,
        raw_text=req.raw_text,
        armor_enabled=req.armor_enabled,
    )
    return IngestResponse(
        case_id=result.case_id,
        armor_verdict=result.armor_result.verdict,
        armor_threat_type=result.armor_result.threat_type,
        triage_severity=result.triage_result.severity if result.triage_result else None,
        triage_category=result.triage_result.category if result.triage_result else None,
        action_taken=result.action_record.type if result.action_record else None,
        trace=result.trace.render(),
    )
