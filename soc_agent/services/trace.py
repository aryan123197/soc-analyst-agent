"""Lightweight reasoning-chain trace, stands in for GEAP Agent Observability.

Each pipeline run gets a trace_id; every hop (ingestion, armor, triage, action)
appends a step. Traces are printed as a table for the demo and also returned
as structured data so they can be linked from a case's triage.reasoning_trace_id.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TraceStep:
    hop: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Trace:
    trace_id: str
    case_id: str
    steps: list[TraceStep] = field(default_factory=list)

    def log(self, hop: str, detail: str) -> None:
        self.steps.append(TraceStep(hop=hop, detail=detail))

    def render(self) -> str:
        lines = [f"trace_id={self.trace_id} case_id={self.case_id}"]
        for step in self.steps:
            lines.append(f"  [{step.timestamp}] {step.hop:12s} | {step.detail}")
        return "\n".join(lines)


def new_trace(case_id: str) -> Trace:
    return Trace(trace_id=f"trace_{uuid.uuid4().hex[:12]}", case_id=case_id)
