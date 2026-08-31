"""Lightweight reasoning-chain trace, stands in for GEAP Agent Observability.

Each pipeline run gets a trace_id; every hop (ingestion, armor, triage, action)
appends a step. Traces are printed as a table for the demo, returned inline in
API responses, and persisted (see persist_trace/get_trace below) so a case's
full reasoning chain can be looked up later via triage.reasoning_trace_id --
this is what soc_agent/server.py's GET /traces/{case_id} and the trace-view
HTML page read from.
"""
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from soc_agent import config
from soc_agent.services import events

_LOCAL_DIR = Path(__file__).resolve().parent.parent.parent / "local_data"
_LOCAL_TRACES_FILE = _LOCAL_DIR / "traces.json"
_lock = threading.Lock()


@dataclass
class TraceStep:
    hop: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {"hop": self.hop, "detail": self.detail, "timestamp": self.timestamp}


@dataclass
class Trace:
    trace_id: str
    case_id: str
    steps: list[TraceStep] = field(default_factory=list)

    def log(self, hop: str, detail: str) -> None:
        step = TraceStep(hop=hop, detail=detail)
        self.steps.append(step)
        events.publish(
            "hop",
            {"trace_id": self.trace_id, "case_id": self.case_id, **step.to_dict()},
        )

    def render(self) -> str:
        lines = [f"trace_id={self.trace_id} case_id={self.case_id}"]
        for step in self.steps:
            lines.append(f"  [{step.timestamp}] {step.hop:12s} | {step.detail}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "case_id": self.case_id,
            "steps": [s.to_dict() for s in self.steps],
        }


def new_trace(case_id: str) -> Trace:
    return Trace(trace_id=f"trace_{uuid.uuid4().hex[:12]}", case_id=case_id)


class LocalTraceStore:
    def __init__(self, path: Path = _LOCAL_TRACES_FILE):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}")

    def save(self, trace: Trace) -> None:
        with _lock:
            data = json.loads(self._path.read_text() or "{}")
            data[trace.case_id] = trace.to_dict()
            self._path.write_text(json.dumps(data, indent=2, default=str))

    def get_by_case_id(self, case_id: str) -> Optional[dict[str, Any]]:
        with _lock:
            data = json.loads(self._path.read_text() or "{}")
        return data.get(case_id)

    def list_all(self) -> list[dict[str, Any]]:
        with _lock:
            data = json.loads(self._path.read_text() or "{}")
        return list(data.values())


class FirestoreTraceStore:
    def __init__(self):
        from google.cloud import firestore

        self._client = firestore.Client(project=config.GOOGLE_CLOUD_PROJECT or None)
        self._collection = self._client.collection("traces")

    def save(self, trace: Trace) -> None:
        self._collection.document(trace.case_id).set(trace.to_dict())

    def get_by_case_id(self, case_id: str) -> Optional[dict[str, Any]]:
        doc = self._collection.document(case_id).get()
        return doc.to_dict() if doc.exists else None

    def list_all(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self._collection.stream()]


def get_trace_store():
    if config.USE_LOCAL_STORE:
        return LocalTraceStore()
    return FirestoreTraceStore()


def persist_trace(trace: Trace) -> None:
    get_trace_store().save(trace)
