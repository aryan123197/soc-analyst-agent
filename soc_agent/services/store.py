"""Case store: Firestore-backed, with a local JSON fallback for offline dev.

Schema follows cases/{caseId} as defined in the project spec (CLAUDE.md).
"""
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from soc_agent import config

_LOCAL_DIR = Path(__file__).resolve().parent.parent.parent / "local_data"
_LOCAL_CASES_FILE = _LOCAL_DIR / "cases.json"
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_case_id() -> str:
    return f"case_{uuid.uuid4().hex[:12]}"


class LocalCaseStore:
    """JSON-file-backed store used when no GCP project/emulator is configured."""

    def __init__(self, path: Path = _LOCAL_CASES_FILE):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}")

    def _read_all(self) -> dict[str, Any]:
        with _lock:
            return json.loads(self._path.read_text() or "{}")

    def _write_all(self, data: dict[str, Any]) -> None:
        with _lock:
            self._path.write_text(json.dumps(data, indent=2, default=str))

    def create_case(self, case: dict[str, Any]) -> str:
        data = self._read_all()
        data[case["case_id"]] = case
        self._write_all(data)
        return case["case_id"]

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        return self._read_all().get(case_id)

    def update_case(self, case_id: str, patch: dict[str, Any]) -> None:
        data = self._read_all()
        if case_id not in data:
            raise KeyError(f"unknown case_id: {case_id}")
        data[case_id].update(patch)
        self._write_all(data)

    def list_cases(self) -> list[dict[str, Any]]:
        return list(self._read_all().values())


class FirestoreCaseStore:
    """Real Firestore-backed store for cases/{caseId}."""

    def __init__(self):
        from google.cloud import firestore

        self._client = firestore.Client(project=config.GOOGLE_CLOUD_PROJECT or None)
        self._collection = self._client.collection("cases")

    def create_case(self, case: dict[str, Any]) -> str:
        self._collection.document(case["case_id"]).set(case)
        return case["case_id"]

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        doc = self._collection.document(case_id).get()
        return doc.to_dict() if doc.exists else None

    def update_case(self, case_id: str, patch: dict[str, Any]) -> None:
        self._collection.document(case_id).update(patch)

    def list_cases(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self._collection.stream()]


def get_case_store():
    if config.USE_LOCAL_STORE:
        return LocalCaseStore()
    return FirestoreCaseStore()


def make_case(
    source_channel: str,
    sender: str,
    raw_content_ref: str,
    synthetic: bool = False,
) -> dict[str, Any]:
    return {
        "case_id": new_case_id(),
        "status": "ingested",
        # Marks demo-generator traffic (soc_agent/sources/replay.py) so it can be
        # told apart from real cases and bulk-deleted after a demo run.
        "synthetic": synthetic,
        "source": {
            "channel": source_channel,
            "sender": sender,
            "received_at": _now(),
        },
        "raw_content_ref": raw_content_ref,
        "model_armor_result": None,
        "triage": None,
        "action_taken": None,
    }
