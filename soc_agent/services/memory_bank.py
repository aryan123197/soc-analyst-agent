"""Memory Bank stand-in: cross-session recall for the triage agent.

Schema follows the memory_entry shape in the project spec. Backed by the same
local/Firestore split as the case store. In production this maps to GEAP's
Memory Bank component; this local implementation keeps the same read/write
shape so swapping it out later is a one-file change.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_agent import config

_LOCAL_DIR = Path(__file__).resolve().parent.parent.parent / "local_data"
_LOCAL_MEMORY_FILE = _LOCAL_DIR / "memory_bank.json"
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalMemoryBank:
    def __init__(self, path: Path = _LOCAL_MEMORY_FILE):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("[]")

    def _read_all(self) -> list[dict[str, Any]]:
        with _lock:
            return json.loads(self._path.read_text() or "[]")

    def _write_all(self, entries: list[dict[str, Any]]) -> None:
        with _lock:
            self._path.write_text(json.dumps(entries, indent=2, default=str))

    def write_entry(
        self, scope: str, subject_key: str, content: str, case_ref: str
    ) -> None:
        entries = self._read_all()
        entries.append(
            {
                "scope": scope,
                "subject_key": subject_key,
                "content": content,
                "case_ref": case_ref,
                "created_at": _now(),
            }
        )
        self._write_all(entries)

    def query_by_subject(self, scope: str, subject_key: str) -> list[dict[str, Any]]:
        return [
            e
            for e in self._read_all()
            if e["scope"] == scope and e["subject_key"] == subject_key
        ]


class FirestoreMemoryBank:
    def __init__(self):
        from google.cloud import firestore

        self._client = firestore.Client(project=config.GOOGLE_CLOUD_PROJECT or None)
        self._collection = self._client.collection("memory_bank")

    def write_entry(
        self, scope: str, subject_key: str, content: str, case_ref: str
    ) -> None:
        self._collection.add(
            {
                "scope": scope,
                "subject_key": subject_key,
                "content": content,
                "case_ref": case_ref,
                "created_at": _now(),
            }
        )

    def query_by_subject(self, scope: str, subject_key: str) -> list[dict[str, Any]]:
        docs = (
            self._collection.where("scope", "==", scope)
            .where("subject_key", "==", subject_key)
            .stream()
        )
        return [d.to_dict() for d in docs]


def get_memory_bank():
    if config.USE_LOCAL_STORE:
        return LocalMemoryBank()
    return FirestoreMemoryBank()
