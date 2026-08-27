"""Memory Bank: cross-session recall for the triage agent.

Schema follows the memory_entry shape in the project spec. Three backends
behind one read/write interface: `VertexMemoryBank` calls the real GEAP Memory
Bank API, with `LocalMemoryBank` (JSON file) and `FirestoreMemoryBank` as the
no-GCP and no-Agent-Engine fallbacks.
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
        from google.cloud.firestore_v1.base_query import FieldFilter

        docs = (
            self._collection.where(filter=FieldFilter("scope", "==", scope))
            .where(filter=FieldFilter("subject_key", "==", subject_key))
            .stream()
        )
        return [d.to_dict() for d in docs]


class VertexMemoryBank:
    """Real GEAP Memory Bank, via google-cloud-aiplatform's MemoryBankServiceClient.

    Requires a pre-provisioned Agent Engine (ReasoningEngine) with a
    memory_bank_config — see soc_agent/scripts/provision_memory_bank.py. Every
    Memory Bank call is parented to that resource; there is no project-level
    Memory Bank.

    Two shape mismatches worth naming, since this is v1beta1-only surface:

    1. The Memory proto has no arbitrary-metadata field (its fields are name,
       fact, scope, display_name, description, create_time, update_time,
       ttl/expire_time). `case_ref` is carried in `description` because that is
       the only free-form field that round-trips. It is not put in `scope` —
       scope is the retrieval filter, so a unique case_ref per entry would make
       every memory unretrievable by subject.
    2. create_memory is a long-running operation, so writes block on .result().
       Retrieval is synchronous.
    """

    def __init__(self, project: str, location: str, agent_engine_id: str):
        from google.cloud import aiplatform_v1beta1

        self._v1beta1 = aiplatform_v1beta1
        self._client = aiplatform_v1beta1.MemoryBankServiceClient(
            client_options={"api_endpoint": f"{location}-aiplatform.googleapis.com"}
        )
        self._parent = self._client.reasoning_engine_path(
            project, location, agent_engine_id
        )

    def write_entry(
        self, scope: str, subject_key: str, content: str, case_ref: str
    ) -> None:
        memory = self._v1beta1.Memory(
            fact=content,
            description=case_ref,
            scope={"scope": scope, "subject_key": subject_key},
        )
        self._client.create_memory(parent=self._parent, memory=memory).result()

    def query_by_subject(self, scope: str, subject_key: str) -> list[dict[str, Any]]:
        response = self._client.retrieve_memories(
            request=self._v1beta1.RetrieveMemoriesRequest(
                parent=self._parent,
                scope={"scope": scope, "subject_key": subject_key},
                simple_retrieval_params=self._v1beta1.RetrieveMemoriesRequest.SimpleRetrievalParams(),
            )
        )
        return [
            {
                "scope": scope,
                "subject_key": subject_key,
                "content": rm.memory.fact,
                "case_ref": rm.memory.description,
                "created_at": rm.memory.create_time.rfc3339()
                if rm.memory.create_time
                else "",
            }
            for rm in response.retrieved_memories
        ]


def get_memory_bank():
    if config.USE_VERTEX_MEMORY_BANK:
        return VertexMemoryBank(
            project=config.GOOGLE_CLOUD_PROJECT,
            location=config.GOOGLE_CLOUD_LOCATION,
            agent_engine_id=config.AGENT_ENGINE_ID,
        )
    if config.USE_LOCAL_STORE:
        return LocalMemoryBank()
    return FirestoreMemoryBank()
