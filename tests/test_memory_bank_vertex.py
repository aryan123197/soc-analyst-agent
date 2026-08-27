"""Mapping tests for VertexMemoryBank against fake Memory Bank clients.

These pin the two places the real Memory Bank proto doesn't line up with the
memory_entry shape the rest of the pipeline expects: case_ref has to survive a
round trip through `description`, and (scope, subject_key) has to become the
scope map that retrieval filters on.
"""
from google.cloud import aiplatform_v1beta1

from soc_agent.services.memory_bank import VertexMemoryBank


class _FakeOperation:
    def result(self):
        return None


class _FakeClient:
    """Captures create_memory calls and replays canned retrieve_memories results."""

    def __init__(self, retrieved=()):
        self.created = []
        self.retrieve_requests = []
        self._retrieved = retrieved

    def reasoning_engine_path(self, project, location, reasoning_engine):
        return f"projects/{project}/locations/{location}/reasoningEngines/{reasoning_engine}"

    def create_memory(self, parent, memory):
        self.created.append((parent, memory))
        return _FakeOperation()

    def retrieve_memories(self, request):
        self.retrieve_requests.append(request)
        return aiplatform_v1beta1.RetrieveMemoriesResponse(
            retrieved_memories=self._retrieved
        )


def _bank(monkeypatch, client):
    monkeypatch.setattr(
        aiplatform_v1beta1, "MemoryBankServiceClient", lambda **kwargs: client
    )
    return VertexMemoryBank(
        project="proj", location="us-central1", agent_engine_id="123"
    )


def test_write_entry_maps_content_and_case_ref(monkeypatch):
    client = _FakeClient()
    bank = _bank(monkeypatch, client)

    bank.write_entry(
        scope="triage-agent",
        subject_key="evil-corp.test",
        content="credential-harvesting lure",
        case_ref="case-001",
    )

    assert len(client.created) == 1
    parent, memory = client.created[0]
    assert parent == "projects/proj/locations/us-central1/reasoningEngines/123"
    assert memory.fact == "credential-harvesting lure"
    # case_ref rides in description -- the only free-form field that round-trips
    assert memory.description == "case-001"
    assert dict(memory.scope) == {
        "scope": "triage-agent",
        "subject_key": "evil-corp.test",
    }


def test_query_by_subject_returns_memory_entry_shape(monkeypatch):
    retrieved = [
        aiplatform_v1beta1.RetrieveMemoriesResponse.RetrievedMemory(
            memory=aiplatform_v1beta1.Memory(
                fact="credential-harvesting lure", description="case-001"
            )
        )
    ]
    client = _FakeClient(retrieved=retrieved)
    bank = _bank(monkeypatch, client)

    entries = bank.query_by_subject(scope="triage-agent", subject_key="evil-corp.test")

    assert entries == [
        {
            "scope": "triage-agent",
            "subject_key": "evil-corp.test",
            "content": "credential-harvesting lure",
            "case_ref": "case-001",
            "created_at": "",
        }
    ]
    # triage.py reads these two keys directly off each entry
    assert entries[0]["case_ref"] == "case-001"
    assert entries[0]["content"]

    request = client.retrieve_requests[0]
    assert dict(request.scope) == {
        "scope": "triage-agent",
        "subject_key": "evil-corp.test",
    }
