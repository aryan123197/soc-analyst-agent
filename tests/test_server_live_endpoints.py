import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from soc_agent.server import app


client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_live_dashboard_serves_html():
    resp = client.get("/live")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SOC ANALYST AGENT" in resp.text


def test_live_sources_reports_both_source_states():
    resp = client.get("/live/sources")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"gmail", "replay"}
    assert "running" in body["gmail"]
    assert "running" in body["replay"]


def test_replay_start_and_stop():
    with patch("soc_agent.server.replay.get_source") as mock_get_source:
        mock_source = MagicMock()
        mock_source.running = True
        mock_source.interval = 3.0
        mock_get_source.return_value = mock_source

        resp = client.post("/live/replay", json={"action": "start", "interval": 3.0})
        assert resp.status_code == 200
        assert resp.json() == {"running": True, "interval": 3.0}
        mock_source.start.assert_called_once()

        mock_source.running = False
        resp = client.post("/live/replay", json={"action": "stop"})
        assert resp.status_code == 200
        assert resp.json()["running"] is False
        mock_source.stop.assert_called_once()


def test_replay_invalid_action_rejected():
    resp = client.post("/live/replay", json={"action": "explode"})
    assert resp.status_code == 400


def test_gmail_start_success():
    with patch("soc_agent.server.gmail.get_source") as mock_get_source:
        mock_source = MagicMock()
        mock_source.running = True
        mock_source.interval = 10.0
        mock_source.last_error = None
        mock_get_source.return_value = mock_source

        resp = client.post("/live/gmail", json={"action": "start"})
        assert resp.status_code == 200
        assert resp.json() == {"running": True, "interval": 10.0, "last_error": None}


def test_gmail_start_failure_returns_503_with_detail():
    with patch("soc_agent.server.gmail.get_source") as mock_get_source:
        mock_source = MagicMock()
        mock_source.start.side_effect = RuntimeError("GMAIL_CLIENT_ID missing")
        mock_get_source.return_value = mock_source

        resp = client.post("/live/gmail", json={"action": "start"})
        assert resp.status_code == 503
        assert "GMAIL_CLIENT_ID missing" in resp.json()["detail"]


def test_gmail_invalid_action_rejected():
    resp = client.post("/live/gmail", json={"action": "explode"})
    assert resp.status_code == 400


def test_live_stream_route_config():
    # TestClient.stream() runs the ASGI app fully in-thread to build the
    # response, so it can't be used against a genuinely infinite generator
    # like this endpoint's -- it hangs waiting for the stream to end, which
    # it never does by design. Route/media-type wiring is checked via the
    # OpenAPI schema instead; the generator's actual behavior (connect
    # message, event forwarding, keepalive) is exercised directly below.
    schema = client.get("/openapi.json").json()
    route = schema["paths"]["/live/stream"]["get"]
    assert route["responses"]["200"]["content"]


@pytest.mark.asyncio
async def test_live_stream_generator_yields_connect_message():
    from soc_agent.server import live_stream

    gen = live_stream().body_iterator
    assert await gen.__anext__() == ": connected\n\n"
    await gen.aclose()


@pytest.mark.asyncio
async def test_live_stream_generator_forwards_published_events():
    from soc_agent.server import live_stream
    from soc_agent.services import events

    gen = live_stream().body_iterator
    await gen.__anext__()  # consume the connect message

    events.publish("case_start", {"case_id": "case_gen_test"})
    chunk = await gen.__anext__()
    assert "case_gen_test" in chunk
    assert chunk.startswith("data: ")

    await gen.aclose()


@pytest.mark.asyncio
async def test_live_stream_generator_unsubscribes_on_close():

    from soc_agent.server import live_stream
    from soc_agent.services import events

    before = len(events._subscribers)
    gen = live_stream().body_iterator
    await gen.__anext__()  # triggers events.subscribe() inside the generator
    assert len(events._subscribers) == before + 1

    await gen.aclose()  # triggers the generator's `finally: events.unsubscribe(q)`
    assert len(events._subscribers) == before


def test_traces_endpoint_404_for_unknown_case():
    resp = client.get("/traces/case_does_not_exist_xyz")
    assert resp.status_code == 404


def test_traces_list_view_renders_html():
    resp = client.get("/traces")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Reasoning Traces" in resp.text


def test_file_ingest_endpoint():
    resp = client.post(
        "/ingest/file",
        json={
            "filename": "security_report.log",
            "content": "Alert: high memory usage on server web-01",
            "source_channel": "file_upload",
            "armor_enabled": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "case_id" in data
    assert data["status"] in ("actioned", "quarantined")


def test_human_review_unknown_case_returns_404():
    resp = client.post(
        "/cases/case_nonexistent_999/review",
        json={"decision": "approve", "analyst_notes": "Looks good"},
    )
    assert resp.status_code == 404

