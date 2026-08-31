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


def test_live_stream_sends_published_event():
    import threading
    import time

    from soc_agent.services import events

    def publish_soon():
        time.sleep(0.2)  # give the endpoint time to subscribe before publishing
        events.publish("case_start", {"case_id": "case_stream_test"})

    publisher = threading.Thread(target=publish_soon, daemon=True)

    with client.stream("GET", "/live/stream") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")

        lines = resp.iter_lines()
        first = next(lines)
        assert first == ": connected"

        publisher.start()

        # skip blank separator lines / keepalives until the data line arrives
        for line in lines:
            if line.startswith("data:"):
                assert "case_stream_test" in line
                break
        else:
            raise AssertionError("did not receive the published event over SSE")


def test_traces_endpoint_404_for_unknown_case():
    resp = client.get("/traces/case_does_not_exist_xyz")
    assert resp.status_code == 404


def test_traces_list_view_renders_html():
    resp = client.get("/traces")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Reasoning Traces" in resp.text
