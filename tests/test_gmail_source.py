import base64
from unittest.mock import MagicMock, patch

import pytest

from soc_agent.sources import gmail


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode()


def test_header_lookup_is_case_insensitive():
    payload = {"headers": [{"name": "From", "value": "attacker@evil.com"}]}
    assert gmail._header(payload, "from") == "attacker@evil.com"
    assert gmail._header(payload, "FROM") == "attacker@evil.com"


def test_header_lookup_missing_returns_empty_string():
    assert gmail._header({"headers": []}, "Subject") == ""


def test_extract_body_prefers_text_plain():
    payload = {
        "mimeType": "multipart/alternative",
        "parts": [
            {"mimeType": "text/html", "body": {"data": _b64("<p>html</p>")}},
            {"mimeType": "text/plain", "body": {"data": _b64("plain text body")}},
        ],
    }
    assert gmail._extract_body(payload) == "plain text body"


def test_extract_body_falls_back_to_html_when_no_plain_part():
    payload = {"mimeType": "text/html", "body": {"data": _b64("<p>only html</p>")}}
    assert gmail._extract_body(payload) == "<p>only html</p>"


def test_extract_body_returns_empty_for_no_body():
    assert gmail._extract_body({"mimeType": "text/plain", "body": {}}) == ""


def test_start_raises_loudly_when_credentials_missing(monkeypatch):
    monkeypatch.delenv("GMAIL_CLIENT_ID", raising=False)
    monkeypatch.delenv("GMAIL_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GMAIL_REFRESH_TOKEN", raising=False)
    source = gmail.GmailSource(interval=0.05)
    with pytest.raises(RuntimeError, match="GMAIL_CLIENT_ID"):
        source.start()
    assert source.running is False


def test_first_poll_seeds_without_processing_existing_mail():
    source = gmail.GmailSource(interval=0.05)
    source._service = MagicMock()
    source._service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg_1"}, {"id": "msg_2"}]
    }

    with patch.object(source, "_process") as mock_process:
        source._poll_once()

    mock_process.assert_not_called()
    assert source._seen == {"msg_1", "msg_2"}
    assert source._seeded is True


def test_second_poll_processes_only_new_messages_oldest_first():
    source = gmail.GmailSource(interval=0.05)
    source._service = MagicMock()
    source._seeded = True
    source._seen = {"msg_1"}
    source._service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg_3"}, {"id": "msg_2"}, {"id": "msg_1"}]
    }

    with patch.object(source, "_process") as mock_process:
        source._poll_once()

    assert mock_process.call_args_list == [(("msg_2",),), (("msg_3",),)]
    assert source._seen == {"msg_1", "msg_2", "msg_3"}


def test_process_runs_pipeline_with_extracted_fields():
    source = gmail.GmailSource(interval=0.05)
    source._service = MagicMock()
    source._service.users().messages().get().execute.return_value = {
        "payload": {
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "Subject", "value": "Test subject"},
            ],
            "mimeType": "text/plain",
            "body": {"data": _b64("body content")},
        },
        "snippet": "fallback snippet",
    }

    with patch("soc_agent.sources.gmail.run_pipeline") as mock_run:
        source._process("msg_1")

    mock_run.assert_called_once_with(
        source_channel="email",
        sender="sender@example.com",
        raw_text="Subject: Test subject\n\nbody content",
    )


def test_poll_error_sets_last_error_but_thread_keeps_running():
    source = gmail.GmailSource(interval=0.03)
    source._service = MagicMock()
    with patch.object(source, "_poll_once", side_effect=RuntimeError("api down")):
        source._stop.clear()
        source._thread = None
        import threading

        source._thread = threading.Thread(target=source._run, daemon=True)
        source._thread.start()
        import time

        time.sleep(0.1)
        source.stop()
        time.sleep(0.1)

    assert source.last_error is not None
    assert "api down" in source.last_error


def test_get_source_returns_a_singleton():
    assert gmail.get_source() is gmail.get_source()
