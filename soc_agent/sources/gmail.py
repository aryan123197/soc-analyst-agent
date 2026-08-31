"""Real inbox source: polls Gmail and runs each new message through the pipeline.

This is the live demo path -- a judge emails the monitored inbox and watches the
message land on the dashboard and get screened in real time.

Read-only by design (`gmail.readonly` scope): the poller never marks messages
read, labels, or deletes anything. Deduplication is handled entirely in-process
via a seen-id set, which is *seeded with whatever is already in the inbox on the
first poll* -- so starting the poller processes only mail that arrives after
startup, never the existing backlog.

Auth: OAuth user credentials, not a service account -- a service account cannot
read a normal consumer Gmail inbox without domain-wide delegation. Run
`python -m soc_agent.scripts.gmail_auth` once to mint a refresh token; see that
script for the environment variables it expects.
"""
import base64
import os
import threading
from typing import Optional

from soc_agent.pipeline import run_pipeline

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _build_service():
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    client_id = os.environ.get("GMAIL_CLIENT_ID")
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET")
    refresh_token = os.environ.get("GMAIL_REFRESH_TOKEN")
    if not (client_id and client_secret and refresh_token):
        raise RuntimeError(
            "Gmail source needs GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET and "
            "GMAIL_REFRESH_TOKEN. Run: python -m soc_agent.scripts.gmail_auth"
        )

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=SCOPES,
    )
    creds.refresh(Request())
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _header(payload: dict, name: str) -> str:
    for h in payload.get("headers", []):
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _extract_body(payload: dict) -> str:
    """Depth-first walk for the first text/plain part, falling back to text/html."""
    mime = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data")

    if data and mime == "text/plain":
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

    for part in payload.get("parts", []) or []:
        found = _extract_body(part)
        if found:
            return found

    if data and mime == "text/html":
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    return ""


class GmailSource:
    """Polls the authorized inbox every `interval` seconds for new mail."""

    def __init__(self, interval: float = 10.0):
        self.interval = interval
        self.last_error: Optional[str] = None
        self._service = None
        self._seen: set[str] = set()
        self._seeded = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return (
            self._thread is not None and self._thread.is_alive() and not self._stop.is_set()
        )

    def start(self) -> None:
        if self.running:
            return
        self._service = _build_service()  # fail loudly here, not silently in the thread
        self.last_error = None
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
                self.last_error = None
            except Exception as exc:  # transient API/network errors must not kill the poller
                self.last_error = repr(exc)
                print(f"[gmail] poll error: {exc!r}", flush=True)
            self._stop.wait(self.interval)

    def _poll_once(self) -> None:
        resp = (
            self._service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=20)
            .execute()
        )
        ids = [m["id"] for m in resp.get("messages", [])]

        if not self._seeded:
            # First poll: treat the existing inbox as already-handled so the demo
            # only ever shows mail that arrives while the poller is running.
            self._seen.update(ids)
            self._seeded = True
            print(f"[gmail] seeded with {len(ids)} existing messages", flush=True)
            return

        for msg_id in reversed(ids):  # oldest-first so the dashboard reads naturally
            if msg_id in self._seen:
                continue
            self._seen.add(msg_id)
            self._process(msg_id)

    def _process(self, msg_id: str) -> None:
        msg = (
            self._service.users()
            .messages()
            .get(userId="me", id=msg_id, format="full")
            .execute()
        )
        payload = msg.get("payload", {})
        sender = _header(payload, "From") or "unknown"
        subject = _header(payload, "Subject")
        body = _extract_body(payload) or msg.get("snippet", "")

        raw_text = f"Subject: {subject}\n\n{body}".strip()
        run_pipeline(source_channel="email", sender=sender, raw_text=raw_text)


_source = GmailSource()


def get_source() -> GmailSource:
    return _source
