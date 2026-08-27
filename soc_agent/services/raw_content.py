"""Raw untrusted content storage — stands in for Cloud Storage.

Design intent (per project spec): raw untrusted content never lives inline in
the Firestore case doc, and is only read directly by the ingestion agent's
sandboxed context. Triage/action agents only see it via raw_content_ref plus
whatever the (screened) ingestion agent chooses to summarize.
"""
import json
import threading
import uuid
from pathlib import Path

_LOCAL_DIR = Path(__file__).resolve().parent.parent.parent / "local_data" / "raw_content"
_lock = threading.Lock()


def _ensure_dir() -> None:
    _LOCAL_DIR.mkdir(parents=True, exist_ok=True)


def store_raw_content(content: str) -> str:
    """Stores raw content, returns a raw_content_ref pointer (not the content itself)."""
    _ensure_dir()
    ref = f"raw_{uuid.uuid4().hex[:12]}"
    path = _LOCAL_DIR / f"{ref}.json"
    with _lock:
        path.write_text(json.dumps({"content": content}))
    return ref


def fetch_raw_content(raw_content_ref: str) -> str:
    """Only the ingestion agent (and Model Armor screening step) should call this."""
    path = _LOCAL_DIR / f"{raw_content_ref}.json"
    if not path.exists():
        raise KeyError(f"unknown raw_content_ref: {raw_content_ref}")
    return json.loads(path.read_text())["content"]
