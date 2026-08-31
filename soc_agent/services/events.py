"""In-process pub/sub so the live dashboard can watch the pipeline as it runs.

Every trace hop is published here the moment it is logged (see Trace.log in
soc_agent/services/trace.py), plus a structured `case_complete` event from the
pipeline carrying the final verdict. The SSE endpoint in soc_agent/server.py
subscribes and forwards each event to connected browsers.

Subscriber queues are bounded and drop the oldest event when full, so a slow or
abandoned browser tab can never block the pipeline.
"""
import queue
import threading
from datetime import datetime, timezone
from typing import Any

_MAX_QUEUED = 500

_subscribers: list[queue.Queue] = []
_lock = threading.Lock()


def publish(event_type: str, payload: dict[str, Any]) -> None:
    event = {
        "type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    with _lock:
        targets = list(_subscribers)
    for q in targets:
        try:
            q.put_nowait(event)
        except queue.Full:
            try:
                q.get_nowait()
                q.put_nowait(event)
            except (queue.Empty, queue.Full):
                pass


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUED)
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        if q in _subscribers:
            _subscribers.remove(q)
