import queue

from soc_agent.services import events


def test_subscribe_receives_published_event():
    q = events.subscribe()
    try:
        events.publish("case_start", {"case_id": "case_1"})
        event = q.get(timeout=1)
        assert event["type"] == "case_start"
        assert event["case_id"] == "case_1"
        assert "timestamp" in event
    finally:
        events.unsubscribe(q)


def test_unsubscribed_queue_does_not_receive_future_events():
    q = events.subscribe()
    events.unsubscribe(q)
    events.publish("case_start", {"case_id": "case_2"})
    assert q.empty()


def test_multiple_subscribers_each_receive_the_event():
    q1 = events.subscribe()
    q2 = events.subscribe()
    try:
        events.publish("hop", {"case_id": "case_3", "hop": "ingestion"})
        assert q1.get(timeout=1)["case_id"] == "case_3"
        assert q2.get(timeout=1)["case_id"] == "case_3"
    finally:
        events.unsubscribe(q1)
        events.unsubscribe(q2)


def test_full_queue_drops_oldest_event_rather_than_blocking():
    q = events.subscribe()
    try:
        for i in range(events._MAX_QUEUED + 10):
            events.publish("hop", {"case_id": f"case_{i}"})

        assert q.qsize() == events._MAX_QUEUED

        first_remaining = q.get_nowait()
        assert first_remaining["case_id"] != "case_0"
    finally:
        events.unsubscribe(q)


def test_unsubscribe_is_a_no_op_for_unknown_queue():
    unknown_queue: queue.Queue = queue.Queue()
    events.unsubscribe(unknown_queue)  # must not raise
