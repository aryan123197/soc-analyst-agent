import time
from unittest.mock import patch

from soc_agent.sources import replay


def test_not_running_before_start():
    source = replay.ReplaySource(interval=0.05)
    assert source.running is False


def test_start_marks_running_and_stop_marks_not_running():
    source = replay.ReplaySource(interval=0.05)
    with patch("soc_agent.sources.replay.run_pipeline") as mock_run:
        source.start()
        assert source.running is True
        time.sleep(0.15)
        source.stop()
        time.sleep(0.15)
        assert source.running is False
    assert mock_run.call_count >= 1


def test_start_is_idempotent_while_already_running():
    source = replay.ReplaySource(interval=0.05)
    with patch("soc_agent.sources.replay.run_pipeline"):
        source.start()
        first_thread = source._thread
        source.start()  # should be a no-op, not spawn a second thread
        assert source._thread is first_thread
        source.stop()
        time.sleep(0.15)


def test_pipeline_error_does_not_kill_the_feed():
    source = replay.ReplaySource(interval=0.03)
    with patch("soc_agent.sources.replay.run_pipeline", side_effect=RuntimeError("boom")) as mock_run:
        source.start()
        time.sleep(0.15)
        assert source.running is True  # thread survives repeated pipeline exceptions
        source.stop()
        time.sleep(0.15)
    assert mock_run.call_count >= 2


def test_attack_items_are_all_expected_blocked_from_corpus():
    from soc_agent.corpus.attack_cases import CASES

    blocked_labels = {c["label"] for c in CASES if c["expected_verdict"] == "blocked"}
    assert len(replay.ATTACK_ITEMS) == len(blocked_labels)
    assert len(replay.ATTACK_ITEMS) > 0


def test_get_source_returns_a_singleton():
    assert replay.get_source() is replay.get_source()
