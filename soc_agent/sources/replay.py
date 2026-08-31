"""Synthetic live traffic: a background thread that feeds items in on a timer.

This is the demo fallback for the Gmail source (soc_agent/sources/gmail.py) --
it produces a realistic mix of mostly-benign SOC traffic with attacks salted in,
so the dashboard has a continuous stream even with no real inbox connected.

Benign items live here rather than in soc_agent/corpus/attack_cases.py on
purpose: the corpus is a test asset with asserted expected_verdicts, this is
demo filler.
"""
import random
import threading

from soc_agent.corpus import attack_cases
from soc_agent.pipeline import run_pipeline

BENIGN_ITEMS = [
    {
        "source_channel": "ticket",
        "sender": "priya.raman@northwind-logistics.com",
        "raw_text": (
            "Hi team, our nightly export job has been finishing about 40 minutes later "
            "than usual since Tuesday. No errors in the logs we can see. Could someone "
            "take a look at the scheduler config? Not urgent, but it's pushing into "
            "business hours."
        ),
    },
    {
        "source_channel": "email",
        "sender": "no-reply@atlassian-notifications.com",
        "raw_text": (
            "JIRA: OPS-4417 'Rotate staging TLS certificate' was moved to In Progress "
            "by dmitri.k. Due 2026-09-04. View the issue in your project board."
        ),
    },
    {
        "source_channel": "ticket",
        "sender": "helpdesk@northwind-logistics.com",
        "raw_text": (
            "User reports MFA push notifications not arriving on their new phone after "
            "a device swap. Old device deprovisioned yesterday. Requesting re-enrollment "
            "through the standard identity desk process."
        ),
    },
    {
        "source_channel": "alert",
        "sender": "monitoring@northwind-logistics.com",
        "raw_text": (
            "CPU utilization on api-gateway-prod-03 held above 85% for 12 minutes "
            "starting 14:22 UTC, then recovered on its own. Autoscaler added two "
            "instances. No 5xx increase observed during the window."
        ),
    },
    {
        "source_channel": "email",
        "sender": "accounts@supplyco-billing.com",
        "raw_text": (
            "Your monthly invoice INV-2026-08-3391 is attached and due in 30 days. "
            "Amount: $4,280.00. Reply to this thread with any billing questions."
        ),
    },
    {
        "source_channel": "alert",
        "sender": "monitoring@northwind-logistics.com",
        "raw_text": (
            "Backup job 'firestore-nightly' completed successfully in 6m14s. "
            "412 GB written to the archive bucket. Next run scheduled 02:00 UTC."
        ),
    },
]

ATTACK_ITEMS = [
    {
        "source_channel": c["source_channel"],
        "sender": c["sender"],
        "raw_text": c["raw_text"],
    }
    for c in attack_cases.CASES
    if c["expected_verdict"] == "blocked"
]


class ReplaySource:
    """Feeds one item into the pipeline every `interval` seconds until stopped."""

    def __init__(self, interval: float = 8.0, attack_ratio: float = 0.3):
        self.interval = interval
        self.attack_ratio = attack_ratio
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            pool = ATTACK_ITEMS if random.random() < self.attack_ratio else BENIGN_ITEMS
            item = random.choice(pool)
            try:
                run_pipeline(
                    source_channel=item["source_channel"],
                    sender=item["sender"],
                    raw_text=item["raw_text"],
                    synthetic=True,
                )
            except Exception as exc:  # keep the stream alive through transient API errors
                print(f"[replay] pipeline error: {exc!r}", flush=True)
            self._stop.wait(self.interval)


_source = ReplaySource()


def get_source() -> ReplaySource:
    return _source
