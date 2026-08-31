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
from soc_agent.services import events

BENIGN_ITEMS = [
    {
        "source_channel": "ticket",
        "sender": "jira-automation@atlassian-cloud.net",
        "raw_text": (
            "JIRA Ticket SOC-2094: 'Monitor suspicious API key usage on prod-auth-01'. "
            "Status updated to In Progress by Tier-2 Security Analyst (dmitri.k). "
            "Assigned to: SOC Escalations Team."
        ),
    },
    {
        "source_channel": "ticket",
        "sender": "servicenow-integration@corp.servicenow.com",
        "raw_text": (
            "ServiceNow Incident INC-009041: 'SIEM High-Volume Log Spike on Prod Firewall Gateway'. "
            "Priority: P2 High. State: Under Investigation by Security Operations Center."
        ),
    },
    {
        "source_channel": "ticket",
        "sender": "salesforce-cloud@support.salesforce.com",
        "raw_text": (
            "Salesforce Service Cloud Case #SF-88094: 'Enterprise SSO OAuth Token Refresh Failure for Tenant 4410'. "
            "Priority: High. Account: Global Logistics Corp. Status: Working."
        ),
    },
    {
        "source_channel": "alert",
        "sender": "pagerduty-events@events.pagerduty.com",
        "raw_text": (
            "PagerDuty Trigger: Incident #PD-44109 'Database Connection Pool Exhaustion on auth-db-cluster-prod'. "
            "Severity: High. Service: Authentication API Gateway."
        ),
    },
    {
        "source_channel": "ticket",
        "sender": "zendesk-support@corp.zendesk.com",
        "raw_text": (
            "Zendesk Ticket #ZD-99412: 'Requesting emergency password reset for executive user session'. "
            "Channel: Web Portal. Status: Pending SOC Identity Verification."
        ),
    },
    {
        "source_channel": "alert",
        "sender": "splunk-hec@siem.corp.internal",
        "raw_text": (
            "Splunk SIEM Alert: 'Multiple failed SSH authentication attempts on bastion-01 (10.0.4.12) "
            "within 60s window'. Risk Score: 65/100. Rule: SSH_BRUTE_FORCE_POSSIBLE."
        ),
    },
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
        "label": c["label"],
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

    def trigger_campaign_sequence(self) -> dict:
        part1 = next((c for c in attack_cases.CASES if c["label"] == "multi_stage_campaign_part1_context"), None)
        part2 = next((c for c in attack_cases.CASES if c["label"] == "multi_stage_campaign_part2_payload"), None)
        res1 = run_pipeline(source_channel=part1["source_channel"], sender=part1["sender"], raw_text=part1["raw_text"], synthetic=True) if part1 else None
        res2 = run_pipeline(source_channel=part2["source_channel"], sender=part2["sender"], raw_text=part2["raw_text"], synthetic=True) if part2 else None
        return {
            "status": "triggered",
            "part1_case_id": res1.case_id if res1 else None,
            "part2_case_id": res2.case_id if res2 else None,
        }

    def _run(self) -> None:
        step_count = 0
        # Run 2-part multi-stage campaign attack first in the live feed stream
        try:
            part1 = next((c for c in attack_cases.CASES if c["label"] == "multi_stage_campaign_part1_context"), None)
            if part1 and not self._stop.is_set():
                run_pipeline(source_channel=part1["source_channel"], sender=part1["sender"], raw_text=part1["raw_text"], synthetic=True)
                self._stop.wait(3.0)

            part2 = next((c for c in attack_cases.CASES if c["label"] == "multi_stage_campaign_part2_payload"), None)
            if part2 and not self._stop.is_set():
                run_pipeline(source_channel=part2["source_channel"], sender=part2["sender"], raw_text=part2["raw_text"], synthetic=True)
                self._stop.wait(self.interval)
        except Exception as exc:
            print(f"[replay] startup campaign sequence error: {exc!r}", flush=True)

        while not self._stop.is_set():
            pool = ATTACK_ITEMS if random.random() < self.attack_ratio else BENIGN_ITEMS
            item = random.choice(pool)
            step_count += 1

            # If multi-stage campaign payload is picked, ensure Part 1 context note
            # is ingested into GEAP Memory Bank right before Part 2 payload arrives.
            if item.get("label") == "multi_stage_campaign_part2_payload":
                part1 = next((c for c in attack_cases.CASES if c["label"] == "multi_stage_campaign_part1_context"), None)
                if part1 and not self._stop.is_set():
                    try:
                        run_pipeline(
                            source_channel=part1["source_channel"],
                            sender=part1["sender"],
                            raw_text=part1["raw_text"],
                            synthetic=True,
                        )
                    except Exception as exc:
                        print(f"[replay] pipeline error in campaign part1: {exc!r}", flush=True)
                    self._stop.wait(self.interval)

            if self._stop.is_set():
                break

            try:
                res = run_pipeline(
                    source_channel=item["source_channel"],
                    sender=item["sender"],
                    raw_text=item["raw_text"],
                    synthetic=True,
                )

                # Periodically emit a simulated inbound Jira/ServiceNow webhook update to live feed
                if step_count % 3 == 0 and res and hasattr(res, "case_id"):
                    events.publish(
                        "webhook_received",
                        {
                            "case_id": res.case_id,
                            "source": random.choice(["jira", "servicenow"]),
                            "external_status": random.choice(["In Progress", "Acknowledged", "Resolved"]),
                            "analyst_notes": "Live ITSM Webhook Sync: Status reconciled in Cloud Firestore",
                        },
                    )
            except Exception as exc:  # keep the stream alive through transient API errors
                print(f"[replay] pipeline error: {exc!r}", flush=True)
            self._stop.wait(self.interval)


_source = ReplaySource()


def get_source() -> ReplaySource:
    return _source
