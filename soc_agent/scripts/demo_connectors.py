"""Interactive Mock Demo Script: Enterprise SIEM & ITSM Connectors (Jira, ServiceNow, Splunk).

Demonstrates:
1. Running an alert case through the SOC Analyst Agent pipeline.
2. Outbound dispatch to Jira Service Desk, ServiceNow Incident API, and Splunk HEC.
3. Inbound webhook sync from Jira (updating status to 'In Progress' with analyst notes).
4. Inbound webhook sync from ServiceNow (updating status to 'Resolved' with work notes).
"""
import json
import sys
import time
from pathlib import Path

# Add project root to sys.path
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from soc_agent.pipeline import run_pipeline
from soc_agent.server import app
from soc_agent.services import store
from soc_agent.services.client_factory import make_test_client


def run_connector_demo():
    print("=" * 80)
    print("  SOC ANALYST AGENT — ENTERPRISE CONNECTORS DEMO (JIRA / SERVICENOW / SPLUNK)")
    print("=" * 80)

    # 1. Run Pipeline for an incoming high-severity alert
    print("\n[STEP 1] Ingesting High-Severity Incident Alert into Zero-Trust Pipeline...")
    raw_text = (
        "SECURITY INCIDENT ALERT: High volume of internal login failures detected on server DB-PROD-01. "
        "User account srv_backup recorded 85 authentication requests within 3 minutes."
    )
    result = run_pipeline(
        source_channel="ticket",
        sender="alert-service@corpmont.net",
        raw_text=raw_text,
        armor_enabled=True,
    )

    case_id = result.case_id
    case_store = store.get_case_store()
    c = case_store.get_case(case_id) or {}

    print(f"  ✓ Case ID Created: {case_id}")
    print(f"  ✓ Model Armor Verdict: {result.armor_result.verdict.upper()}")
    print(f"  ✓ Triage Severity: {result.triage_result.severity.upper() if result.triage_result else 'N/A'}")
    print(f"  ✓ Action Executed: {result.action_record.type if result.action_record else 'N/A'}")

    # 2. Inspect Outbound Integration Dispatch Results
    print("\n[STEP 2] Inspecting Outbound Integration Dispatchers...")
    integrations = c.get("integrations") or {}
    jira_info = integrations.get("jira", {})
    snow_info = integrations.get("servicenow", {})
    splunk_info = integrations.get("splunk", {})

    print(f"  🎟️  Jira Service Desk Dispatch:  Status={jira_info.get('status')} | Key={jira_info.get('issue_key', 'N/A')}")
    print(f"  📋 ServiceNow Incident API:      Status={snow_info.get('status')} | Number={snow_info.get('number', 'N/A')}")
    print(f"  📊 Splunk HEC Collector:         Status={splunk_info.get('status')} | HEC={splunk_info.get('hec_status', 'N/A')}")

    client = make_test_client(app)



    # 3. Simulate Inbound Jira Webhook Update
    print("\n[STEP 3] Receiving Inbound Webhook Update from Jira Service Desk...")
    jira_webhook_payload = {
        "issue": {
            "key": jira_info.get("issue_key", "SOC-1042"),
            "fields": {
                "summary": f"SOC Alert for {case_id}",
                "status": {"name": "In Progress"},
            },
        },
        "comment": {"body": "Tier-2 Analyst assigned. Endpoint host isolated and memory dump captured."},
    }
    resp1 = client.post("/api/v1/webhooks/jira", json=jira_webhook_payload)
    print(f"  ✓ POST /api/v1/webhooks/jira -> HTTP {resp1.status_code}")
    print(f"  ✓ Response: {json.dumps(resp1.json(), indent=2)}")

    time.sleep(0.5)

    # 4. Simulate Inbound ServiceNow Webhook Update
    print("\n[STEP 4] Receiving Inbound Webhook Update from ServiceNow...")
    snow_webhook_payload = {
        "correlation_id": case_id,
        "number": snow_info.get("number", "INC001042"),
        "state": "Resolved",
        "work_notes": "ServiceNow Incident Resolved. IP 198.51.100.42 blocked at perimeter firewall.",
    }
    resp2 = client.post("/api/v1/webhooks/servicenow", json=snow_webhook_payload)
    print(f"  ✓ POST /api/v1/webhooks/servicenow -> HTTP {resp2.status_code}")
    print(f"  ✓ Response: {json.dumps(resp2.json(), indent=2)}")

    # 5. Fetch Final Reconciled Case Record
    print("\n[STEP 5] Fetching Reconciled Case State from Case Store...")
    final_case = case_store.get_case(case_id)
    print(json.dumps({
        "case_id": final_case["case_id"],
        "status": final_case["status"],
        "external_status": final_case.get("external_status"),
        "external_notes": final_case.get("external_notes"),
        "last_webhook_update": final_case.get("last_webhook_update"),
        "integrations": final_case.get("integrations"),
        "webhook_history_count": len(final_case.get("webhook_history", []))
    }, indent=2))

    print("\n" + "=" * 80)
    print("  ✓ DEMO COMPLETE: Outbound & Inbound Enterprise SIEM/ITSM Connectors Verified!")
    print("=" * 80)


if __name__ == "__main__":
    run_connector_demo()
