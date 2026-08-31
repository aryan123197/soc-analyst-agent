"""Tests for Enterprise SIEM & ITSM Connectors and Inbound Webhooks."""
from soc_agent.agents import action
from soc_agent.server import app
from soc_agent.services import connectors, store, trace
from soc_agent.services.client_factory import make_test_client



def test_outbound_connectors_simulation():
    tr = trace.new_trace(case_id="case_test_sim_123")
    res = connectors.dispatch_outbound_integrations(
        case_id="case_test_sim_123",
        severity="high",
        category="phishing",
        reasoning="Suspicious link detected in email body",
        tr=tr,
    )
    assert res["jira"]["status"] == "simulated"
    assert "SOC-" in res["jira"]["issue_key"]
    assert res["servicenow"]["status"] == "simulated"
    assert "INC" in res["servicenow"]["number"]
    assert res["splunk"]["status"] == "simulated"
    assert res["splunk"]["hec_status"] == "success"


def test_action_agent_integrations_dispatch():
    case_store = store.get_case_store()
    c = store.make_case(source_channel="email", sender="attacker@evil.com", raw_content_ref="ref_123")
    case_id = c["case_id"]
    c["triage"] = {
        "severity": "critical",
        "category": "prompt-injection",
        "reasoning": "Attempted system override",
    }
    case_store.create_case(c)

    tr = trace.new_trace(case_id=case_id)
    rec = action.act(case_id=case_id, severity="critical", tr=tr)


    assert rec.type == "escalated"
    updated_case = case_store.get_case(case_id)
    assert updated_case is not None
    assert "integrations" in updated_case
    assert updated_case["integrations"]["jira"]["status"] == "simulated"
    assert updated_case["integrations"]["servicenow"]["status"] == "simulated"
    assert updated_case["integrations"]["splunk"]["status"] == "simulated"


def test_inbound_webhooks():
    client = make_test_client(app)


    case_store = store.get_case_store()

    # Create a test case
    c = store.make_case(source_channel="ticket", sender="user@corp.example", raw_content_ref="ref_wh")
    case_id = c["case_id"]
    c["integrations"] = {
        "jira": {"issue_key": "SOC-9988"},
        "servicenow": {"number": "INC009988"},
    }
    case_store.create_case(c)

    # 1. Jira Inbound Webhook
    jira_payload = {
        "issue": {
            "key": "SOC-9988",
            "fields": {
                "summary": f"Incident review for {case_id}",
                "status": {"name": "In Progress"},
            },
        },
        "comment": {"body": "Analyst assigned to investigate endpoint logs."},
    }
    resp_jira = client.post("/api/v1/webhooks/jira", json=jira_payload)
    assert resp_jira.status_code == 200, resp_jira.text
    jira_data = resp_jira.json()
    assert jira_data["case_id"] == case_id
    assert jira_data["update"]["external_status"] == "In Progress"

    # Verify store updated
    case_after_jira = case_store.get_case(case_id)
    assert case_after_jira["external_status"] == "In Progress"
    assert "Analyst assigned" in case_after_jira["external_notes"]

    # 2. ServiceNow Inbound Webhook
    snow_payload = {
        "correlation_id": case_id,
        "number": "INC009988",
        "state": "Resolved",
        "work_notes": "Host isolated and malware quarantined.",
    }
    resp_snow = client.post("/api/v1/webhooks/servicenow", json=snow_payload)
    assert resp_snow.status_code == 200, resp_snow.text
    snow_data = resp_snow.json()
    assert snow_data["case_id"] == case_id
    assert snow_data["update"]["external_status"] == "Resolved"

    # Verify store updated
    case_after_snow = case_store.get_case(case_id)
    assert case_after_snow["external_status"] == "Resolved"

    # 3. Generic SIEM Webhook
    generic_payload = {
        "case_id": case_id,
        "status": "Closed-Remediated",
        "analyst_notes": "Custom SIEM rule updated",
    }
    resp_generic = client.post("/api/v1/webhooks/splunk", json=generic_payload)
    assert resp_generic.status_code == 200, resp_generic.text
    generic_data = resp_generic.json()
    assert generic_data["update"]["external_status"] == "Closed-Remediated"

    # Verify full webhook history
    case_final = case_store.get_case(case_id)
    assert len(case_final["webhook_history"]) == 3
