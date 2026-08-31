"""Enterprise SIEM & ITSM Connectors.

Provides outbound dispatchers for:
1. Jira Service Desk REST API
2. ServiceNow Incident API
3. Splunk HEC (HTTP Event Collector)

Supports real REST API execution when configured via environment variables, with
intelligent simulation fallback when credentials are not supplied (for offline dev/demos).
"""
import base64
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Optional

from soc_agent import config

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_post(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float = 5.0) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8")
            return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = json.loads(err_body) if err_body.startswith("{") else {"error": err_body}
        return exc.code, parsed
    except Exception as exc:
        return 500, {"error": str(exc)}


class JiraConnector:
    @staticmethod
    def create_issue(case_id: str, severity: str, category: str, reasoning: str) -> dict[str, Any]:
        if not config.JIRA_ENABLED:
            mock_id = abs(hash(case_id)) % 8999 + 1000
            mock_key = f"{config.JIRA_PROJECT_KEY}-{mock_id}"
            return {
                "status": "simulated",
                "issue_key": mock_key,
                "issue_id": str(mock_id),
                "url": f"{config.JIRA_URL or 'https://jira.corp.example'}/browse/{mock_key}",
                "dispatched_at": _now(),
            }

        url = f"{config.JIRA_URL.rstrip('/')}/rest/api/3/issue"
        auth_str = f"{config.JIRA_USER_EMAIL}:{config.JIRA_API_TOKEN}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "fields": {
                "project": {"key": config.JIRA_PROJECT_KEY},
                "summary": f"[SOC Alert] {severity.upper()}: {category} ({case_id})",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Case ID: {case_id}\nSeverity: {severity}\nCategory: {category}\nReasoning: {reasoning}",
                                }
                            ],
                        }
                    ],
                },
                "issuetype": {"name": "Task"},
            }
        }

        status_code, resp = _http_post(url, headers, payload)
        if status_code in (200, 201):
            key = resp.get("key", "")
            return {
                "status": "created",
                "issue_key": key,
                "issue_id": resp.get("id", ""),
                "url": f"{config.JIRA_URL.rstrip('/')}/browse/{key}",
                "dispatched_at": _now(),
            }
        else:
            logger.error(f"Jira API error ({status_code}): {resp}")
            return {
                "status": "failed",
                "error": resp.get("error", f"HTTP {status_code}"),
                "dispatched_at": _now(),
            }


class ServiceNowConnector:
    @staticmethod
    def create_incident(case_id: str, severity: str, category: str, reasoning: str) -> dict[str, Any]:
        if not config.SERVICENOW_ENABLED:
            mock_num = f"INC{abs(hash(case_id)) % 899999 + 100000}"
            mock_sys_id = f"sys_{abs(hash(case_id)):x}"[:32]
            inst = config.SERVICENOW_INSTANCE or "servicenow.corp.example"
            return {
                "status": "simulated",
                "sys_id": mock_sys_id,
                "number": mock_num,
                "url": f"https://{inst}/nav_to.do?uri=incident.do?sys_id={mock_sys_id}",
                "dispatched_at": _now(),
            }

        url = f"https://{config.SERVICENOW_INSTANCE.strip()}/api/now/table/incident"
        auth_str = f"{config.SERVICENOW_USER}:{config.SERVICENOW_PASSWORD}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        urgency_val = "1" if severity in ("critical", "high") else "2"
        payload = {
            "correlation_id": case_id,
            "short_description": f"[SOC Agent] {severity.upper()} - {category} ({case_id})",
            "description": f"Automated Alert Case ID: {case_id}\nSeverity: {severity}\nCategory: {category}\nReasoning: {reasoning}",
            "urgency": urgency_val,
            "impact": urgency_val,
            "category": "Security",
        }

        status_code, resp = _http_post(url, headers, payload)
        if status_code in (200, 201):
            res_result = resp.get("result", {})
            sys_id = res_result.get("sys_id", "")
            number = res_result.get("number", "")
            return {
                "status": "created",
                "sys_id": sys_id,
                "number": number,
                "url": f"https://{config.SERVICENOW_INSTANCE.strip()}/nav_to.do?uri=incident.do?sys_id={sys_id}",
                "dispatched_at": _now(),
            }
        else:
            logger.error(f"ServiceNow API error ({status_code}): {resp}")
            return {
                "status": "failed",
                "error": resp.get("error", f"HTTP {status_code}"),
                "dispatched_at": _now(),
            }


class SplunkConnector:
    @staticmethod
    def send_hec_event(
        case_id: str,
        severity: str,
        category: str,
        reasoning: str,
        threat_intel: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if not config.SPLUNK_ENABLED:
            return {
                "status": "simulated",
                "hec_status": "success",
                "sourcetype": "soc:agent:action",
                "dispatched_at": _now(),
            }

        url = config.SPLUNK_HEC_URL
        headers = {
            "Authorization": f"Splunk {config.SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        }

        payload = {
            "event": {
                "case_id": case_id,
                "severity": severity,
                "category": category,
                "reasoning": reasoning,
                "threat_intel": threat_intel,
                "timestamp": _now(),
            },
            "sourcetype": "soc:agent:action",
            "source": "soc-analyst-agent",
        }

        status_code, resp = _http_post(url, headers, payload)
        if status_code == 200:
            return {
                "status": "indexed",
                "hec_status": resp.get("text", "Success"),
                "code": resp.get("code", 0),
                "dispatched_at": _now(),
            }
        else:
            logger.error(f"Splunk HEC error ({status_code}): {resp}")
            return {
                "status": "failed",
                "error": resp.get("error", f"HTTP {status_code}"),
                "dispatched_at": _now(),
            }


def dispatch_outbound_integrations(
    case_id: str,
    severity: str,
    category: str,
    reasoning: str,
    threat_intel: Optional[dict[str, Any]] = None,
    tr: Optional[Any] = None,
) -> dict[str, Any]:
    """Dispatches alerts to all enterprise connectors (Jira, ServiceNow, Splunk)."""
    jira_res = JiraConnector.create_issue(case_id, severity, category, reasoning)
    snow_res = ServiceNowConnector.create_incident(case_id, severity, category, reasoning)
    splunk_res = SplunkConnector.send_hec_event(case_id, severity, category, reasoning, threat_intel)

    integrations_summary = {
        "jira": jira_res,
        "servicenow": snow_res,
        "splunk": splunk_res,
        "dispatched_at": _now(),
    }

    if tr:
        tr.log(
            "connectors",
            f"outbound sync complete: Jira={jira_res.get('status')} ({jira_res.get('issue_key', 'N/A')}), "
            f"ServiceNow={snow_res.get('status')} ({snow_res.get('number', 'N/A')}), "
            f"Splunk={splunk_res.get('status')}",
        )

    return integrations_summary
