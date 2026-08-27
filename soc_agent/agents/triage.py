"""Triage agent — classifies severity, queries Memory Bank for similar past cases.

Only ever reads the (already Model-Armor-screened) content. Never sees the raw
untrusted payload directly if it was blocked — a blocked case short-circuits
before reaching this module.
"""
import json
import re
from dataclasses import dataclass
from typing import Optional

from google import genai

from soc_agent import config
from soc_agent.services import memory_bank, store, trace

SEVERITIES = ("low", "medium", "high", "critical")

_TRIAGE_PROMPT = """You are a SOC triage analyst. Classify the following incident.

Sender: {sender}
Channel: {channel}
Content:
---
{content}
---

Prior related memory (may be empty):
{memory_context}

Respond with strict JSON only, no markdown fences:
{{"severity": "low|medium|high|critical", "category": "short category label", "reasoning": "one sentence"}}
"""


@dataclass
class TriageResult:
    severity: str
    category: str
    reasoning: str
    similar_past_cases: list[str]


def _sender_domain(sender: str) -> str:
    match = re.search(r"@([\w.-]+)", sender)
    return match.group(1) if match else sender


def _fallback_classify(content: str) -> tuple[str, str, str]:
    """Deterministic fallback used when no GOOGLE_API_KEY is configured."""
    lowered = content.lower()
    if any(k in lowered for k in ("breach", "ransomware", "exfil", "critical")):
        return "critical", "active-threat", "Fallback heuristic: high-severity keywords present."
    if any(k in lowered for k in ("suspicious", "phishing", "unauthorized")):
        return "high", "suspected-incident", "Fallback heuristic: suspicious activity keywords present."
    if any(k in lowered for k in ("failed login", "policy violation")):
        return "medium", "policy-or-access", "Fallback heuristic: moderate-risk keywords present."
    return "low", "informational", "Fallback heuristic: no elevated-risk keywords found."


def _classify_with_llm(sender: str, channel: str, content: str, memory_context: str) -> tuple[str, str, str]:
    client = genai.Client()
    prompt = _TRIAGE_PROMPT.format(
        sender=sender, channel=channel, content=content, memory_context=memory_context
    )
    response = client.models.generate_content(model=config.GEMINI_MODEL, contents=prompt)
    parsed = json.loads(response.text.strip())
    severity = parsed["severity"] if parsed["severity"] in SEVERITIES else "medium"
    return severity, parsed["category"], parsed["reasoning"]


def triage(
    case_id: str,
    sender: str,
    channel: str,
    screened_content: str,
    tr: trace.Trace,
) -> TriageResult:
    bank = memory_bank.get_memory_bank()
    domain = _sender_domain(sender)
    memories = bank.query_by_subject(scope="triage-agent", subject_key=domain)
    memory_context = (
        "\n".join(f"- {m['content']}" for m in memories) if memories else "(none)"
    )
    tr.log("triage", f"queried Memory Bank for subject_key={domain}, found {len(memories)} entries")

    if config.GOOGLE_CLOUD_PROJECT or _has_api_key():
        try:
            severity, category, reasoning = _classify_with_llm(sender, channel, screened_content, memory_context)
        except Exception as exc:  # network/API issues shouldn't crash the demo
            tr.log("triage", f"LLM classify failed ({exc}), falling back to heuristic")
            severity, category, reasoning = _fallback_classify(screened_content)
    else:
        severity, category, reasoning = _fallback_classify(screened_content)

    similar_case_ids = [m["case_ref"] for m in memories]

    case_store = store.get_case_store()
    case_store.update_case(
        case_id,
        {
            "status": "triaged",
            "triage": {
                "severity": severity,
                "category": category,
                "similar_past_cases": similar_case_ids,
                "reasoning_trace_id": tr.trace_id,
            },
        },
    )
    tr.log("triage", f"classified severity={severity} category={category}: {reasoning}")

    return TriageResult(
        severity=severity, category=category, reasoning=reasoning, similar_past_cases=similar_case_ids
    )


def write_memory_summary(sender: str, case_id: str, summary: str) -> None:
    bank = memory_bank.get_memory_bank()
    domain = _sender_domain(sender)
    bank.write_entry(scope="triage-agent", subject_key=domain, content=summary, case_ref=case_id)


def _has_api_key() -> bool:
    import os

    return bool(os.environ.get("GOOGLE_API_KEY"))
