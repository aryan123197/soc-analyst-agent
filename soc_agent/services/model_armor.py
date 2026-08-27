"""Model Armor screening interface.

Screens untrusted content crossing the ingestion -> triage boundary for:
  - prompt_injection
  - tool_poisoning
  - pii_exfil

This module exposes a stable `screen(content) -> ArmorResult` interface.
`HeuristicModelArmor` is a local regex-based stand-in with no GCP dependency.
`VertexModelArmor` calls the real GEAP Model Armor API (google-cloud-modelarmor)
against a pre-provisioned Template (see soc_agent/scripts/provision_model_armor.py).

Note: Model Armor's native filter categories are PI-and-jailbreak, SDP
(sensitive data), malicious URI, and RAI — there is no dedicated
"tool_poisoning" category. Tool-poisoning-shaped payloads (fake tool
descriptions instructing improper escalation) are jailbreak-shaped prompts
and get caught by the PI-and-jailbreak filter; VertexModelArmor reports them
as threat_type="prompt_injection" rather than inventing a category the real
service doesn't have.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

ThreatType = Literal["prompt_injection", "tool_poisoning", "pii_exfil"]


@dataclass
class ArmorResult:
    verdict: Literal["clean", "blocked"]
    threat_type: Optional[ThreatType]
    confidence: float
    screened_at: str
    matched_signal: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "screened_at": self.screened_at,
        }


class BaseModelArmor:
    def screen(self, content: str) -> ArmorResult:
        raise NotImplementedError


class PassthroughModelArmor(BaseModelArmor):
    """No-op screener — used to demo the 'before' (unprotected) state only."""

    def screen(self, content: str) -> ArmorResult:
        return ArmorResult(
            verdict="clean",
            threat_type=None,
            confidence=0.0,
            screened_at=datetime.now(timezone.utc).isoformat(),
        )


_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (all |any )?(previous|prior|above) (instructions|rules)",
    r"you are now",
    r"new instructions?:",
    r"system prompt",
    r"forward all (tickets|cases|emails) to",
    r"act as (the )?(admin|administrator|system)",
    r"reveal your (instructions|prompt|system prompt)",
]

_TOOL_POISONING_PATTERNS = [
    r"<tool_description>",
    r"when calling this tool.*always",
    r"escalate.*without (review|approval|confirmation)",
    r"grant (full|admin|write) access",
    r"override.*(policy|permission|gateway)",
]

_PII_EXFIL_PATTERNS = [
    r"list all (users?|employees?|customers?).*(ssn|social security|password|credit card)",
    r"(include|output|print|return).*(api key|password|ssn|social security number)",
    r"send (me |a copy of )?(all|every).*(credentials|passwords|keys)",
    r"dump (the )?(database|user table|credentials)",
]


class HeuristicModelArmor(BaseModelArmor):
    """Local heuristic screener: regex-signal based, good enough for a hackathon demo.

    In production this call is replaced by GEAP Model Armor (Vertex AI), which
    uses trained classifiers instead of regex. The interface (ArmorResult) stays
    the same either way.
    """

    def __init__(self, threshold: float = 0.6):
        self._threshold = threshold

    def _score(self, content: str, patterns: list[str]) -> tuple[float, Optional[str]]:
        lowered = content.lower()
        for pattern in patterns:
            match = re.search(pattern, lowered)
            if match:
                return 0.9, match.group(0)
        return 0.0, None

    def screen(self, content: str) -> ArmorResult:
        now = datetime.now(timezone.utc).isoformat()

        checks: list[tuple[ThreatType, list[str]]] = [
            ("prompt_injection", _INJECTION_PATTERNS),
            ("tool_poisoning", _TOOL_POISONING_PATTERNS),
            ("pii_exfil", _PII_EXFIL_PATTERNS),
        ]

        best_threat: Optional[ThreatType] = None
        best_score = 0.0
        best_signal: Optional[str] = None

        for threat_type, patterns in checks:
            score, signal = self._score(content, patterns)
            if score > best_score:
                best_threat, best_score, best_signal = threat_type, score, signal

        if best_score >= self._threshold:
            return ArmorResult(
                verdict="blocked",
                threat_type=best_threat,
                confidence=best_score,
                screened_at=now,
                matched_signal=best_signal,
            )

        return ArmorResult(
            verdict="clean",
            threat_type=None,
            confidence=1.0 - best_score,
            screened_at=now,
        )


class VertexModelArmor(BaseModelArmor):
    """Real GEAP Model Armor, via google-cloud-modelarmor against a pre-provisioned Template."""

    def __init__(self, project: str, location: str, template_id: str):
        from google.cloud import modelarmor_v1

        api_endpoint = f"modelarmor.{location}.rep.googleapis.com"
        self._client = modelarmor_v1.ModelArmorClient(
            client_options={"api_endpoint": api_endpoint}
        )
        self._template_name = self._client.template_path(project, location, template_id)
        self._modelarmor_v1 = modelarmor_v1

    def screen(self, content: str) -> ArmorResult:
        m = self._modelarmor_v1
        now = datetime.now(timezone.utc).isoformat()

        request = m.SanitizeUserPromptRequest(
            name=self._template_name,
            user_prompt_data=m.DataItem(text=content),
        )
        response = self._client.sanitize_user_prompt(request=request)
        result = response.sanitization_result

        if result.filter_match_state != m.FilterMatchState.MATCH_FOUND:
            return ArmorResult(
                verdict="clean", threat_type=None, confidence=1.0, screened_at=now
            )

        filter_results = result.filter_results  # map: filter name -> FilterResult
        pj = filter_results.get("pi_and_jailbreak")
        sdp = filter_results.get("sdp")

        confidence_rank = {
            m.DetectionConfidenceLevel.HIGH: 0.95,
            m.DetectionConfidenceLevel.MEDIUM_AND_ABOVE: 0.75,
            m.DetectionConfidenceLevel.LOW_AND_ABOVE: 0.5,
        }

        if pj is not None and pj.pi_and_jailbreak_filter_result.match_state == m.FilterMatchState.MATCH_FOUND:
            confidence_level = pj.pi_and_jailbreak_filter_result.confidence_level
            return ArmorResult(
                verdict="blocked",
                threat_type="prompt_injection",
                confidence=confidence_rank.get(confidence_level, 0.9),
                screened_at=now,
            )

        if sdp is not None:
            sdp_result = sdp.sdp_filter_result
            sdp_match = (
                sdp_result.inspect_result.match_state == m.FilterMatchState.MATCH_FOUND
                or sdp_result.deidentify_result.match_state == m.FilterMatchState.MATCH_FOUND
            )
            if sdp_match:
                return ArmorResult(
                    verdict="blocked", threat_type="pii_exfil", confidence=0.9, screened_at=now
                )

        return ArmorResult(
            verdict="blocked", threat_type="prompt_injection", confidence=0.7, screened_at=now
        )


def get_model_armor(
    enabled: bool = True,
    project: Optional[str] = None,
    location: Optional[str] = None,
    template_id: Optional[str] = None,
) -> BaseModelArmor:
    if not enabled:
        return PassthroughModelArmor()
    if project and template_id:
        return VertexModelArmor(project=project, location=location or "us-central1", template_id=template_id)
    return HeuristicModelArmor()
