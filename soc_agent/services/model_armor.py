"""Model Armor screening interface.

Screens untrusted content crossing the ingestion -> triage boundary for:
  - prompt_injection
  - tool_poisoning
  - pii_exfil
  - malicious_uri (phishing/C2 links embedded in content)

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
import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

ThreatType = Literal["prompt_injection", "tool_poisoning", "pii_exfil", "malicious_uri"]

# Model Armor screens literal text only -- a base64-encoded instruction with no
# plaintext framing around it ("please decode this: <b64>") passes through clean,
# because there's no suspicious *text* to flag. Confirmed empirically: a bare
# base64 blob of "Ignore all previous instructions..." with no surrounding hint
# scored clean against the real API. If anything downstream ever decodes a field
# from ticket/email content (attachments, encoded API payloads -- a normal thing
# to do), the decoded text re-enters the reasoning context completely unscreened.
# _decode_candidates finds base64-looking substrings and decodes the ones that
# produce valid printable text, so screen() can pass them through Model Armor too.
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decode_candidates(content: str) -> list[str]:
    decoded: list[str] = []
    for match in _BASE64_CANDIDATE.findall(content):
        try:
            raw = base64.b64decode(match, validate=True)
            text = raw.decode("utf-8")
        except Exception:
            continue
        if text.isprintable() and text.strip():
            decoded.append(text)
    return decoded


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
    def _screen_raw(self, content: str) -> ArmorResult:
        raise NotImplementedError

    def screen(self, content: str) -> ArmorResult:
        """Screens content as-is, plus any base64-decodable substrings within it.

        Blocks if either the literal content or a decoded candidate trips a filter.
        The decoded-candidate result is returned as-is (its threat_type/confidence
        reflect whatever the decoded text tripped) so a case gets meaningfully
        categorized rather than a generic "something in here was bad."
        """
        result = self._screen_raw(content)
        if result.verdict == "blocked":
            return result

        for decoded in _decode_candidates(content):
            decoded_result = self._screen_raw(decoded)
            if decoded_result.verdict == "blocked":
                return decoded_result

        return result


class PassthroughModelArmor(BaseModelArmor):
    """No-op screener — used to demo the 'before' (unprotected) state only."""

    def _screen_raw(self, content: str) -> ArmorResult:
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

# No local heuristic for malicious_uri: real threat-intel-backed URL reputation isn't
# something a regex can approximate without giving false confidence. This category is
# only covered by VertexModelArmor (real Model Armor's malicious-URI filter); the local
# heuristic will never flag a URL, by design -- offline dev mode is not URL-safe.


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

    def _screen_raw(self, content: str) -> ArmorResult:
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

    def _screen_raw(self, content: str) -> ArmorResult:
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
        malicious_uri = filter_results.get("malicious_uris")

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

        if malicious_uri is not None and malicious_uri.malicious_uri_filter_result.match_state == m.FilterMatchState.MATCH_FOUND:
            return ArmorResult(
                verdict="blocked", threat_type="malicious_uri", confidence=0.9, screened_at=now
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
