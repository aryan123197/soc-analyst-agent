import shutil
from pathlib import Path

import pytest

from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline
from soc_agent.services import gateway, trace


@pytest.fixture(autouse=True)
def clean_local_data():
    local_dir = Path(__file__).resolve().parent.parent / "local_data"
    shutil.rmtree(local_dir, ignore_errors=True)
    yield
    shutil.rmtree(local_dir, ignore_errors=True)


@pytest.mark.parametrize("case", CASES, ids=[c["label"] for c in CASES])
def test_corpus_case_matches_expected_verdict(case):
    # threat_type categorization can legitimately differ between the local heuristic
    # and real GCP Model Armor (e.g. a jailbreak-phrased PII request may be caught by
    # either the PI-and-jailbreak or SDP filter) -- verdict is the strict contract.
    result = run_pipeline(
        source_channel=case["source_channel"],
        sender=case["sender"],
        raw_text=case["raw_text"],
        armor_enabled=True,
    )
    assert result.armor_result.verdict == case["expected_verdict"]
    if case["expected_verdict"] == "clean":
        assert result.armor_result.threat_type is None


def test_blocked_case_never_reaches_action_gateway():
    injection_case = next(c for c in CASES if c["label"] == "classic_prompt_injection_email")
    result = run_pipeline(
        source_channel=injection_case["source_channel"],
        sender=injection_case["sender"],
        raw_text=injection_case["raw_text"],
        armor_enabled=True,
    )
    assert result.triage_result is None
    assert result.action_record is None


def test_benign_case_reaches_action_via_gateway():
    benign_case = next(c for c in CASES if c["label"] == "benign_adversarial_looking_case")
    result = run_pipeline(
        source_channel=benign_case["source_channel"],
        sender=benign_case["sender"],
        raw_text=benign_case["raw_text"],
        armor_enabled=True,
    )
    assert result.triage_result is not None
    assert result.action_record is not None


def test_gateway_rejects_unauthorized_identity():
    with pytest.raises(gateway.GatewayPolicyError):
        gateway.execute_action(actor_identity="ingestion-agent", action_type="escalated")


def test_gateway_rejects_disallowed_action_type():
    with pytest.raises(gateway.GatewayPolicyError):
        gateway.execute_action(actor_identity="action-agent", action_type="delete_all_data")


def test_trace_persisted_and_queryable_by_case_id():
    benign_case = next(c for c in CASES if c["label"] == "benign_adversarial_looking_case")
    result = run_pipeline(
        source_channel=benign_case["source_channel"],
        sender=benign_case["sender"],
        raw_text=benign_case["raw_text"],
        armor_enabled=True,
    )
    stored = trace.get_trace_store().get_by_case_id(result.case_id)
    assert stored is not None
    assert stored["trace_id"] == result.trace.trace_id
    assert [s["hop"] for s in stored["steps"]] == [s.hop for s in result.trace.steps]


def test_trace_persisted_for_quarantined_case():
    injection_case = next(c for c in CASES if c["label"] == "classic_prompt_injection_email")
    result = run_pipeline(
        source_channel=injection_case["source_channel"],
        sender=injection_case["sender"],
        raw_text=injection_case["raw_text"],
        armor_enabled=True,
    )
    stored = trace.get_trace_store().get_by_case_id(result.case_id)
    assert stored is not None
    assert "model_armor" in [s["hop"] for s in stored["steps"]]
