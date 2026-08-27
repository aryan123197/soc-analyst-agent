import shutil
from pathlib import Path

import pytest

from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline
from soc_agent.services import gateway


@pytest.fixture(autouse=True)
def clean_local_data():
    local_dir = Path(__file__).resolve().parent.parent / "local_data"
    shutil.rmtree(local_dir, ignore_errors=True)
    yield
    shutil.rmtree(local_dir, ignore_errors=True)


@pytest.mark.parametrize("case", CASES, ids=[c["label"] for c in CASES])
def test_corpus_case_matches_expected_verdict(case):
    result = run_pipeline(
        source_channel=case["source_channel"],
        sender=case["sender"],
        raw_text=case["raw_text"],
        armor_enabled=True,
    )
    assert result.armor_result.verdict == case["expected_verdict"]
    assert result.armor_result.threat_type == case["expected_threat_type"]


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
