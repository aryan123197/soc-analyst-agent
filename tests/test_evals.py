"""Tests for Agent Evaluation (Evals) Framework."""
import pytest
from soc_agent.services import evals


def test_run_benchmark_evals():
    # Execute the benchmark evals runner (synthetic=True)
    run_result = evals.run_benchmark_evals()

    assert run_result.run_id.startswith("eval_")
    assert run_result.total_cases == 12
    assert run_result.passed_cases >= 10  # All or almost all curated cases pass
    assert 0.0 <= run_result.accuracy_percent <= 100.0
    assert len(run_result.case_results) == 12

    # Verify history retrieval
    history = evals.get_eval_store().list_all()
    assert len(history) >= 1
    assert history[0]["run_id"] == run_result.run_id

