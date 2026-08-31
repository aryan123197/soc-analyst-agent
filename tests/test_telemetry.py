"""Tests for Telemetry, Prometheus Metrics, and OpenTelemetry Tracing."""
import pytest
from soc_agent.services import telemetry


def test_telemetry_recording_and_summary():
    # Record synthetic pipeline executions
    telemetry.record_pipeline_telemetry(
        case_id="case_test_001",
        source_channel="email",
        outcome="quarantined",
        armor_verdict="blocked",
        threat_type="prompt_injection",
        llm_used=False,
        total_duration_ms=150.0,
        hop_durations_ms={"ingestion": 10.0, "model_armor": 120.0, "triage": 0.0, "action": 20.0, "memory_bank": 0.0}
    )

    telemetry.record_pipeline_telemetry(
        case_id="case_test_002",
        source_channel="ticket",
        outcome="actioned",
        armor_verdict="clean",
        threat_type=None,
        llm_used=True,
        total_duration_ms=450.0,
        hop_durations_ms={"ingestion": 15.0, "model_armor": 50.0, "triage": 300.0, "action": 35.0, "memory_bank": 50.0}
    )

    summary = telemetry.get_telemetry_summary()
    assert summary["total_cases"] >= 2
    assert summary["armor_verdicts"]["blocked"] >= 1
    assert summary["armor_verdicts"]["clean"] >= 1
    assert "ingestion" in summary["avg_hop_latencies_ms"]


def test_prometheus_metrics_export():
    metrics_bytes = telemetry.get_prometheus_metrics_bytes()
    assert isinstance(metrics_bytes, bytes)
    assert b"soc_agent_cases_total" in metrics_bytes
    assert b"soc_agent_armor_verdicts_total" in metrics_bytes


def test_opentelemetry_waterfall_spans():
    case_id = "case_waterfall_123"
    with telemetry.trace_span("test_span_1", case_id=case_id, attributes={"key": "val"}):
        pass

    spans = telemetry.get_case_waterfall_spans(case_id)
    assert len(spans) == 1
    assert spans[0]["name"] == "test_span_1"
    assert spans[0]["attributes"]["key"] == "val"
