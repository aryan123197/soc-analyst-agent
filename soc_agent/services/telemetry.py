"""Observability and Telemetry service: OpenTelemetry, Prometheus metrics, and Structured Logging.

Provides:
1. OpenTelemetry tracer and context manager for distributed tracing across pipeline hops.
2. Prometheus metrics (counters, histograms) for throughput and hop latencies.
3. Structured JSON logging compatible with GCP Cloud Logging.
4. Summary telemetry metrics aggregator for the Admin Observability Dashboard.
"""
import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Status, StatusCode

# -----------------------------------------------------------------------------
# 1. OpenTelemetry Initialization
# -----------------------------------------------------------------------------
_provider = TracerProvider()
# Console exporter enabled for local debugging, non-blocking
_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
otel_trace.set_tracer_provider(_provider)

tracer = otel_trace.get_tracer("soc_agent.telemetry")

# In-memory trace span buffer for frontend waterfall rendering
_span_records: List[Dict[str, Any]] = []

def record_span_waterfall(case_id: str, name: str, start_time: float, end_time: float, attributes: Dict[str, Any]):
    duration_ms = round((end_time - start_time) * 1000, 2)
    _span_records.append({
        "case_id": case_id,
        "name": name,
        "start_time": start_time,
        "end_time": end_time,
        "duration_ms": duration_ms,
        "attributes": attributes
    })
    # Keep last 500 span records in memory
    if len(_span_records) > 500:
        _span_records.pop(0)

def get_case_waterfall_spans(case_id: str) -> List[Dict[str, Any]]:
    return [s for s in _span_records if s.get("case_id") == case_id]


@contextmanager
def trace_span(name: str, case_id: str = "", attributes: Optional[Dict[str, Any]] = None):
    """Context manager for tracing execution spans and recording waterfall metadata."""
    attrs = attributes or {}
    if case_id:
        attrs["case_id"] = case_id

    start_t = time.time()
    with tracer.start_as_current_span(name) as span:
        for k, v in attrs.items():
            if v is not None:
                span.set_attribute(k, str(v))
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
            raise
        finally:
            end_t = time.time()
            record_span_waterfall(case_id, name, start_t, end_t, attrs)


# -----------------------------------------------------------------------------
# 2. Prometheus Metrics
# -----------------------------------------------------------------------------
PIPELINE_CASES_TOTAL = Counter(
    "soc_agent_cases_total",
    "Total cases ingested by status and source channel",
    ["status", "source_channel"]
)

MODEL_ARMOR_VERDICTS_TOTAL = Counter(
    "soc_agent_armor_verdicts_total",
    "Model Armor screening verdicts by verdict and threat_type",
    ["verdict", "threat_type"]
)

TRIAGE_LLM_USED_TOTAL = Counter(
    "soc_agent_triage_llm_used_total",
    "Triage LLM execution status (llm vs fallback)",
    ["status"]
)

PIPELINE_HOP_LATENCY_SECONDS = Histogram(
    "soc_agent_pipeline_hop_latency_seconds",
    "Latency per pipeline hop in seconds",
    ["hop"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

def get_prometheus_metrics_bytes() -> bytes:
    return generate_latest()


# -----------------------------------------------------------------------------
# 3. Structured Logging Setup
# -----------------------------------------------------------------------------
logger = logging.getLogger("soc_agent")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '{"time":"%(asctime)s", "level":"%(levelname)s", "module":"%(module)s", "message":%(message)s}'
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def log_event(event_type: str, payload: Dict[str, Any]):
    import json
    msg = json.dumps({"event": event_type, **payload})
    logger.info(msg)


# -----------------------------------------------------------------------------
# 4. Summary Telemetry Aggregator for Admin Dashboard
# -----------------------------------------------------------------------------
_telemetry_history: List[Dict[str, Any]] = []

def record_pipeline_telemetry(
    case_id: str,
    source_channel: str,
    outcome: str,
    armor_verdict: str,
    threat_type: Optional[str],
    llm_used: bool,
    total_duration_ms: float,
    hop_durations_ms: Dict[str, float]
):
    entry = {
        "case_id": case_id,
        "source_channel": source_channel,
        "outcome": outcome,
        "armor_verdict": armor_verdict,
        "threat_type": threat_type or "none",
        "llm_used": llm_used,
        "total_duration_ms": round(total_duration_ms, 2),
        "hop_durations_ms": {k: round(v, 2) for k, v in hop_durations_ms.items()},
        "timestamp": time.time()
    }
    _telemetry_history.append(entry)
    if len(_telemetry_history) > 1000:
        _telemetry_history.pop(0)

    # Increment Prometheus metrics
    PIPELINE_CASES_TOTAL.labels(status=outcome, source_channel=source_channel).inc()
    MODEL_ARMOR_VERDICTS_TOTAL.labels(verdict=armor_verdict, threat_type=threat_type or "none").inc()
    TRIAGE_LLM_USED_TOTAL.labels(status="llm" if llm_used else "fallback").inc()
    for hop, duration_ms in hop_durations_ms.items():
        PIPELINE_HOP_LATENCY_SECONDS.labels(hop=hop).observe(duration_ms / 1000.0)


def get_telemetry_summary() -> Dict[str, Any]:
    total_cases = len(_telemetry_history)
    if total_cases == 0:
        return {
            "total_cases": 0,
            "avg_latency_ms": 0.0,
            "armor_block_rate": 0.0,
            "llm_reliability_rate": 100.0,
            "outcomes": {"quarantined": 0, "actioned": 0},
            "armor_verdicts": {"clean": 0, "blocked": 0},
            "threat_types": {},
            "avg_hop_latencies_ms": {
                "ingestion": 0.0,
                "model_armor": 0.0,
                "triage": 0.0,
                "action": 0.0,
                "memory_bank": 0.0
            }
        }

    total_latency = sum(t["total_duration_ms"] for t in _telemetry_history)
    quarantined = sum(1 for t in _telemetry_history if t["outcome"] == "quarantined")
    actioned = sum(1 for t in _telemetry_history if t["outcome"] == "actioned")
    blocked = sum(1 for t in _telemetry_history if t["armor_verdict"] == "blocked")
    clean = sum(1 for t in _telemetry_history if t["armor_verdict"] == "clean")
    llm_count = sum(1 for t in _telemetry_history if t["llm_used"])

    threat_counts: Dict[str, int] = {}
    hop_totals: Dict[str, float] = {}
    hop_counts: Dict[str, int] = {}

    for t in _telemetry_history:
        tt = t["threat_type"]
        if tt != "none":
            threat_counts[tt] = threat_counts.get(tt, 0) + 1

        for hop, dur in t["hop_durations_ms"].items():
            hop_totals[hop] = hop_totals.get(hop, 0.0) + dur
            hop_counts[hop] = hop_counts.get(hop, 0) + 1

    avg_hop_latencies = {
        hop: round(hop_totals[hop] / hop_counts[hop], 2) if hop_counts.get(hop, 0) > 0 else 0.0
        for hop in ["ingestion", "model_armor", "triage", "action", "memory_bank"]
    }

    return {
        "total_cases": total_cases,
        "avg_latency_ms": round(total_latency / total_cases, 2),
        "armor_block_rate": round((blocked / total_cases) * 100.0, 1),
        "llm_reliability_rate": round((llm_count / total_cases) * 100.0, 1),
        "outcomes": {"quarantined": quarantined, "actioned": actioned},
        "armor_verdicts": {"clean": clean, "blocked": blocked},
        "threat_types": threat_counts,
        "avg_hop_latencies_ms": avg_hop_latencies
    }
