"""Sequential pipeline: ingestion -> Model Armor -> triage -> action (via gateway).

    External sources (tickets, emails, alerts)
            |
            v
    Ingestion agent  (read-only, no action tools)
            |
            v
    Model Armor  (screens for injection / tool poisoning / PII leaks)
            |         \\
            |          -> blocked payloads -> quarantine log
            v
    Triage agent  (severity + Memory Bank recall)
            |
            v
    Action agent (behind Agent Gateway, only write-capable identity)
"""
import time
from dataclasses import dataclass
from typing import Optional

from soc_agent import config
from soc_agent.agents import action, ingestion, triage
from soc_agent.services import audit, events, model_armor, store, telemetry, threat_intel, trace


@dataclass
class PipelineResult:
    case_id: str
    armor_result: model_armor.ArmorResult
    triage_result: Optional[triage.TriageResult]
    action_record: Optional[object]
    trace: trace.Trace
    threat_intel_report: Optional[threat_intel.ThreatIntelReport] = None
    audit_certificate: Optional[audit.AuditCertificate] = None



def run_pipeline(
    source_channel: str,
    sender: str,
    raw_text: str,
    armor_enabled: bool = True,
    synthetic: bool = False,
) -> PipelineResult:
    """`synthetic=True` marks demo-generator traffic: the case is tagged in the
    store and no Memory Bank entry is written, so a long-running replay feed
    cannot pollute the recall corpus the real demo depends on (and doesn't pay
    for a synchronous embedding LRO per item)."""
    start_total_t = time.time()
    hop_durations: dict[str, float] = {}

    # Hop 1: Ingestion
    t0 = time.time()
    with telemetry.trace_span("ingestion_hop", attributes={"source_channel": source_channel, "sender": sender}):
        item, tr = ingestion.ingest(
            source_channel=source_channel, sender=sender, raw_text=raw_text, synthetic=synthetic
        )
    t1 = time.time()
    hop_durations["ingestion"] = (t1 - t0) * 1000.0

    # Hop 1b: Threat Intelligence & IOC Analysis (Google Web Risk + AbuseIPDB/VT)
    t0 = time.time()
    with telemetry.trace_span("threat_intel_hop", case_id=item.case_id):
        intel_report = threat_intel.analyze_iocs(item.raw_text)
        tr.log(
            "threat_intel",
            f"extracted IOCs: {len(intel_report.ips_found)} IPs, {len(intel_report.hashes_found)} hashes, "
            f"{len(intel_report.urls_found)} URLs. Max Risk Score: {intel_report.risk_score_max}/100"
        )
    t1 = time.time()
    hop_durations["threat_intel"] = (t1 - t0) * 1000.0

    case_store = store.get_case_store()
    case_store.update_case(
        item.case_id,
        {"threat_intel": intel_report.to_dict()}
    )

    # Hop 2: Model Armor screening
    t0 = time.time()
    with telemetry.trace_span("model_armor_hop", case_id=item.case_id, attributes={"armor_enabled": armor_enabled}):
        armor = model_armor.get_model_armor(
            enabled=armor_enabled,
            project=config.GOOGLE_CLOUD_PROJECT if config.USE_VERTEX_MODEL_ARMOR else None,
            location=config.GOOGLE_CLOUD_LOCATION,
            template_id=config.MODEL_ARMOR_TEMPLATE_ID,
        )
        armor_result = armor.screen(item.raw_text)
    t1 = time.time()
    hop_durations["model_armor"] = (t1 - t0) * 1000.0

    case_store.update_case(
        item.case_id,
        {"status": "screened", "model_armor_result": armor_result.to_dict()},
    )
    tr.log(
        "model_armor",
        f"verdict={armor_result.verdict} threat_type={armor_result.threat_type} "
        f"confidence={armor_result.confidence:.2f}"
        + (f" matched={armor_result.matched_signal!r}" if armor_result.matched_signal else ""),
    )

    if armor_result.verdict == "blocked":
        t0 = time.time()
        with telemetry.trace_span("quarantine_action_hop", case_id=item.case_id, attributes={"threat_type": armor_result.threat_type}):
            action.quarantine(item.case_id, threat_type=armor_result.threat_type or "unknown", tr=tr)
        t1 = time.time()
        hop_durations["action"] = (t1 - t0) * 1000.0

        # Sign Cryptographic Audit Certificate
        audit_cert = audit.generate_certificate(
            case_id=item.case_id,
            outcome="quarantined",
            model_armor_verdict=armor_result.verdict,
            actor_identity="soc-agent-quarantine-edge"
        )
        case_store.update_case(item.case_id, {"audit_certificate": audit_cert.to_dict()})
        tr.log("audit", f"signed SHA-256 certificate {audit_cert.certificate_id}")

        trace.persist_trace(tr)
        events.publish(
            "case_complete",
            {
                "case_id": item.case_id,
                "outcome": "quarantined",
                "armor_verdict": armor_result.verdict,
                "armor_threat_type": armor_result.threat_type,
                "severity": None,
                "category": None,
                "action_taken": None,
            },
        )
        total_duration_ms = (time.time() - start_total_t) * 1000.0
        telemetry.record_pipeline_telemetry(
            case_id=item.case_id,
            source_channel=source_channel,
            outcome="quarantined",
            armor_verdict=armor_result.verdict,
            threat_type=armor_result.threat_type,
            llm_used=False,
            total_duration_ms=total_duration_ms,
            hop_durations_ms=hop_durations
        )
        telemetry.log_event("pipeline_quarantined", {
            "case_id": item.case_id,
            "threat_type": armor_result.threat_type,
            "duration_ms": round(total_duration_ms, 2)
        })
        return PipelineResult(
            case_id=item.case_id,
            armor_result=armor_result,
            triage_result=None,
            action_record=None,
            trace=tr,
            threat_intel_report=intel_report,
            audit_certificate=audit_cert,
        )

    # Hop 3: Triage agent
    t0 = time.time()
    with telemetry.trace_span("triage_hop", case_id=item.case_id):
        triage_result = triage.triage(
            case_id=item.case_id,
            sender=sender,
            channel=source_channel,
            screened_content=item.raw_text,
            tr=tr,
            threat_intel_summary=intel_report.formatted_summary,
        )
    t1 = time.time()
    hop_durations["triage"] = (t1 - t0) * 1000.0

    # Hop 4: Gateway Action
    t0 = time.time()
    with telemetry.trace_span("gateway_action_hop", case_id=item.case_id, attributes={"severity": triage_result.severity}):
        action_record = action.act(case_id=item.case_id, severity=triage_result.severity, tr=tr)
    t1 = time.time()
    hop_durations["action"] = (t1 - t0) * 1000.0

    # Hop 5: Memory Bank recall summary
    t0 = time.time()
    with telemetry.trace_span("memory_bank_write_hop", case_id=item.case_id, attributes={"synthetic": synthetic}):
        if synthetic:
            tr.log("memory_bank", "skipped write (synthetic demo traffic)")
        else:
            triage.write_memory_summary(
                sender=sender,
                case_id=item.case_id,
                summary=(
                    f"{source_channel} from {sender} classified {triage_result.severity}/"
                    f"{triage_result.category}: {triage_result.reasoning}"
                ),
            )
            tr.log("memory_bank", f"wrote summary for sender domain of {sender}")
    t1 = time.time()
    hop_durations["memory_bank"] = (t1 - t0) * 1000.0

    # Sign Cryptographic Audit Certificate
    audit_cert = audit.generate_certificate(
        case_id=item.case_id,
        outcome="actioned",
        model_armor_verdict=armor_result.verdict,
        actor_identity="soc-agent-gateway-v1"
    )
    case_store.update_case(item.case_id, {"audit_certificate": audit_cert.to_dict()})
    tr.log("audit", f"signed SHA-256 certificate {audit_cert.certificate_id}")

    trace.persist_trace(tr)
    events.publish(
        "case_complete",
        {
            "case_id": item.case_id,
            "outcome": "actioned",
            "armor_verdict": armor_result.verdict,
            "armor_threat_type": armor_result.threat_type,
            "severity": triage_result.severity,
            "category": triage_result.category,
            "action_taken": action_record.type,
            "degraded": not triage_result.llm_used,
        },
    )

    total_duration_ms = (time.time() - start_total_t) * 1000.0
    telemetry.record_pipeline_telemetry(
        case_id=item.case_id,
        source_channel=source_channel,
        outcome="actioned",
        armor_verdict=armor_result.verdict,
        threat_type=armor_result.threat_type,
        llm_used=triage_result.llm_used,
        total_duration_ms=total_duration_ms,
        hop_durations_ms=hop_durations
    )
    telemetry.log_event("pipeline_actioned", {
        "case_id": item.case_id,
        "severity": triage_result.severity,
        "action_taken": action_record.type,
        "duration_ms": round(total_duration_ms, 2)
    })

    return PipelineResult(
        case_id=item.case_id,
        armor_result=armor_result,
        triage_result=triage_result,
        action_record=action_record,
        trace=tr,
        threat_intel_report=intel_report,
        audit_certificate=audit_cert,
    )


