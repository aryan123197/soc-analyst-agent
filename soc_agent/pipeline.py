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
from dataclasses import dataclass
from typing import Optional

from soc_agent import config
from soc_agent.agents import action, ingestion, triage
from soc_agent.services import events, model_armor, store, trace


@dataclass
class PipelineResult:
    case_id: str
    armor_result: model_armor.ArmorResult
    triage_result: Optional[triage.TriageResult]
    action_record: Optional[object]
    trace: trace.Trace


def run_pipeline(
    source_channel: str,
    sender: str,
    raw_text: str,
    armor_enabled: bool = True,
) -> PipelineResult:
    item, tr = ingestion.ingest(source_channel=source_channel, sender=sender, raw_text=raw_text)

    armor = model_armor.get_model_armor(
        enabled=armor_enabled,
        project=config.GOOGLE_CLOUD_PROJECT if config.USE_VERTEX_MODEL_ARMOR else None,
        location=config.GOOGLE_CLOUD_LOCATION,
        template_id=config.MODEL_ARMOR_TEMPLATE_ID,
    )
    armor_result = armor.screen(item.raw_text)

    case_store = store.get_case_store()
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
        action.quarantine(item.case_id, threat_type=armor_result.threat_type or "unknown", tr=tr)
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
        return PipelineResult(
            case_id=item.case_id,
            armor_result=armor_result,
            triage_result=None,
            action_record=None,
            trace=tr,
        )

    triage_result = triage.triage(
        case_id=item.case_id,
        sender=sender,
        channel=source_channel,
        screened_content=item.raw_text,
        tr=tr,
    )

    action_record = action.act(case_id=item.case_id, severity=triage_result.severity, tr=tr)

    triage.write_memory_summary(
        sender=sender,
        case_id=item.case_id,
        summary=(
            f"{source_channel} from {sender} classified {triage_result.severity}/"
            f"{triage_result.category}: {triage_result.reasoning}"
        ),
    )
    tr.log("memory_bank", f"wrote summary for sender domain of {sender}")
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
        },
    )

    return PipelineResult(
        case_id=item.case_id,
        armor_result=armor_result,
        triage_result=triage_result,
        action_record=action_record,
        trace=tr,
    )
