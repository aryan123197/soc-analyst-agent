"""Ingestion agent — read-only identity, cannot call any action tool.

Responsibilities: accept a raw external item (email/ticket/scraped_page),
store the raw content by reference, create the Firestore case doc, and hand
the raw content off (in-process only) for Model Armor screening. This agent
has zero write-capable tools by construction — there is nothing for a
successful prompt injection to hijack here.
"""
from dataclasses import dataclass

from soc_agent.services import events, raw_content, store, trace


@dataclass
class IngestedItem:
    case_id: str
    raw_content_ref: str
    raw_text: str


def ingest(source_channel: str, sender: str, raw_text: str) -> tuple[IngestedItem, trace.Trace]:
    raw_ref = raw_content.store_raw_content(raw_text)
    case = store.make_case(source_channel=source_channel, sender=sender, raw_content_ref=raw_ref)

    case_store = store.get_case_store()
    case_store.create_case(case)

    tr = trace.new_trace(case["case_id"])
    events.publish(
        "case_start",
        {
            "case_id": case["case_id"],
            "trace_id": tr.trace_id,
            "source_channel": source_channel,
            "sender": sender,
            "preview": raw_text[:280],
        },
    )
    tr.log("ingestion", f"received {source_channel} from {sender}, stored as {raw_ref}")

    return IngestedItem(case_id=case["case_id"], raw_content_ref=raw_ref, raw_text=raw_text), tr
