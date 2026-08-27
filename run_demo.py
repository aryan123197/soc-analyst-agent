#!/usr/bin/env python3
"""Demo runner: runs the curated attack corpus through the pipeline.

Default: runs all 5 corpus cases with Model Armor enabled.
`--before-after`: runs the classic injection case twice -- once with Model
Armor disabled (agent gets manipulated), once enabled (blocked + quarantined,
visible in the trace) -- for the before/after demo clip.
"""
import argparse

from soc_agent.corpus.attack_cases import CASES
from soc_agent.pipeline import run_pipeline


def print_result(result, expected=None) -> None:
    print(result.trace.render())
    print(f"  case_id: {result.case_id}")
    print(f"  final status in store: model_armor={result.armor_result.verdict}", end="")
    if result.triage_result:
        print(f", triage={result.triage_result.severity}/{result.triage_result.category}", end="")
    if result.action_record:
        print(f", action={result.action_record.type}", end="")
    print()
    if expected is not None:
        ok = result.armor_result.verdict == expected
        print(f"  expected verdict={expected} -> {'PASS' if ok else 'FAIL'}")
    print()


def run_corpus() -> None:
    for case in CASES:
        print("=" * 100)
        print(f"CASE: {case['label']}")
        print(f"  {case['description']}")
        print("-" * 100)
        result = run_pipeline(
            source_channel=case["source_channel"],
            sender=case["sender"],
            raw_text=case["raw_text"],
            armor_enabled=True,
        )
        print_result(result, expected=case["expected_verdict"])


def run_before_after() -> None:
    injection_case = next(c for c in CASES if c["label"] == "classic_prompt_injection_email")

    print("=" * 100)
    print("BEFORE: Model Armor DISABLED")
    print(f"  {injection_case['description']}")
    print("-" * 100)
    before = run_pipeline(
        source_channel=injection_case["source_channel"],
        sender=injection_case["sender"],
        raw_text=injection_case["raw_text"],
        armor_enabled=False,
    )
    print_result(before)
    if before.action_record:
        print("  >>> UNPROTECTED: pipeline proceeded to triage/action on manipulated content.")
    print()

    print("=" * 100)
    print("AFTER: Model Armor ENABLED")
    print(f"  {injection_case['description']}")
    print("-" * 100)
    after = run_pipeline(
        source_channel=injection_case["source_channel"],
        sender=injection_case["sender"],
        raw_text=injection_case["raw_text"],
        armor_enabled=True,
    )
    print_result(after, expected="blocked")
    print("  >>> PROTECTED: payload blocked at ingestion->triage boundary, case quarantined.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--before-after",
        action="store_true",
        help="Run the classic injection case with Model Armor disabled then enabled.",
    )
    args = parser.parse_args()

    if args.before_after:
        run_before_after()
    else:
        run_corpus()
