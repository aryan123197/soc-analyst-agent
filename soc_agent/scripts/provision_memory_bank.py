#!/usr/bin/env python3
"""One-time setup: create the Agent Engine that backs the Memory Bank.

Memory Bank has no project-level resource — every call is parented to an Agent
Engine (ReasoningEngine). This creates a memory-bank-only engine: it declares a
context_spec.memory_bank_config and deploys no agent code. Safe to re-run —
reuses the existing engine if one with the same display name is present.

Prints the engine ID to set as AGENT_ENGINE_ID in .env.

Usage: python -m soc_agent.scripts.provision_memory_bank
"""
from google.cloud import aiplatform_v1beta1

from soc_agent import config

DISPLAY_NAME = "soc-analyst-memory-bank"


def provision() -> str:
    if not config.GOOGLE_CLOUD_PROJECT:
        raise SystemExit("GOOGLE_CLOUD_PROJECT is not set — cannot provision a GCP resource.")

    location = config.GOOGLE_CLOUD_LOCATION
    client = aiplatform_v1beta1.ReasoningEngineServiceClient(
        client_options={"api_endpoint": f"{location}-aiplatform.googleapis.com"}
    )
    parent = f"projects/{config.GOOGLE_CLOUD_PROJECT}/locations/{location}"

    for engine in client.list_reasoning_engines(parent=parent):
        if engine.display_name == DISPLAY_NAME:
            print(f"Agent Engine already exists: {engine.name}")
            return engine.name

    engine = aiplatform_v1beta1.ReasoningEngine(
        display_name=DISPLAY_NAME,
        context_spec=aiplatform_v1beta1.ReasoningEngineContextSpec(
            memory_bank_config=aiplatform_v1beta1.ReasoningEngineContextSpec.MemoryBankConfig(),
        ),
    )
    created = client.create_reasoning_engine(
        parent=parent, reasoning_engine=engine
    ).result()
    print(f"Created Agent Engine: {created.name}")
    return created.name


if __name__ == "__main__":
    name = provision()
    print(f"\nSet this in .env:\n  AGENT_ENGINE_ID={name.split('/')[-1]}")
