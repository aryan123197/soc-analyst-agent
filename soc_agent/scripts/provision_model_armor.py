#!/usr/bin/env python3
"""One-time setup: create the Model Armor Template this pipeline screens against.

Enables the PI-and-jailbreak filter (prompt injection / jailbreak detection)
and the SDP basic filter (PII detection) at HIGH enforcement. Safe to re-run —
skips creation if the template already exists.

Usage: python -m soc_agent.scripts.provision_model_armor
"""
from google.api_core.exceptions import AlreadyExists
from google.cloud import modelarmor_v1

from soc_agent import config

TEMPLATE_ID = "soc-analyst-armor-template"


def provision() -> str:
    if not config.GOOGLE_CLOUD_PROJECT:
        raise SystemExit("GOOGLE_CLOUD_PROJECT is not set — cannot provision a GCP resource.")

    location = config.GOOGLE_CLOUD_LOCATION
    api_endpoint = f"modelarmor.{location}.rep.googleapis.com"
    client = modelarmor_v1.ModelArmorClient(client_options={"api_endpoint": api_endpoint})

    parent = f"projects/{config.GOOGLE_CLOUD_PROJECT}/locations/{location}"
    template_name = client.template_path(config.GOOGLE_CLOUD_PROJECT, location, TEMPLATE_ID)

    template = modelarmor_v1.Template(
        filter_config=modelarmor_v1.FilterConfig(
            pi_and_jailbreak_filter_settings=modelarmor_v1.PiAndJailbreakFilterSettings(
                filter_enforcement=modelarmor_v1.PiAndJailbreakFilterSettings.PiAndJailbreakFilterEnforcement.ENABLED,
                confidence_level=modelarmor_v1.DetectionConfidenceLevel.LOW_AND_ABOVE,
            ),
            sdp_settings=modelarmor_v1.SdpFilterSettings(
                basic_config=modelarmor_v1.SdpBasicConfig(
                    filter_enforcement=modelarmor_v1.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED,
                ),
            ),
        ),
    )

    try:
        created = client.create_template(parent=parent, template=template, template_id=TEMPLATE_ID)
        print(f"Created template: {created.name}")
    except AlreadyExists:
        created = client.get_template(name=template_name)
        print(f"Template already exists: {created.name}")

    return created.name


if __name__ == "__main__":
    provision()
