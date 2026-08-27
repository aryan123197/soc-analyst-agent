#!/usr/bin/env python3
"""One-time setup: create/update the Model Armor Template this pipeline screens against.

Enables:
  - PI-and-jailbreak filter (prompt injection / jailbreak detection), LOW_AND_ABOVE
  - SDP basic filter (sensitive data present in content), ENABLED
  - Malicious URI filter (phishing/C2 links embedded in content), ENABLED

Idempotent: creates the template if it doesn't exist, otherwise updates it in
place to match the filter config defined here (so re-running after editing
this file picks up the change on the existing template).

Usage: python -m soc_agent.scripts.provision_model_armor
"""
from google.api_core.exceptions import AlreadyExists
from google.cloud import modelarmor_v1
from google.protobuf import field_mask_pb2

from soc_agent import config

TEMPLATE_ID = "soc-analyst-armor-template"


def _filter_config() -> "modelarmor_v1.FilterConfig":
    return modelarmor_v1.FilterConfig(
        pi_and_jailbreak_filter_settings=modelarmor_v1.PiAndJailbreakFilterSettings(
            filter_enforcement=modelarmor_v1.PiAndJailbreakFilterSettings.PiAndJailbreakFilterEnforcement.ENABLED,
            confidence_level=modelarmor_v1.DetectionConfidenceLevel.LOW_AND_ABOVE,
        ),
        sdp_settings=modelarmor_v1.SdpFilterSettings(
            basic_config=modelarmor_v1.SdpBasicConfig(
                filter_enforcement=modelarmor_v1.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED,
            ),
        ),
        malicious_uri_filter_settings=modelarmor_v1.MaliciousUriFilterSettings(
            filter_enforcement=modelarmor_v1.MaliciousUriFilterSettings.MaliciousUriFilterEnforcement.ENABLED,
        ),
    )


def provision() -> str:
    if not config.GOOGLE_CLOUD_PROJECT:
        raise SystemExit("GOOGLE_CLOUD_PROJECT is not set — cannot provision a GCP resource.")

    location = config.GOOGLE_CLOUD_LOCATION
    api_endpoint = f"modelarmor.{location}.rep.googleapis.com"
    client = modelarmor_v1.ModelArmorClient(client_options={"api_endpoint": api_endpoint})

    parent = f"projects/{config.GOOGLE_CLOUD_PROJECT}/locations/{location}"
    template_name = client.template_path(config.GOOGLE_CLOUD_PROJECT, location, TEMPLATE_ID)

    template = modelarmor_v1.Template(filter_config=_filter_config())

    try:
        created = client.create_template(parent=parent, template=template, template_id=TEMPLATE_ID)
        print(f"Created template: {created.name}")
        return created.name
    except AlreadyExists:
        pass

    template.name = template_name
    updated = client.update_template(
        template=template,
        update_mask=field_mask_pb2.FieldMask(paths=["filter_config"]),
    )
    print(f"Updated existing template: {updated.name}")
    return updated.name


if __name__ == "__main__":
    provision()
