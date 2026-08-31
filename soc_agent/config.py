import os

from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLOUD_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
GOOGLE_CLOUD_LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_LOCATION = os.environ.get("GEMINI_LOCATION", "global")
MODEL_ARMOR_TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "soc-analyst-armor-template")
AGENT_ENGINE_ID = os.environ.get("AGENT_ENGINE_ID", "")

USE_LOCAL_STORE = not GOOGLE_CLOUD_PROJECT and not os.environ.get("FIRESTORE_EMULATOR_HOST")
USE_VERTEX_MODEL_ARMOR = bool(GOOGLE_CLOUD_PROJECT)
USE_VERTEX_MEMORY_BANK = bool(GOOGLE_CLOUD_PROJECT and AGENT_ENGINE_ID)

# Connector Configuration (Jira, ServiceNow, Splunk HEC)
JIRA_URL = os.environ.get("JIRA_URL", "")
JIRA_USER_EMAIL = os.environ.get("JIRA_USER_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SOC")

SERVICENOW_INSTANCE = os.environ.get("SERVICENOW_INSTANCE", "")
SERVICENOW_USER = os.environ.get("SERVICENOW_USER", "")
SERVICENOW_PASSWORD = os.environ.get("SERVICENOW_PASSWORD", "")

SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")

JIRA_ENABLED = bool(JIRA_URL and JIRA_USER_EMAIL and JIRA_API_TOKEN)
SERVICENOW_ENABLED = bool(SERVICENOW_INSTANCE and SERVICENOW_USER and SERVICENOW_PASSWORD)
SPLUNK_ENABLED = bool(SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN)

