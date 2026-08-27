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
