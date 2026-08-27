import os

from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLOUD_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
GOOGLE_CLOUD_LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
FIRESTORE_EMULATOR_HOST = os.environ.get("FIRESTORE_EMULATOR_HOST", "")

USE_LOCAL_STORE = not GOOGLE_CLOUD_PROJECT and not FIRESTORE_EMULATOR_HOST
