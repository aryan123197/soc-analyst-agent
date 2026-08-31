"""One-time OAuth flow to mint a Gmail refresh token for the live inbox source.

Run this locally (it opens a browser); the resulting refresh token is what
soc_agent/sources/gmail.py uses, and what you set on the Cloud Run service.

Setup, once, in the Cloud Console for your project:
  1. APIs & Services > Library > enable "Gmail API".
  2. APIs & Services > OAuth consent screen > External. While it is in "Testing"
     mode, add the demo Gmail account under "Test users" -- otherwise the flow
     fails with access_denied.
  3. APIs & Services > Credentials > Create Credentials > OAuth client ID >
     "Desktop app". Download the JSON.

Then:
    export GMAIL_OAUTH_CLIENT_SECRETS=/path/to/downloaded_client_secret.json
    python -m soc_agent.scripts.gmail_auth

It prints the three values to add to .env (and to the Cloud Run service via
`gcloud run services update ... --update-env-vars`). Treat the refresh token as
a secret: it is not printed to logs anywhere else, and .env is gitignored.
"""
import json
import os
import sys

from soc_agent.sources.gmail import SCOPES


def main() -> int:
    secrets_path = os.environ.get("GMAIL_OAUTH_CLIENT_SECRETS")
    if not secrets_path or not os.path.exists(secrets_path):
        print(
            "Set GMAIL_OAUTH_CLIENT_SECRETS to the OAuth client JSON you "
            "downloaded from the Cloud Console (see this module's docstring).",
            file=sys.stderr,
        )
        return 1

    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(secrets_path, SCOPES)
    creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

    if not creds.refresh_token:
        print(
            "No refresh token returned. Revoke the app's access at "
            "https://myaccount.google.com/permissions and re-run.",
            file=sys.stderr,
        )
        return 1

    installed = json.load(open(secrets_path))
    client = installed.get("installed") or installed.get("web") or {}

    print("\nAdd these to .env:\n")
    print(f"GMAIL_CLIENT_ID={client.get('client_id', '')}")
    print(f"GMAIL_CLIENT_SECRET={client.get('client_secret', '')}")
    print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
