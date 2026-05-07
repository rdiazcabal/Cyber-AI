import requests
import os

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")


def send_slack_alert(message: str):
    if not SLACK_WEBHOOK or SLACK_WEBHOOK == "None":
        print("⚠️ Slack webhook not configured, skipping alert")
        return

    payload = {"text": message}

    try:
        requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
    except Exception as e:
        print(f"⚠️ Slack error: {e}")