import os
import requests

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(message: str):
    if not SLACK_WEBHOOK:
        return

    try:
        requests.post(
            SLACK_WEBHOOK,
            json={"text": message},
            timeout=5
        )
    except:
        pass