import os
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")


def send_slack_alert(message: str):
    payload = {
        "text": f" *Cyber-AI Alert*\n{message}"
    }

    requests.post(SLACK_WEBHOOK, json=payload)