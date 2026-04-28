import json
import re
from typing import Any, Dict


def detect_provider(log_text: str) -> str:
    text = log_text.lower()

    if "cloudtrail" in text or "guardduty" in text or "awsregion" in text:
        return "AWS"

    if "azure" in text or "entra" in text or "signinlogs" in text or "operationname" in text:
        return "AZURE"

    if "gcp" in text or "google.cloud" in text or "protoPayload" in text or "resourceName" in text:
        return "GCP"

    if "failed password" in text or "sshd" in text:
        return "LINUX_AUTH"

    if "nginx" in text or "http" in text:
        return "WEB_LOG"

    return "GENERIC"


def parse_input(raw_input: Any) -> Dict[str, Any]:
    if isinstance(raw_input, dict):
        return {
            "format": "json",
            "provider": detect_provider(json.dumps(raw_input)),
            "normalized": raw_input,
            "raw": raw_input
        }

    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
            return {
                "format": "json",
                "provider": detect_provider(raw_input),
                "normalized": parsed,
                "raw": raw_input
            }
        except json.JSONDecodeError:
            return {
                "format": "plain_text",
                "provider": detect_provider(raw_input),
                "normalized": normalize_plain_text(raw_input),
                "raw": raw_input
            }

    return {
        "format": "unknown",
        "provider": "GENERIC",
        "normalized": {"message": str(raw_input)},
        "raw": raw_input
    }


def normalize_plain_text(log_text: str) -> Dict[str, Any]:
    ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text)

    return {
        "message": log_text,
        "source_ips": ip_match,
        "possible_indicators": extract_indicators(log_text)
    }


def extract_indicators(text: str):
    indicators = []

    suspicious_words = [
        "failed",
        "denied",
        "unauthorized",
        "error",
        "malware",
        "crypto",
        "root",
        "admin",
        "mfa",
        "tor",
        "exfiltration",
        "permission",
        "privilege",
        "key",
        "token"
    ]

    lower_text = text.lower()

    for word in suspicious_words:
        if word in lower_text:
            indicators.append(word)

    return indicators