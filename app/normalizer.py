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

IOC_IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
IOC_DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
IOC_URL_REGEX = r"https?://[^\s\"'<>]+"
IOC_SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
IOC_MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"


def extract_iocs_from_text(raw_text: str) -> dict:
    """
    Extracts basic IOCs from any raw log/text.
    Does not replace your existing parse_input().
    """
    if not raw_text:
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": []
        }

    ips = sorted(set(re.findall(IOC_IP_REGEX, raw_text)))
    urls = sorted(set(re.findall(IOC_URL_REGEX, raw_text)))
    domains = sorted(set(re.findall(IOC_DOMAIN_REGEX, raw_text)))
    hashes = sorted(set(re.findall(IOC_SHA256_REGEX, raw_text) + re.findall(IOC_MD5_REGEX, raw_text)))

    # Avoid counting domains already inside URLs too aggressively, but keep simple for MVP
    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "hashes": hashes
    }