import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_ip_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {
            "ip": ip,
            "provider": "AbuseIPDB",
            "enabled": False,
            "error": "ABUSEIPDB_API_KEY not configured"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "ip": ip,
            "provider": "AbuseIPDB",
            "enabled": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0)
        }

    except Exception as e:
        return {
            "ip": ip,
            "provider": "AbuseIPDB",
            "enabled": True,
            "error": str(e)
        }


def enrich_iocs(iocs: dict) -> dict:
    ips = iocs.get("ips", [])

    return {
        "ips": [check_ip_abuseipdb(ip) for ip in ips],
        "users": iocs.get("users", []),
        "resources": iocs.get("resources", [])
    }