import os
import ipaddress
import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def check_ip_abuse(ip: str) -> dict | None:
    """
    Checks IP reputation using AbuseIPDB.
    Private/reserved/local IPs are skipped.
    Returns None if AbuseIPDB is unavailable or the IP should not be checked.
    """
    if not ABUSEIPDB_API_KEY:
        return None

    if not is_public_ip(ip):
        return None

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=8
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "source": "AbuseIPDB",
                "available": False,
                "error": f"AbuseIPDB HTTP {response.status_code}"
            }

        data = response.json().get("data", {})

        return {
            "ip": ip,
            "source": "AbuseIPDB",
            "available": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_public": True,
        }

    except Exception as e:
        return {
            "ip": ip,
            "source": "AbuseIPDB",
            "available": False,
            "error": str(e)
        }


def enrich_iocs(iocs: dict) -> dict:
    """
    Existing-compatible function.
    Keeps your current calls working:
      enrich_iocs(result.get("iocs", {}))
    """
    ips = []

    if isinstance(iocs, dict):
        ips = iocs.get("ips", []) or iocs.get("ip_addresses", []) or []

    enriched_ips = []

    for ip in ips:
        intel = check_ip_abuse(ip)
        if intel:
            enriched_ips.append(intel)

    return {
        "ips": enriched_ips
    }