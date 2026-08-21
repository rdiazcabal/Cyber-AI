import os
import ipaddress
import requests

try:
    from app.country_name_safe import country_name as _safe_country_name
except Exception:  # pragma: no cover - safe fallback during imports
    _safe_country_name = None

SECURITY_FEEDS_API_KEY = (
    os.getenv("SECURITY_FEEDS_API_KEY")
    or os.getenv("ABUSEIPDB_API_KEY")
)

COUNTRY_FALLBACKS = {
    "US": "United States",
    "GB": "United Kingdom",
    "UK": "United Kingdom",
    "HN": "Honduras",
    "VE": "Venezuela",
    "ZA": "South Africa",
}


def display_country(value: str | None) -> str | None:
    if not value:
        return None

    clean = str(value).strip()
    if not clean:
        return None

    if _safe_country_name:
        try:
            return _safe_country_name(clean)
        except Exception:
            pass

    if len(clean) == 2:
        return COUNTRY_FALLBACKS.get(clean.upper(), clean.upper())

    return clean


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


def check_security_feed_ip(ip: str) -> dict | None:
    """
    Checks IP reputation using configured Security Feeds.
    Private/reserved/local IPs are skipped.
    Returns None if Security Feeds are unavailable or the IP should not be checked.
    """
    if not SECURITY_FEEDS_API_KEY:
        return None

    if not is_public_ip(ip):
        return None

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": SECURITY_FEEDS_API_KEY,
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
                "source": "Security Feeds",
                "available": False,
                "error": f"Security Feeds HTTP {response.status_code}"
            }

        data = response.json().get("data", {})
        raw_country_code = data.get("countryCode")
        normalized_country = display_country(raw_country_code)
        country_iso_code = (
            str(raw_country_code).strip().upper()
            if raw_country_code and len(str(raw_country_code).strip()) == 2
            else None
        )

        return {
            "ip": ip,
            "source": "Security Feeds",
            "available": True,
            "security_feed_score": data.get("abuseConfidenceScore", 0),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            # Legacy frontend sections render country_code directly.
            # Keep it display-ready and preserve the ISO value separately.
            "country_code": normalized_country,
            "countryCode": normalized_country,
            "country": normalized_country,
            "country_name": normalized_country,
            "country_iso_code": country_iso_code,
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
            "source": "Security Feeds",
            "available": False,
            "error": str(e)
        }


def check_ip_abuse(ip: str) -> dict | None:
    """
    Backward-compatible wrapper.
    Do not expose AbuseIPDB naming to the UI.
    """
    return check_security_feed_ip(ip)


def enrich_iocs(iocs: dict) -> dict:
    ips = []

    if isinstance(iocs, dict):
        ips = iocs.get("ips", []) or iocs.get("ip_addresses", []) or []

    enriched_ips = []

    for ip in ips:
        intel = check_security_feed_ip(ip)
        if intel:
            enriched_ips.append(intel)

    return {
        "ips": enriched_ips
    }
