CIS_MAPPING = {
    "Brute Force Login": ["CIS 5", "CIS 6"],
    "Suspicious IP": ["CIS 13"],
    "Privilege Escalation": ["CIS 5", "CIS 6"],
    "Malware Activity": ["CIS 10"],
    "Data Exfiltration": ["CIS 3", "CIS 13"],
}


def map_to_cis(detections: list, result: dict | None = None) -> list:
    """
    Maps detections and analysis context to CIS Controls v8.
    This does not replace MITRE mapping; it complements it for compliance reporting.
    """

    result = result or {}
    cis_controls = set()

    detection_text = " ".join(
        [
            str(d.get("name", "")) + " " +
            str(d.get("title", "")) + " " +
            str(d.get("description", "")) + " " +
            str(d.get("severity", ""))
            for d in detections or []
            if isinstance(d, dict)
        ]
    ).lower()

    result_text = str(result).lower()

    combined_text = f"{detection_text} {result_text}"

    if any(x in combined_text for x in ["login", "brute force", "failed password", "authentication", "mfa"]):
        cis_controls.update([
            "CIS 5 - Account Management",
            "CIS 6 - Access Control Management"
        ])

    if any(x in combined_text for x in ["iam", "privilege", "admin", "policy", "permission", "access key"]):
        cis_controls.update([
            "CIS 5 - Account Management",
            "CIS 6 - Access Control Management"
        ])

    if any(x in combined_text for x in ["s3", "bucket", "public", "exfiltration", "data exposure", "sensitive data"]):
        cis_controls.update([
            "CIS 3 - Data Protection"
        ])

    if any(x in combined_text for x in ["malware", "crypto", "cryptomining", "bitcoin", "trojan", "ransomware"]):
        cis_controls.update([
            "CIS 10 - Malware Defenses"
        ])

    if any(x in combined_text for x in ["ip", "suspicious", "abuseipdb", "threat intel", "ioc", "indicator"]):
        cis_controls.update([
            "CIS 13 - Network Monitoring and Defense"
        ])

    if any(x in combined_text for x in ["cloudtrail", "audit", "log", "guardduty", "security hub"]):
        cis_controls.update([
            "CIS 8 - Audit Log Management"
        ])

    if any(x in combined_text for x in ["vulnerability", "cve", "patch", "exploit"]):
        cis_controls.update([
            "CIS 7 - Continuous Vulnerability Management"
        ])

    if any(x in combined_text for x in ["incident", "case", "critical", "high", "containment", "response"]):
        cis_controls.update([
            "CIS 17 - Incident Response Management"
        ])

    if not cis_controls:
        cis_controls.add("CIS 13 - Network Monitoring and Defense")

    return sorted(cis_controls)

