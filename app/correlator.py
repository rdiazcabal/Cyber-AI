import re
from typing import List, Dict, Any


def get_field(event: Dict[str, Any], *paths, default="N/A"):
    for path in paths:
        current = event
        try:
            for key in path.split("."):
                current = current[key]
            return current
        except Exception:
            continue
    return default

def normalize_resource(resource):
    if isinstance(resource, dict):
        return (
            resource.get("instanceId")
            or resource.get("bucket")
            or resource.get("resourceId")
            or resource.get("resourceName")
            or resource.get("id")
            or str(resource)
        )

    if resource:
        return str(resource)

    return "N/A"

def extract_iocs(events: List[Dict[str, Any]]) -> Dict[str, list]:
    raw = str(events)

    ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)))
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw)))

    usernames = []
    resources = []

    for event in events:
        user = get_field(
            event,
            "userIdentity.userName",
            "principalEmail",
            "user",
            default=None
        )

        if user:
            usernames.append(user)

        resource = normalize_resource(
            event.get("resource")
            or event.get("bucket")
            or event.get("resourceId")
            or event.get("resourceName")
        )

        if resource and resource != "N/A":
            resources.append(resource)

    return {
        "ips": list(set(ips)),
        "users": list(set(emails + usernames)),
        "resources": list(set(resources))
    }

def parse_severity(value) -> float:
    if value is None:
        return 0.0

    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip().upper()

    severity_map = {
        "DEBUG": 1.0,
        "DEFAULT": 1.0,
        "INFO": 2.0,
        "NOTICE": 3.0,
        "LOW": 3.0,
        "WARNING": 5.0,
        "WARN": 5.0,
        "MEDIUM": 5.0,
        "ERROR": 7.0,
        "ERR": 7.0,
        "HIGH": 8.0,
        "CRITICAL": 9.5,
        "ALERT": 10.0,
        "EMERGENCY": 10.0,
        "FATAL": 10.0,
    }

    if text in severity_map:
        return severity_map[text]

    try:
        return float(text)
    except Exception:
        return 0.0

def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    severity = parse_severity(
        event.get("severity")
        or event.get("Severity")
        or event.get("level")
        or event.get("severityLabel")
        or 0
    )

    resource = normalize_resource(
        event.get("resource")
        or event.get("bucket")
        or event.get("resourceId")
        or event.get("resourceName")
        or event.get("dst_ip")
        or get_field(event, "resource.labels.service_name", default=None)
    )

    service = (
        event.get("service")
        or event.get("source")
        or event.get("cloud")
        or get_field(event, "resource.labels.service_name", default=None)
        or get_field(event, "resource.type", default="Unknown")
    )

    event_name = (
        event.get("eventName")
        or event.get("event_type")
        or event.get("type")
        or event.get("rule")
        or event.get("rule_name")
        or get_field(event, "protoPayload.methodName", default=None)
        or get_field(event, "httpRequest.requestMethod", default=None)
        or "Unknown"
    )

    source_ip = (
        event.get("sourceIPAddress")
        or event.get("src_ip")
        or event.get("remoteIp")
        or get_field(event, "httpRequest.remoteIp", default=None)
        or get_field(event, "network.remoteIp", default="N/A")
    )

    user = get_field(
        event,
        "userIdentity.userName",
        "principalEmail",
        "protoPayload.authenticationInfo.principalEmail",
        "user",
        default="N/A"
    )

    description = (
        event.get("description")
        or event.get("message")
        or event.get("textPayload")
        or get_field(event, "jsonPayload.message", default="")
        or ""
    )

    return {
        "service": service,
        "severity": severity,
        "eventName": event_name,
        "user": user,
        "source_ip": source_ip,
        "resource": resource,
        "description": description,
    }

def build_pattern(name, severity, description, mitre, kill_chain, attack_type, playbook):
    return {
        "name": name,
        "severity": severity,
        "description": description,
        "mitre": mitre,
        "kill_chain_phase": kill_chain,
        "attack_type": attack_type,
        "playbook": playbook
    }

def correlate_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    normalized = [normalize_event(e) for e in events]

    patterns = []
    risk_score = 0

    event_names = [e["eventName"] for e in normalized]
    descriptions = " ".join([e["description"].lower() for e in normalized])
    iocs = extract_iocs(events)

    has_console_login = "ConsoleLogin" in event_names or "SignIn" in event_names
    has_create_access_key = "CreateAccessKey" in event_names
    has_attach_policy = "AttachUserPolicy" in event_names or "SetIamPolicy" in event_names

    has_public_bucket = any(
        e["eventName"] == "PutBucketPolicy" or "public" in e["description"].lower()
        for e in normalized
    )

    has_crypto = any(
        "crypto" in e["eventName"].lower() or "bitcoin" in e["eventName"].lower()
        for e in normalized
    )

    has_missing_mfa = any(term in descriptions for term in [
        "without mfa",
        "no mfa",
        "mfaused': 'no",
        'mfaused": "no',
        "mfa requirement was not satisfied",
        "mfa was not used"
    ])

    if has_console_login and has_create_access_key:
        patterns.append(build_pattern(
            name="Possible Credential Compromise",
            severity="Critical",
            description="Suspicious login followed by access key creation.",
            mitre="T1078 Valid Accounts / T1098 Account Manipulation",
            kill_chain="Exploitation / Installation",
            attack_type="Credential Abuse",
            playbook=[
                "Revoke active sessions",
                "Disable or rotate access keys",
                "Force password reset",
                "Review CloudTrail activity for the user",
                "Validate MFA configuration"
            ]
        ))
        risk_score += 35

    if has_create_access_key and has_attach_policy:
        patterns.append(build_pattern(
            name="Privilege Escalation / Persistence",
            severity="Critical",
            description="Access key creation followed by privileged policy assignment.",
            mitre="T1098 Account Manipulation",
            kill_chain="Installation / Persistence",
            attack_type="Privilege Escalation",
            playbook=[
                "Remove newly attached privileged policies",
                "Disable suspicious access keys",
                "Review IAM policy changes",
                "Check for newly created users, roles, or trust policies",
                "Escalate to incident response"
            ]
        ))
        risk_score += 30

    if has_missing_mfa:
        patterns.append(build_pattern(
            name="MFA Bypass / Missing MFA",
            severity="High",
            description="Authentication activity indicates MFA was not used or not satisfied.",
            mitre="T1078 Valid Accounts",
            kill_chain="Exploitation",
            attack_type="Identity Risk",
            playbook=[
                "Enforce MFA for the affected identity",
                "Apply conditional access policies",
                "Review login source IP and geo-location",
                "Invalidate active sessions",
                "Check for additional suspicious authentication events"
            ]
        ))
        risk_score += 15

    if has_public_bucket:
        patterns.append(build_pattern(
            name="Potential Data Exposure",
            severity="High",
            description="Storage configuration indicates possible public exposure.",
            mitre="T1530 Data from Cloud Storage",
            kill_chain="Actions on Objectives",
            attack_type="Data Exposure",
            playbook=[
                "Block public access immediately",
                "Review bucket policy and ACLs",
                "Check object access logs",
                "Identify sensitive exposed objects",
                "Rotate credentials if data access is confirmed"
            ]
        ))
        risk_score += 20

    if has_crypto:
        patterns.append(build_pattern(
            name="Crypto Mining Activity",
            severity="Critical",
            description="Compute resource shows indicators of crypto mining activity.",
            mitre="T1496 Resource Hijacking",
            kill_chain="Actions on Objectives",
            attack_type="Resource Hijacking",
            playbook=[
                "Isolate affected instance",
                "Capture forensic snapshot",
                "Review process and network activity",
                "Rotate instance role credentials",
                "Terminate malicious workload after evidence collection"
            ]
        ))
        risk_score += 30

    return {
        "risk_score": min(risk_score, 100),
        "patterns_detected": patterns,
        "iocs": iocs,
        "normalized_events": normalized
    }