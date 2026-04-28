from app.mitre_mapper import map_mitre


def build_detection(
    name: str,
    severity: str,
    confidence: int,
    behavior: str,
    attack_type: str,
    event_name: str,
    entities: dict,
    recommended_response: list
) -> dict:
    return {
        "detection_name": name,
        "severity": severity,
        "confidence": confidence,
        "behavior": behavior,
        "attack_type": attack_type,
        "mitre": map_mitre(event_name),
        "entities": entities,
        "recommended_response": recommended_response
    }


def run_detections(events: list, normalized_events: list) -> list:
    detections = []

    event_names = [
        event.get("eventName") or event.get("type") or event.get("rule") or "Unknown"
        for event in events
    ]

    descriptions = " ".join([
        str(event.get("description", "")).lower()
        for event in events
    ])

    users = list(set([
        event.get("user", "N/A")
        for event in normalized_events
        if event.get("user") and event.get("user") != "N/A"
    ]))

    ips = list(set([
        event.get("source_ip", "N/A")
        for event in normalized_events
        if event.get("source_ip") and event.get("source_ip") != "N/A"
    ]))

    resources = list(set([
        str(event.get("resource", "N/A"))
        for event in normalized_events
        if event.get("resource") and event.get("resource") != "N/A"
    ]))

    has_login = "ConsoleLogin" in event_names or "SignIn" in event_names
    has_create_key = "CreateAccessKey" in event_names
    has_attach_policy = "AttachUserPolicy" in event_names or "SetIamPolicy" in event_names
    has_public_bucket = "PutBucketPolicy" in event_names or "public" in descriptions
    has_crypto = any("crypto" in str(name).lower() or "bitcoin" in str(name).lower() for name in event_names)
    missing_mfa = any(term in descriptions for term in [
        "without mfa",
        "no mfa",
        "mfa requirement was not satisfied",
        "mfa was not used"
    ])

    entities = {
        "users": users,
        "ips": ips,
        "resources": resources
    }

    if has_login and missing_mfa:
        detections.append(build_detection(
            name="Suspicious Authentication Without MFA",
            severity="High",
            confidence=85,
            behavior="Successful authentication without MFA or MFA not satisfied.",
            attack_type="Identity Risk",
            event_name="ConsoleLogin",
            entities=entities,
            recommended_response=[
                "Invalidate active sessions",
                "Force MFA enrollment",
                "Review conditional access policy",
                "Check authentication history"
            ]
        ))

    if has_login and has_create_key:
        detections.append(build_detection(
            name="Cloud Identity Compromise",
            severity="Critical",
            confidence=95,
            behavior="Suspicious login followed by cloud credential creation.",
            attack_type="Credential Abuse",
            event_name="CreateAccessKey",
            entities=entities,
            recommended_response=[
                "Disable or rotate new access keys",
                "Revoke sessions",
                "Force password reset",
                "Review all actions from source IP"
            ]
        ))

    if has_create_key and has_attach_policy:
        detections.append(build_detection(
            name="Persistence and Privilege Escalation",
            severity="Critical",
            confidence=92,
            behavior="Credential creation followed by privileged policy assignment.",
            attack_type="Privilege Escalation",
            event_name="AttachUserPolicy",
            entities=entities,
            recommended_response=[
                "Remove suspicious policy attachments",
                "Disable suspicious credentials",
                "Audit IAM changes",
                "Review newly created users and roles"
            ]
        ))

    if has_public_bucket:
        detections.append(build_detection(
            name="Cloud Storage Exposure",
            severity="High",
            confidence=88,
            behavior="Storage bucket policy indicates possible public exposure.",
            attack_type="Data Exposure",
            event_name="PutBucketPolicy",
            entities=entities,
            recommended_response=[
                "Block public access",
                "Review bucket ACL and policy",
                "Check object access logs",
                "Identify exposed sensitive objects"
            ]
        ))

    if has_crypto:
        detections.append(build_detection(
            name="Resource Hijacking / Crypto Mining",
            severity="Critical",
            confidence=90,
            behavior="Compute resource shows crypto mining indicators.",
            attack_type="Resource Hijacking",
            event_name="CryptoCurrency:EC2/BitcoinTool.B!DNS",
            entities=entities,
            recommended_response=[
                "Isolate affected workload",
                "Capture forensic snapshot",
                "Review process and network activity",
                "Rotate instance role credentials"
            ]
        ))

    return detections