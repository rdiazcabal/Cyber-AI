MITRE_MAP = {
    "ConsoleLogin": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "subtechnique": "T1078.004 Cloud Accounts"
    },
    "SignIn": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "subtechnique": "T1078.004 Cloud Accounts"
    },
    "CreateAccessKey": {
        "tactic": "Persistence",
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "subtechnique": "T1098.001 Additional Cloud Credentials"
    },
    "AttachUserPolicy": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "subtechnique": "T1098.003 Additional Cloud Roles"
    },
    "SetIamPolicy": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "subtechnique": "Cloud IAM Policy Modification"
    },
    "PutBucketPolicy": {
        "tactic": "Collection / Exfiltration",
        "technique_id": "T1530",
        "technique": "Data from Cloud Storage",
        "subtechnique": "Cloud Storage Public Exposure"
    },
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": {
        "tactic": "Impact",
        "technique_id": "T1496",
        "technique": "Resource Hijacking",
        "subtechnique": "Cloud Compute Resource Hijacking"
    }
}


def map_mitre(event_name: str) -> dict:
    return MITRE_MAP.get(event_name, {
        "tactic": "Unknown",
        "technique_id": "Unknown",
        "technique": "Unknown",
        "subtechnique": "Unknown"
    })


def build_mitre_coverage(events: list) -> dict:
    coverage = {}

    for event in events:
        event_name = event.get("eventName") or event.get("type") or "Unknown"
        mitre = map_mitre(event_name)
        tactic = mitre["tactic"]

        if tactic not in coverage:
            coverage[tactic] = {
                "count": 0,
                "techniques": []
            }

        coverage[tactic]["count"] += 1

        technique = {
            "event": event_name,
            "technique_id": mitre["technique_id"],
            "technique": mitre["technique"],
            "subtechnique": mitre["subtechnique"]
        }

        if technique not in coverage[tactic]["techniques"]:
            coverage[tactic]["techniques"].append(technique)

    return coverage