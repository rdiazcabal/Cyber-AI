import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"


def get_guardduty_detector_id():
    client = boto3.client("guardduty", region_name=REGION)
    response = client.list_detectors()

    detectors = response.get("DetectorIds", [])

    if not detectors:
        raise Exception("No GuardDuty detector found in this region")

    return detectors[0]


def get_guardduty_findings(max_results: int = 5):
    client = boto3.client("guardduty", region_name=REGION)

    detector_id = get_guardduty_detector_id()

    findings_response = client.list_findings(
        DetectorId=detector_id,
        MaxResults=max_results,
        SortCriteria={
            "AttributeName": "updatedAt",
            "OrderBy": "DESC"
        }
    )

    finding_ids = findings_response.get("FindingIds", [])

    if not finding_ids:
        return []

    details_response = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )

    return details_response.get("Findings", [])