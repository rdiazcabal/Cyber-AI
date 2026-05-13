# Sample Logs para Demo

## Sample 1 - AWS suspicious login and access key creation

```json
{
  "events": [
    {
      "service": "CloudTrail",
      "severity": 9.2,
      "eventName": "ConsoleLogin",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "admin-user"
      },
      "sourceIPAddress": "8.8.8.8",
      "awsRegion": "us-east-1",
      "description": "Successful console login without MFA from suspicious public IP."
    },
    {
      "service": "CloudTrail",
      "severity": 8.8,
      "eventName": "CreateAccessKey",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "admin-user"
      },
      "sourceIPAddress": "8.8.8.8",
      "awsRegion": "us-east-1",
      "description": "Access key created shortly after suspicious login."
    },
    {
      "service": "CloudTrail",
      "severity": 7.9,
      "eventName": "AttachUserPolicy",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "admin-user"
      },
      "sourceIPAddress": "8.8.8.8",
      "awsRegion": "us-east-1",
      "description": "Administrative policy attached to IAM user."
    }
  ]
}
```

## Sample 2 - Web suspicious domain

```json
{
  "events": [
    {
      "service": "Web",
      "severity": 7.5,
      "eventName": "SuspiciousRequest",
      "sourceIPAddress": "185.199.108.153",
      "domain": "malicious-example.com",
      "url": "https://malicious-example.com/payload",
      "description": "Suspicious outbound request to external domain."
    },
    {
      "service": "Web",
      "severity": 8.1,
      "eventName": "PossibleDataExfiltration",
      "sourceIPAddress": "185.199.108.153",
      "domain": "malicious-example.com",
      "url": "https://malicious-example.com/upload",
      "description": "Large outbound data transfer to suspicious external domain."
    }
  ]
}
```

## Sample 3 - Linux failed login brute force

```json
{
  "events": [
    {
      "service": "Linux",
      "severity": 6.8,
      "eventName": "FailedPassword",
      "username": "root",
      "sourceIPAddress": "45.133.1.10",
      "description": "Failed password for root from 45.133.1.10 port 54231 ssh2"
    },
    {
      "service": "Linux",
      "severity": 7.2,
      "eventName": "FailedPassword",
      "username": "admin",
      "sourceIPAddress": "45.133.1.10",
      "description": "Multiple failed SSH authentication attempts."
    },
    {
      "service": "Linux",
      "severity": 8.0,
      "eventName": "AcceptedPassword",
      "username": "admin",
      "sourceIPAddress": "45.133.1.10",
      "description": "Successful SSH login after multiple failed attempts."
    }
  ]
}
```