"""On-prem agent ingest API for SecuRI.

This module registers lightweight endpoints on the existing FastAPI app without
requiring database migrations. The first MVP supports:

- Agent heartbeat
- Agent configuration pull
- Single event ingest
- Batch event ingest

Security model:

- The customer network only needs outbound HTTPS/443 to SecuRI.
- The agent authenticates with a token in either:
  - Authorization: Bearer <token>
  - X-SecuRI-Agent-Token: <token>
- The token is read from SECURI_AGENT_INGEST_TOKEN, falling back to
  SECURI_WEBHOOK_SECRET for compatibility.
"""

from __future__ import annotations

from datetime import datetime
import hmac
import json
import os
from typing import Any


SEVERITY_RISK = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "info": 10,
    "informational": 10,
}


DEFAULT_AGENT_CONFIG = {
    "version": "2026.07-mvp",
    "batch_size": 100,
    "flush_interval_seconds": 30,
    "heartbeat_interval_seconds": 60,
    "transport": "https_outbound_only",
    "enabled_sources": [
        "file",
        "syslog",
        "windows_eventlog_future",
    ],
}


def _expected_agent_token() -> str | None:
    return os.getenv("SECURI_AGENT_INGEST_TOKEN") or os.getenv("SECURI_WEBHOOK_SECRET")


def _extract_agent_token(request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    return request.headers.get("X-SecuRI-Agent-Token", "").strip()


def _require_agent_token(main_module, request) -> None:
    expected = _expected_agent_token()
    if not expected:
        raise main_module.HTTPException(
            status_code=503,
            detail="Agent ingest token is not configured",
        )

    provided = _extract_agent_token(request)
    if not provided or not hmac.compare_digest(provided, expected):
        raise main_module.HTTPException(
            status_code=401,
            detail="Invalid agent token",
        )


def _severity_to_risk(severity: Any) -> int:
    if severity is None:
        return 35

    return SEVERITY_RISK.get(str(severity).strip().lower(), 35)


def _event_title(event: dict[str, Any], fallback: str) -> str:
    for key in ["event_name", "title", "message", "source_name"]:
        value = event.get(key)
        if value:
            text = str(value).strip()
            return text[:255] if text else fallback

    return fallback


def _normalize_event(event: dict[str, Any], agent_id: str, company_id: int) -> dict[str, Any]:
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "company_id": company_id,
        "agent_id": agent_id,
        "source_type": event.get("source_type") or "onprem_agent",
        "source_name": event.get("source_name") or agent_id,
        "event_time": event.get("event_time") or now,
        "severity": event.get("severity") or "medium",
        "event_name": event.get("event_name") or event.get("title") or "On-prem event",
        "host": event.get("host") or event.get("hostname"),
        "user": event.get("user") or event.get("username"),
        "source_ip": event.get("source_ip") or event.get("src_ip"),
        "destination_ip": event.get("destination_ip") or event.get("dst_ip"),
        "raw_event": event.get("raw_event", event),
        "received_at": now,
    }


def _build_report_payload(events: list[dict[str, Any]], agent_id: str, source_type: str) -> dict[str, Any]:
    risk_score = max((_severity_to_risk(event.get("severity")) for event in events), default=0)
    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}

    for event in events:
        severity = str(event.get("severity") or "medium").lower()
        source = str(event.get("source_type") or source_type or "onprem_agent").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1

    return {
        "source": "securi_onprem_agent",
        "agent_id": agent_id,
        "source_type": source_type,
        "events_count": len(events),
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "source_counts": source_counts,
        "events": events,
        "recommendations": [
            "Review high and critical on-prem events first.",
            "Correlate user, host, source IP and timestamps before containment.",
            "Create a security case when repeated or high-risk activity is detected.",
        ],
    }


def _get_company_or_404(main_module, db, company_id: int):
    company = db.query(main_module.Company).filter(main_module.Company.id == company_id).first()

    if not company:
        raise main_module.HTTPException(status_code=404, detail="Company not found")

    if not company.is_active:
        raise main_module.HTTPException(status_code=403, detail="Company is inactive")

    return company


def _validate_company_subscription(main_module, db, company_id: int):
    company, plan_name, plan = main_module.get_company_subscription(db, company_id)

    if company.id != 1 and int(plan.get("max_integrations") or 0) <= 0:
        raise main_module.HTTPException(
            status_code=403,
            detail=f"On-prem integrations are not available for plan '{plan_name}'",
        )

    return company, plan_name, plan


def _create_ingest_report(main_module, db, company_id: int, agent_id: str, source_type: str, events: list[dict[str, Any]]):
    report_payload = _build_report_payload(events, agent_id=agent_id, source_type=source_type)
    title = f"On-Prem Agent Ingest - {agent_id} - {len(events)} event(s)"

    report = main_module.AnalysisReport(
        company_id=company_id,
        title=title[:255],
        risk_score=report_payload["risk_score"],
        raw_input=json.dumps(events, ensure_ascii=False),
        result_json=json.dumps(report_payload, ensure_ascii=False),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return report, report_payload


def _audit_agent_action(main_module, db, request, company_id: int, action: str, details: dict[str, Any]) -> None:
    xff = request.headers.get("x-forwarded-for", "")
    ip_address = xff.split(",")[0].strip() if xff else getattr(request.client, "host", None)

    audit = main_module.AuditLog(
        company_id=company_id,
        user_id=None,
        action=action,
        resource_type="onprem_agent",
        resource_id=str(details.get("agent_id") or "unknown"),
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent"),
        details=json.dumps(details, ensure_ascii=False),
    )

    db.add(audit)
    db.commit()


def register_onprem_agent_routes(main_module) -> None:
    """Register on-prem agent routes on the existing FastAPI app."""
    app = getattr(main_module, "app", None)
    if app is None:
        return

    if getattr(app.state, "onprem_agent_routes_registered", False):
        return

    app.state.onprem_agent_routes_registered = True

    @app.post("/api/agents/heartbeat")
    def agent_heartbeat(
        request: main_module.Request,
        payload: dict = main_module.Body(...),
        db=main_module.Depends(main_module.get_db),
    ):
        _require_agent_token(main_module, request)

        company_id = int(payload.get("company_id") or 0)
        agent_id = (payload.get("agent_id") or "").strip()

        if not company_id or not agent_id:
            raise main_module.HTTPException(status_code=400, detail="company_id and agent_id are required")

        company = _get_company_or_404(main_module, db, company_id)

        _audit_agent_action(
            main_module,
            db,
            request,
            company_id=company.id,
            action="ONPREM_AGENT_HEARTBEAT",
            details={
                "agent_id": agent_id,
                "status": payload.get("status") or "online",
                "hostname": payload.get("hostname"),
                "version": payload.get("version"),
            },
        )

        return {
            "accepted": True,
            "company_id": company.id,
            "agent_id": agent_id,
            "server_time": datetime.utcnow().isoformat() + "Z",
        }

    @app.get("/api/agents/config")
    def agent_config(
        request: main_module.Request,
        company_id: int,
        agent_id: str,
        db=main_module.Depends(main_module.get_db),
    ):
        _require_agent_token(main_module, request)
        _validate_company_subscription(main_module, db, company_id)

        config = dict(DEFAULT_AGENT_CONFIG)
        config["company_id"] = company_id
        config["agent_id"] = agent_id

        return config

    @app.post("/api/ingest/events")
    def ingest_event(
        request: main_module.Request,
        payload: dict = main_module.Body(...),
        db=main_module.Depends(main_module.get_db),
    ):
        _require_agent_token(main_module, request)

        company_id = int(payload.get("company_id") or 0)
        agent_id = (payload.get("agent_id") or "").strip()

        if not company_id or not agent_id:
            raise main_module.HTTPException(status_code=400, detail="company_id and agent_id are required")

        _validate_company_subscription(main_module, db, company_id)

        event = _normalize_event(payload, agent_id=agent_id, company_id=company_id)
        report, report_payload = _create_ingest_report(
            main_module,
            db,
            company_id=company_id,
            agent_id=agent_id,
            source_type=event["source_type"],
            events=[event],
        )

        _audit_agent_action(
            main_module,
            db,
            request,
            company_id=company_id,
            action="ONPREM_AGENT_EVENT_INGEST",
            details={
                "agent_id": agent_id,
                "events_count": 1,
                "report_id": report.id,
                "risk_score": report_payload["risk_score"],
            },
        )

        return {
            "accepted": True,
            "events_count": 1,
            "report_id": report.id,
            "risk_score": report.risk_score,
        }

    @app.post("/api/ingest/batch")
    def ingest_batch(
        request: main_module.Request,
        payload: dict = main_module.Body(...),
        db=main_module.Depends(main_module.get_db),
    ):
        _require_agent_token(main_module, request)

        company_id = int(payload.get("company_id") or 0)
        agent_id = (payload.get("agent_id") or "").strip()
        source_type = (payload.get("source_type") or "onprem_agent").strip()
        raw_events = payload.get("events") or []

        if not company_id or not agent_id:
            raise main_module.HTTPException(status_code=400, detail="company_id and agent_id are required")

        if not isinstance(raw_events, list) or not raw_events:
            raise main_module.HTTPException(status_code=400, detail="events must be a non-empty list")

        if len(raw_events) > 500:
            raise main_module.HTTPException(status_code=413, detail="Batch exceeds 500 events")

        _validate_company_subscription(main_module, db, company_id)

        normalized_events = [
            _normalize_event(event if isinstance(event, dict) else {"raw_event": event}, agent_id=agent_id, company_id=company_id)
            for event in raw_events
        ]

        report, report_payload = _create_ingest_report(
            main_module,
            db,
            company_id=company_id,
            agent_id=agent_id,
            source_type=source_type,
            events=normalized_events,
        )

        _audit_agent_action(
            main_module,
            db,
            request,
            company_id=company_id,
            action="ONPREM_AGENT_BATCH_INGEST",
            details={
                "agent_id": agent_id,
                "source_type": source_type,
                "events_count": len(normalized_events),
                "report_id": report.id,
                "risk_score": report_payload["risk_score"],
            },
        )

        return {
            "accepted": True,
            "events_count": len(normalized_events),
            "report_id": report.id,
            "risk_score": report.risk_score,
        }
