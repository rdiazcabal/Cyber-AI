"""Structured report workflow patch for SecuRI.

Adds safe report-focused routes without touching Dockerfile, GZip or frontend
source files. The routes are registered before the legacy report routes so PDF
links with token query parameters work from a new tab.
"""

from __future__ import annotations

import json
from collections import Counter
from io import BytesIO
from textwrap import wrap
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from jose import JWTError, jwt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def _safe_json_loads(value: Any, fallback: Any):
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _event_field(event: dict, *names: str, default=None):
    for name in names:
        if isinstance(event, dict) and event.get(name) not in (None, ""):
            return event.get(name)
    return default


def _normalize_event_list(raw_input: dict, result: dict) -> list[dict]:
    events = []

    if isinstance(raw_input, dict):
        events = raw_input.get("events") or []
    elif isinstance(raw_input, list):
        events = raw_input

    normalized = result.get("normalized_events") or []

    if normalized:
        return normalized

    if isinstance(events, list):
        return [e for e in events if isinstance(e, dict)]

    return []


def _severity_from_number(value) -> str:
    try:
        number = float(value or 0)
    except Exception:
        number = 0

    if number >= 9:
        return "Critical"
    if number >= 7:
        return "High"
    if number >= 4:
        return "Medium"
    return "Low"


def _risk_label(score: int) -> str:
    try:
        score = int(score or 0)
    except Exception:
        score = 0

    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _top_values(values: list, limit: int = 5) -> list[dict]:
    clean = [str(v) for v in values if v not in (None, "", [], {})]
    return [{"value": k, "count": v} for k, v in Counter(clean).most_common(limit)]


def _extract_ioc_count(result: dict) -> int:
    iocs = result.get("iocs") or {}
    if not isinstance(iocs, dict):
        return 0
    total = 0
    for key in ["ips", "domains", "urls", "hashes"]:
        total += len(_as_list(iocs.get(key)))
    return total


def _build_findings(events: list[dict], result: dict) -> list[str]:
    findings = []
    detections = _as_list(result.get("detections"))
    patterns = _as_list(result.get("patterns_detected"))
    anomalies = result.get("anomaly_detection") or {}
    mitre = result.get("mitre_coverage") or {}

    if detections:
        for detection in detections[:6]:
            if isinstance(detection, dict):
                name = detection.get("name") or detection.get("title") or detection.get("type") or "Detección"
                severity = detection.get("severity") or detection.get("risk") or "N/A"
                findings.append(f"Detección: {name} · Severidad: {severity}")
            else:
                findings.append(f"Detección: {detection}")

    if patterns:
        for pattern in patterns[:5]:
            if isinstance(pattern, dict):
                title = pattern.get("name") or pattern.get("title") or pattern.get("pattern") or "Patrón detectado"
                findings.append(f"Patrón: {title}")
            else:
                findings.append(f"Patrón: {pattern}")

    if isinstance(anomalies, dict):
        anomaly_items = anomalies.get("anomalies") or anomalies.get("items") or []
        if anomaly_items:
            findings.append(f"Anomalías detectadas: {len(anomaly_items)} evento(s) requieren revisión.")

    if isinstance(mitre, dict):
        techniques = mitre.get("techniques") or mitre.get("detected_techniques") or []
        if techniques:
            findings.append(f"Cobertura MITRE relacionada: {len(techniques)} técnica(s) identificadas.")

    if not findings and events:
        findings.append("No se detectaron reglas críticas automáticas; se recomienda validar actividad, identidad, recurso y origen contra logs de control.")

    if not findings:
        findings.append("No hay hallazgos suficientes en el reporte para generar conclusiones técnicas detalladas.")

    return findings[:10]


def _build_recommendations(score: int, severity_counts: dict, iocs_count: int) -> list[str]:
    recommendations = []
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)

    if score >= 70 or critical or high:
        recommendations.extend([
            "Abrir o mantener caso SOC con responsable, evidencia, alcance e hipótesis de ataque.",
            "Correlacionar los eventos con CloudTrail, autenticación, red, EDR, DNS, WAF/proxy y cambios de configuración.",
            "Validar si las identidades, recursos o direcciones IP observadas corresponden a actividad autorizada.",
            "Aplicar contención temporal sobre cuentas, accesos, reglas o recursos afectados cuando exista evidencia de abuso.",
        ])
    else:
        recommendations.extend([
            "Mantener monitoreo y correlacionar con eventos recientes antes de cerrar el hallazgo.",
            "Confirmar que la actividad corresponde a operación esperada y documentar la evidencia de cierre.",
            "Ajustar reglas o umbrales si el evento se repite con bajo riesgo operacional.",
        ])

    if iocs_count:
        recommendations.append("Revisar los IOC observados contra fuentes internas y externas antes de bloquear permanentemente.")

    return recommendations


def _build_rich_summary(report, raw_input: dict, result: dict) -> dict:
    events = _normalize_event_list(raw_input, result)
    risk_score = int(report.risk_score or result.get("risk_score") or 0)
    risk_label = _risk_label(risk_score)

    severities = []
    services = []
    users = []
    resources = []
    actions = []
    source_ips = []

    for event in events:
        sev = _event_field(event, "severity", "risk", "level", default=0)
        severities.append(_severity_from_number(sev))
        services.append(_event_field(event, "service", "eventSource", "provider", default=None))
        users.append(_event_field(event, "user", "username", "userIdentity", "principal", default=None))
        resources.append(_event_field(event, "resource", "resource_id", "resourceName", "bucket", default=None))
        actions.append(_event_field(event, "eventName", "action", "operation", default=None))
        source_ips.append(_event_field(event, "sourceIPAddress", "source_ip", "ip", "remoteIp", default=None))

    severity_counts = dict(Counter(severities))
    top_services = _top_values(services)
    top_users = _top_values(users)
    top_resources = _top_values(resources)
    top_actions = _top_values(actions)
    top_source_ips = _top_values(source_ips)
    ioc_count = _extract_ioc_count(result)
    detections_count = len(_as_list(result.get("detections")))
    patterns_count = len(_as_list(result.get("patterns_detected")))

    primary_service = top_services[0]["value"] if top_services else "servicios no clasificados"
    primary_user = top_users[0]["value"] if top_users else "usuarios no identificados"
    primary_action = top_actions[0]["value"] if top_actions else "acciones no clasificadas"

    executive_summary = (
        f"Se analizaron {len(events)} evento(s) del reporte #{report.id} con puntaje de riesgo {risk_score} ({risk_label}). "
        f"La actividad se concentra principalmente en {primary_service}, con participación de {primary_user} y acciones como {primary_action}. "
        f"Se identificaron {patterns_count} patrón(es), {detections_count} detección(es) y {ioc_count} IOC(s). "
        "El análisis debe enfocarse en validar identidad, recurso afectado, origen de conexión, acción ejecutada y evidencia de recurrencia antes de cerrar o escalar el caso."
    )

    findings = _build_findings(events, result)
    recommendations = _build_recommendations(risk_score, severity_counts, ioc_count)

    return {
        "executive_summary": executive_summary,
        "risk_label": risk_label,
        "severity_counts": severity_counts,
        "total_events": len(events),
        "ioc_count": ioc_count,
        "detections_count": detections_count,
        "patterns_count": patterns_count,
        "top_services": top_services,
        "top_users": top_users,
        "top_resources": top_resources,
        "top_actions": top_actions,
        "top_source_ips": top_source_ips,
        "key_findings": findings,
        "recommendations": recommendations,
    }


def _structured_payload(report) -> dict:
    raw_input = _safe_json_loads(report.raw_input, {})
    result = _safe_json_loads(report.result_json, {})
    events = _normalize_event_list(raw_input, result)
    summary = _build_rich_summary(report, raw_input if isinstance(raw_input, dict) else {"events": events}, result)

    return {
        "id": report.id,
        "title": report.title,
        "risk_score": report.risk_score,
        "created_at": str(report.created_at) if report.created_at else None,
        "summary": summary,
        "events": events,
        "result": result,
        "raw_input": raw_input,
        "monitoring_payload": {
            "title": report.title,
            "events": events,
        },
    }


def _extract_token(request: Request) -> str | None:
    token = request.query_params.get("token")
    if token:
        return token.strip()

    auth_header = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    return None


def _current_user_from_request(request: Request, db, main_module):
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        from app.auth import SECRET_KEY, ALGORITHM

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_session_version = payload.get("session_version")

        if not username or token_session_version is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(main_module.User).filter(main_module.User.username == username).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User is inactive or not found")

        if int(token_session_version) != int(user.session_version or 0):
            raise HTTPException(status_code=401, detail="Session expired")

        return user
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _report_for_user(report_id: int, user, db, main_module):
    query = db.query(main_module.AnalysisReport).filter(main_module.AnalysisReport.id == report_id)

    is_master = (
        user is not None
        and user.role == "super_admin"
        and int(user.company_id or 0) == 1
    )

    if not is_master:
        query = query.filter(main_module.AnalysisReport.company_id == user.company_id)

    report = query.first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


def _write_pdf_line(pdf, text, x, y, font="Helvetica", size=9, max_width_chars=100):
    pdf.setFont(font, size)
    for line in wrap(str(text), width=max_width_chars) or [""]:
        pdf.drawString(x, y, line[:max_width_chars])
        y -= size + 4
    return y


def _structured_pdf(report) -> BytesIO:
    payload = _structured_payload(report)
    summary = payload["summary"]
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 48

    def ensure_space(min_y=80):
        nonlocal y
        if y < min_y:
            pdf.showPage()
            y = height - 48

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(48, y, "SecuRI SOC Report")
    y -= 22
    pdf.setFont("Helvetica", 9)
    pdf.drawString(48, y, f"Report #{payload['id']} · {payload['title']} · Risk {payload['risk_score']} ({summary['risk_label']})")
    y -= 28

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Resumen Ejecutivo")
    y -= 18
    y = _write_pdf_line(pdf, summary["executive_summary"], 48, y, size=9, max_width_chars=105)
    y -= 8

    ensure_space()
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Indicadores principales")
    y -= 18
    metrics = [
        f"Eventos analizados: {summary['total_events']}",
        f"Patrones detectados: {summary['patterns_count']}",
        f"Detecciones: {summary['detections_count']}",
        f"IOCs: {summary['ioc_count']}",
        f"Severidades: {summary['severity_counts']}",
    ]
    for metric in metrics:
        ensure_space()
        y = _write_pdf_line(pdf, f"- {metric}", 56, y, size=9, max_width_chars=100)

    y -= 8
    ensure_space()
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Hallazgos clave")
    y -= 18
    for finding in summary["key_findings"]:
        ensure_space()
        y = _write_pdf_line(pdf, f"- {finding}", 56, y, size=9, max_width_chars=100)

    y -= 8
    ensure_space()
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Recomendaciones")
    y -= 18
    for rec in summary["recommendations"]:
        ensure_space()
        y = _write_pdf_line(pdf, f"- {rec}", 56, y, size=9, max_width_chars=100)

    y -= 8
    ensure_space()
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Eventos principales")
    y -= 18
    for idx, event in enumerate(payload["events"][:25], 1):
        ensure_space()
        service = _event_field(event, "service", "eventSource", "provider", default="N/A")
        action = _event_field(event, "eventName", "action", "operation", default="N/A")
        user = _event_field(event, "user", "username", "principal", default="N/A")
        sev = _event_field(event, "severity", default="N/A")
        y = _write_pdf_line(pdf, f"{idx}. {service} · {action} · User: {user} · Severity: {sev}", 56, y, size=8, max_width_chars=115)

    pdf.save()
    buffer.seek(0)
    return buffer


def _register_priority_route(app, path: str, endpoint, methods: list[str], name: str):
    filtered = []
    for route in app.router.routes:
        route_path = getattr(route, "path", None)
        route_methods = getattr(route, "methods", set()) or set()
        if route_path == path and set(methods).intersection(route_methods) and getattr(route, "name", "") == name:
            continue
        filtered.append(route)
    app.router.routes = filtered
    app.router.routes.insert(0, APIRoute(path=path, endpoint=endpoint, methods=methods, name=name))


def install_report_workflow_patch(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    if getattr(app.state, "securi_report_workflow_patch_installed", False):
        return

    app.state.securi_report_workflow_patch_installed = True

    def list_reports_structured(request: Request, db=Depends(main_module.get_db)):
        user = _current_user_from_request(request, db, main_module)
        query = db.query(main_module.AnalysisReport)
        is_master = user.role == "super_admin" and int(user.company_id or 0) == 1
        if not is_master:
            query = query.filter(main_module.AnalysisReport.company_id == user.company_id)
        reports = query.order_by(main_module.AnalysisReport.created_at.desc()).all()

        items = []
        for report in reports:
            structured = _structured_payload(report)
            summary = structured["summary"]
            case = db.query(main_module.SecurityCase).filter(main_module.SecurityCase.report_id == report.id).first()
            company = db.query(main_module.Company).filter(main_module.Company.id == report.company_id).first() if report.company_id else None
            items.append({
                "company_id": report.company_id,
                "company_name": company.name if company else None,
                "id": report.id,
                "title": report.title,
                "risk_score": report.risk_score,
                "severity": summary["risk_label"],
                "summary": summary["executive_summary"],
                "ioc_count": summary["ioc_count"],
                "case_id": case.id if case else None,
                "case_status": case.status if case else None,
                "created_at": report.created_at,
            })
        return items

    def get_report_structured(report_id: int, request: Request, db=Depends(main_module.get_db)):
        user = _current_user_from_request(request, db, main_module)
        report = _report_for_user(report_id, user, db, main_module)
        return _structured_payload(report)

    def report_monitoring_payload(report_id: int, request: Request, db=Depends(main_module.get_db)):
        user = _current_user_from_request(request, db, main_module)
        report = _report_for_user(report_id, user, db, main_module)
        payload = _structured_payload(report)
        return {
            "report_id": report.id,
            "title": report.title,
            "events": payload["monitoring_payload"]["events"],
            "result": payload["result"],
            "summary": payload["summary"],
        }

    def export_report_pdf_token(report_id: int, request: Request, db=Depends(main_module.get_db)):
        user = _current_user_from_request(request, db, main_module)
        report = _report_for_user(report_id, user, db, main_module)

        settings = main_module.get_or_create_company_settings(db=db, company_id=report.company_id)
        if not settings.allow_pdf_export:
            raise HTTPException(status_code=403, detail="PDF export is disabled for this company")

        main_module.audit_action(
            db=db,
            current_user=user,
            action="DOWNLOAD_PDF",
            resource_type="analysis_report",
            resource_id=report.id,
            details={
                "title": report.title,
                "risk_score": report.risk_score,
                "company_id": report.company_id,
                "token_query_supported": True,
                "structured_pdf": True,
            },
        )

        pdf_buffer = _structured_pdf(report)
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=securi-report-{report.id}.pdf"},
        )

    _register_priority_route(app, "/reports", list_reports_structured, ["GET"], "securi_reports_structured_list")
    _register_priority_route(app, "/reports/{report_id}/structured", get_report_structured, ["GET"], "securi_report_structured")
    _register_priority_route(app, "/reports/{report_id}/monitoring-payload", report_monitoring_payload, ["GET"], "securi_report_monitoring_payload")
    _register_priority_route(app, "/reports/{report_id}/pdf", export_report_pdf_token, ["GET"], "securi_report_pdf_token")
