"""Groq-backed IOC unified analysis route for SecuRI.

This module overrides only the JSON API route `/iocs/unified-analysis-v2`.
It does not touch frontend assets, Docker build, compression, Security Feeds,
or country normalization. Groq enriches the technical narrative only; the
official threat score remains based on verifiable evidence.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi.routing import APIRoute

try:
    from app.groq_safe_analysis import analyze_security_event_structured
except Exception:  # pragma: no cover - startup fallback
    analyze_security_event_structured = None

try:
    from app.ioc_runtime_hotfix import (
        _country_display_fields,
        _normalize_language,
        _reputation_recommendations,
        _risk_label,
    )
except Exception:  # pragma: no cover - partial import fallback
    _country_display_fields = None

    def _normalize_language(value: str | None) -> str:
        return "en" if str(value or "").lower().strip() in {"en", "english"} else "es"

    def _risk_label(score: int) -> str:
        if score >= 90:
            return "Critical"
        if score >= 70:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    def _reputation_recommendations(ioc: str, score: int, language: str = "es") -> list[str]:
        if language == "en":
            return [
                f"Correlate {ioc} with firewall, DNS, proxy, EDR and authentication logs.",
                "Open or update a SOC case when internal evidence or external reputation supports escalation.",
            ]
        return [
            f"Correlacionar {ioc} con logs de firewall, DNS, proxy, EDR y autenticación.",
            "Abrir o actualizar un caso SOC cuando la evidencia interna o reputación externa sustente escalamiento.",
        ]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.5) -> float:
    try:
        return float(value if value is not None else default)
    except Exception:
        return default


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _getattr(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def _is_master(main_module: Any, current_user: Any) -> bool:
    try:
        return bool(main_module.is_master_super_admin(current_user))
    except Exception:
        return False


def _country_fields(reputation: dict | None) -> dict:
    if _country_display_fields:
        try:
            return _country_display_fields(reputation)
        except Exception:
            pass
    rep = reputation or {}
    value = rep.get("country_name") or rep.get("country") or rep.get("country_code") or "N/A"
    return {
        "country": value,
        "country_name": value,
        "country_code": value,
        "countryCode": value,
        "country_iso_code": rep.get("country_iso_code"),
    }


def _local_summary(query: str, threat_score: int, language: str) -> str:
    if language == "en":
        if threat_score == 0:
            return (
                f"No active threat evidence was found for {query}. Keep monitoring and "
                "correlate with internal activity before taking permanent action."
            )
        return f"Activity related to {query} requires containment or investigation according to observed evidence."

    if threat_score == 0:
        return (
            f"No se encontró evidencia de amenaza activa para {query}. Mantener monitoreo y "
            "correlacionar con actividad interna antes de tomar acciones permanentes."
        )
    return f"La actividad asociada a {query} requiere contención o investigación según la evidencia observada."


def _verdict_text(threat_score: int, language: str) -> str:
    if language == "en":
        return "No threat evidence" if threat_score == 0 else _risk_label(threat_score)

    if threat_score == 0:
        return "Sin evidencia de amenaza"
    if threat_score >= 90:
        return "Crítico"
    if threat_score >= 70:
        return "Alto riesgo"
    if threat_score >= 40:
        return "Requiere revisión"
    return "Bajo riesgo / monitoreo"


def _run_groq_context(groq_payload: dict, language: str) -> tuple[dict, str, str | None]:
    """Run Groq analysis and return (analysis, source, error)."""
    if not analyze_security_event_structured:
        return {}, "local_fallback", "Groq wrapper is not available"

    try:
        result = analyze_security_event_structured(groq_payload)
    except Exception as exc:  # defensive; wrapper normally returns fallback dict
        return {}, "local_fallback", str(exc)

    if not isinstance(result, dict):
        return {}, "local_fallback", "Groq returned an invalid response type"

    error = result.get("error")
    if error:
        return result, "local_fallback", str(error)

    return result, "groq", None


def _build_groq_payload(
    query: str,
    ioc_type: str,
    language: str,
    internal_history: list[dict],
    external: dict | None,
    internal_max_risk: int,
    reputation_score: int,
) -> dict:
    return {
        "analysis_type": "ioc_unified_analysis",
        "language": language,
        "ioc": query,
        "ioc_type": ioc_type,
        "official_scoring_rule": (
            "El puntaje oficial de amenaza debe basarse únicamente en evidencia verificable: "
            "riesgo interno y reputación externa. El modelo solo debe enriquecer el análisis técnico, "
            "sin inventar evidencia y sin mencionar IA/AI al usuario."
        ),
        "internal_evidence": {
            "observation_count": len(internal_history),
            "max_internal_risk": internal_max_risk,
            "recent_observations": internal_history[:10],
        },
        "external_reputation": external or {},
        "external_reputation_score": reputation_score,
        "required_output": {
            "summary": "Resumen técnico breve, sin mencionar IA/AI.",
            "severity": "Low|Medium|High|Critical",
            "risk_score": "Número contextual 0-100. No reemplaza el puntaje oficial.",
            "evidence": "Lista de evidencia observada, sin inventar.",
            "recommendations": "Acciones resolutivas de contención, investigación y remediación.",
        },
    }


def install_ioc_groq_analysis(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    if getattr(app.state, "securi_ioc_groq_analysis_installed", False):
        return

    app.state.securi_ioc_groq_analysis_installed = True

    Depends = main_module.Depends
    get_db = main_module.get_db
    get_current_user = main_module.get_current_user

    def unified_analysis_v2_groq(
        payload: dict,
        db=Depends(get_db),
        current_user=Depends(get_current_user),
    ):
        query = (payload.get("query") or "").strip()
        language = _normalize_language(payload.get("language"))

        if len(query) < 2:
            detail = "El IOC debe tener al menos 2 caracteres" if language == "es" else "IOC query must have at least 2 characters"
            raise main_module.HTTPException(status_code=400, detail=detail)

        ioc_type = main_module.classify_ioc_value(query)

        obs_query = db.query(main_module.IOCObservation).filter(main_module.IOCObservation.ioc == query)
        if not _is_master(main_module, current_user):
            obs_query = obs_query.filter(main_module.IOCObservation.company_id == current_user.company_id)
        observations = obs_query.order_by(main_module.IOCObservation.created_at.desc()).limit(25).all()

        internal_history: list[dict] = []
        internal_max_risk = 0

        for obs in observations:
            report = None
            report_id = _getattr(obs, "report_id")
            if report_id:
                report_query = db.query(main_module.AnalysisReport).filter(main_module.AnalysisReport.id == report_id)
                if not _is_master(main_module, current_user):
                    report_query = report_query.filter(main_module.AnalysisReport.company_id == current_user.company_id)
                report = report_query.first()

            risk = _safe_int(_getattr(report, "risk_score", 0), 0) if report else 0
            internal_max_risk = max(internal_max_risk, risk)
            internal_history.append({
                "observation_id": _getattr(obs, "id"),
                "ioc": _getattr(obs, "ioc"),
                "type": _getattr(obs, "type"),
                "seen_at": str(_getattr(obs, "created_at", "")),
                "report_id": _getattr(report, "id") if report else None,
                "report_title": _getattr(report, "title") if report else None,
                "risk_score": risk,
                "severity": _getattr(report, "severity", "Unknown") if report else "Unknown",
                "summary": _getattr(report, "summary", None) if report else None,
            })

        external = None
        reputation_score = 0

        if ioc_type == "ip":
            if main_module.is_public_ip(query):
                external = main_module.check_ip_abuse(query) or {}
                reputation_score = _safe_int(
                    external.get("abuse_confidence_score") or external.get("security_feed_score"),
                    0,
                )
                external.update(_country_fields(external))
                external["available"] = True
            else:
                external = {
                    "ip": query,
                    "source": "Validación local" if language == "es" else "Local validation",
                    "available": False,
                    "country": "N/A",
                    "country_code": "N/A",
                    "country_name": "N/A",
                    "country_iso_code": None,
                    "error": "IP privada, reservada, local o no pública." if language == "es" else "Private, reserved, local or non-public IP.",
                }

        threat_score = max(internal_max_risk, reputation_score)
        severity = _risk_label(threat_score)
        recommendations = _reputation_recommendations(query, threat_score, language)

        groq_payload = _build_groq_payload(
            query=query,
            ioc_type=ioc_type,
            language=language,
            internal_history=internal_history,
            external=external,
            internal_max_risk=internal_max_risk,
            reputation_score=reputation_score,
        )
        groq_result, analysis_source, groq_error = _run_groq_context(groq_payload, language)

        contextual_score = _safe_int(groq_result.get("risk_score"), 50) if groq_result else 50
        technical_summary = (groq_result.get("summary") or "").strip() if groq_result else ""
        if not technical_summary or groq_error:
            technical_summary = _local_summary(query, threat_score, language)

        groq_recommendations = _safe_list(groq_result.get("recommendations")) if groq_result else []
        final_recommendations = groq_recommendations or recommendations

        technical_analysis = {
            "summary": technical_summary,
            "severity": groq_result.get("severity") or severity,
            "risk_score": contextual_score,
            "recommendations": final_recommendations,
            "confidence": _safe_float(groq_result.get("confidence"), 0.65) if groq_result else 0.65,
            "provider": groq_result.get("provider", "Generic") if groq_result else "Generic",
            "evidence": _safe_list(groq_result.get("evidence")) if groq_result else [],
            "mitre_techniques": _safe_list(groq_result.get("mitre_techniques")) if groq_result else [],
            "analysis_source": analysis_source,
            "model_used": groq_result.get("model_used") if groq_result else None,
            "prompt_version": groq_result.get("prompt_version", "ioc-groq-v1") if groq_result else "ioc-groq-v1",
            "language": language,
        }

        if groq_error:
            technical_analysis["groq_error"] = groq_error

        score_explanation = (
            f"Puntaje oficial calculado con evidencia verificable. Riesgo interno: {internal_max_risk}. "
            f"Reputación externa: {reputation_score}. Análisis contextual: {contextual_score}."
            if language == "es"
            else f"Official threat score calculated with verifiable evidence. Internal risk: {internal_max_risk}. "
                 f"External reputation: {reputation_score}. Contextual analysis: {contextual_score}."
        )

        return {
            "ioc": query,
            "ioc_type": ioc_type,
            "language": language,
            "verdict": {
                "ioc": query,
                "ioc_type": ioc_type,
                "unified_score": threat_score,
                "threat_score": threat_score,
                "severity": severity,
                "verdict": _verdict_text(threat_score, language),
                "internal_max_risk": internal_max_risk,
                "reputation_score": reputation_score,
                "score_basis": "evidencia_verificable" if language == "es" else "verifiable_evidence",
                "score_explanation": score_explanation,
                "contextual_score": contextual_score,
                "ai_score": contextual_score,
                "analysis_source": analysis_source,
            },
            "internal_history": internal_history,
            "external_reputation": external,
            "technical_analysis": technical_analysis,
            "ai_analysis": technical_analysis,
            "recommendations": final_recommendations,
            "metadata": {
                "groq_requested": bool(os.getenv("GROQ_API_KEY")),
                "groq_used": analysis_source == "groq",
                "analysis_source": analysis_source,
                "model_used": technical_analysis.get("model_used"),
                "groq_error": groq_error,
            },
        }

    route = APIRoute(
        path="/iocs/unified-analysis-v2",
        endpoint=unified_analysis_v2_groq,
        methods=["POST"],
        tags=["iocs"],
    )

    app.router.routes.insert(0, route)
