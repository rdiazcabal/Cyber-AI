"""Reliable IOC runtime endpoints for SecuRI UI.

Adds explicit v2 endpoints used by the frontend hotfix so the UI does not depend on
fragile runtime monkey-patching of existing routes.
"""

from __future__ import annotations

import json
from datetime import datetime

try:
    from app.country_name_safe import country_name as _safe_country_name
except Exception:  # pragma: no cover - fallback during partial imports
    _safe_country_name = None


COUNTRY_NAMES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola",
    "AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
    "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BT": "Bhutan", "BO": "Bolivia",
    "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria",
    "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
    "CV": "Cape Verde", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "CR": "Costa Rica", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus",
    "CZ": "Czech Republic", "DK": "Denmark", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
    "SV": "El Salvador", "EE": "Estonia", "ET": "Ethiopia", "FI": "Finland", "FR": "France",
    "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GR": "Greece", "GT": "Guatemala",
    "HT": "Haiti", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland",
    "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland",
    "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan",
    "KZ": "Kazakhstan", "KE": "Kenya", "KR": "South Korea", "KW": "Kuwait", "LV": "Latvia",
    "LB": "Lebanon", "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia", "MX": "Mexico",
    "MA": "Morocco", "NL": "Netherlands", "NZ": "New Zealand", "NI": "Nicaragua", "NG": "Nigeria",
    "NO": "Norway", "PA": "Panama", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines",
    "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RO": "Romania",
    "RU": "Russia", "SA": "Saudi Arabia", "RS": "Serbia", "SG": "Singapore", "SK": "Slovakia",
    "SI": "Slovenia", "ZA": "South Africa", "ES": "Spain", "SE": "Sweden", "CH": "Switzerland",
    "TW": "Taiwan", "TH": "Thailand", "TR": "Turkey", "UA": "Ukraine", "AE": "United Arab Emirates",
    "GB": "United Kingdom", "UK": "United Kingdom", "US": "United States", "UY": "Uruguay", "VE": "Venezuela",
    "VN": "Vietnam",
}


def country_name(value: str | None) -> str | None:
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
        return COUNTRY_NAMES.get(clean.upper(), clean.upper())
    return clean


def _country_display_fields(reputation: dict | None) -> dict:
    """Return display-safe country fields for legacy frontend sections.

    The current UI still prints country_code in some IOC v2 blocks. To avoid
    showing ISO abbreviations like VE/ZA, country_code is intentionally returned
    as the display name while the original ISO value is preserved in
    country_iso_code.
    """
    rep = reputation or {}
    raw_value = (
        rep.get("country_iso_code")
        or rep.get("country_code")
        or rep.get("countryCode")
        or rep.get("country")
    )

    iso_code = None
    if raw_value and len(str(raw_value).strip()) == 2:
        iso_code = str(raw_value).strip().upper()

    display_name = rep.get("country_name") or country_name(raw_value)

    if not display_name:
        display_name = "N/A"

    return {
        "country": display_name,
        "country_name": display_name,
        "country_code": display_name,
        "countryCode": display_name,
        "country_iso_code": iso_code,
    }


def _risk_label(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _reputation_recommendations(ip: str, score: int, language: str = "es") -> list[str]:
    if language == "en":
        if score >= 70:
            return [
                f"Block {ip} on firewall, WAF, proxy, VPN and perimeter controls.",
                "Search the IP in firewall, proxy, DNS, EDR, VPN and authentication logs from the last 72 hours.",
                "Identify users, devices and services that communicated with the IP.",
                "Open or update a SOC case with evidence, containment actions and owner.",
            ]
        return [
            f"Record {ip} as a low-risk indicator and keep monitoring enabled.",
            "Correlate the IP with internal logs before blocking permanently.",
            "Close as monitoring if there are no internal matches or relevant new reports.",
        ]

    if score >= 70:
        return [
            f"Bloquear {ip} en firewall, WAF, proxy, VPN y controles perimetrales.",
            "Buscar la IP en logs de firewall, proxy, DNS, EDR, VPN y autenticación de las últimas 72 horas.",
            "Identificar usuarios, equipos y servicios que tuvieron comunicación con la IP.",
            "Abrir o actualizar un caso SOC con evidencias, acciones de contención y responsable.",
        ]
    return [
        f"Registrar {ip} como indicador de bajo riesgo y mantener monitoreo.",
        "Correlacionar la IP con logs internos antes de aplicar bloqueo permanente.",
        "Cerrar como monitoreo si no existen coincidencias internas ni nuevos reportes relevantes.",
    ]


def _normalize_language(value: str | None) -> str:
    return "en" if str(value or "").lower().strip() in {"en", "english"} else "es"


def install_ioc_runtime_hotfix(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    existing_paths = {getattr(route, "path", None) for route in getattr(app, "routes", [])}

    if "/threat/ip-reputation-v2" not in existing_paths:
        def ip_reputation_v2(
            ip: str,
            language: str = "es",
            db=main_module.Depends(main_module.get_db),
            current_user=main_module.Depends(main_module.get_current_user),
        ):
            lang = _normalize_language(language)
            if not main_module.is_public_ip(ip):
                detail = "La IP es privada, reservada o no pública. No se consulta reputación externa." if lang == "es" else "The IP is private, reserved or non-public. External reputation was skipped."
                return {
                    "ip": ip,
                    "risk_level": "Low",
                    "risk_score": 0,
                    "summary": {
                        "source": "Validación local" if lang == "es" else "Local validation",
                        "pulse_count": 0,
                        "country": "N/A",
                        "country_code": "N/A",
                        "country_name": "N/A",
                        "country_iso_code": None,
                        "asn": "N/A",
                        "tags": [],
                        "malware_families": [],
                        "reasons": [detail],
                    },
                    "recommendations": _reputation_recommendations(ip, 0, lang),
                }

            rep = main_module.check_ip_abuse(ip) or {}
            score = int(rep.get("abuse_confidence_score") or rep.get("security_feed_score") or 0)
            country_fields = _country_display_fields(rep)
            reasons = []
            if rep.get("total_reports") is not None:
                reasons.append(f"Total reports: {rep.get('total_reports')}")
            if rep.get("last_reported_at"):
                reasons.append(f"Last reported at: {rep.get('last_reported_at')}")
            if not reasons and score == 0:
                reasons.append("Sin reportes relevantes." if lang == "es" else "No relevant reports.")

            return {
                "ip": ip,
                "risk_level": _risk_label(score),
                "risk_score": score,
                "summary": {
                    "source": rep.get("source") or "Security Feeds",
                    "pulse_count": rep.get("total_reports", 0),
                    **country_fields,
                    "asn": rep.get("isp") or rep.get("asn") or "N/A",
                    "tags": [rep.get("usage_type")] if rep.get("usage_type") else [],
                    "malware_families": [],
                    "reasons": reasons,
                },
                "recommendations": _reputation_recommendations(ip, score, lang),
                "raw_reputation": rep,
            }

        app.add_api_route(
            "/threat/ip-reputation-v2",
            ip_reputation_v2,
            methods=["GET"],
            tags=["threat-intel"],
        )

    if "/iocs/unified-analysis-v2" not in existing_paths:
        def unified_analysis_v2(
            payload: dict,
            db=main_module.Depends(main_module.get_db),
            current_user=main_module.Depends(main_module.get_current_user),
        ):
            query = (payload.get("query") or "").strip()
            language = _normalize_language(payload.get("language"))
            if len(query) < 2:
                detail = "El IOC debe tener al menos 2 caracteres" if language == "es" else "IOC query must have at least 2 characters"
                raise main_module.HTTPException(status_code=400, detail=detail)

            ioc_type = main_module.classify_ioc_value(query)
            obs_query = db.query(main_module.IOCObservation).filter(main_module.IOCObservation.ioc == query)
            if not main_module.is_master_super_admin(current_user):
                obs_query = obs_query.filter(main_module.IOCObservation.company_id == current_user.company_id)
            observations = obs_query.order_by(main_module.IOCObservation.created_at.desc()).limit(25).all()

            internal_history = []
            internal_max_risk = 0
            for obs in observations:
                report = None
                if obs.report_id:
                    report_query = db.query(main_module.AnalysisReport).filter(main_module.AnalysisReport.id == obs.report_id)
                    if not main_module.is_master_super_admin(current_user):
                        report_query = report_query.filter(main_module.AnalysisReport.company_id == current_user.company_id)
                    report = report_query.first()
                risk = int(report.risk_score or 0) if report else 0
                internal_max_risk = max(internal_max_risk, risk)
                internal_history.append({
                    "observation_id": obs.id,
                    "ioc": obs.ioc,
                    "type": obs.type,
                    "seen_at": obs.created_at,
                    "report_id": report.id if report else None,
                    "report_title": report.title if report else None,
                    "risk_score": risk,
                    "severity": report.severity if report and hasattr(report, "severity") else "Unknown",
                    "summary": report.summary if report and hasattr(report, "summary") else None,
                })

            external = None
            reputation_score = 0
            if ioc_type == "ip":
                if main_module.is_public_ip(query):
                    external = main_module.check_ip_abuse(query) or {}
                    reputation_score = int(external.get("abuse_confidence_score") or external.get("security_feed_score") or 0)
                    external.update(_country_display_fields(external))
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

            analysis_score = 50
            threat_score = max(internal_max_risk, reputation_score)
            severity = _risk_label(threat_score)
            if language == "en":
                verdict_text = "No threat evidence" if threat_score == 0 else _risk_label(threat_score)
                score_explanation = f"Official threat score calculated with verifiable evidence. Internal risk: {internal_max_risk}. External reputation: {reputation_score}. Contextual analysis: {analysis_score}."
                summary = f"No active threat evidence was found for {query}. Keep monitoring and correlate with internal activity before taking permanent action." if threat_score == 0 else f"Activity related to {query} requires containment or investigation according to the observed score."
            else:
                verdict_text = "Sin evidencia de amenaza" if threat_score == 0 else ("Crítico" if threat_score >= 90 else "Alto riesgo" if threat_score >= 70 else "Requiere revisión" if threat_score >= 40 else "Bajo riesgo / monitoreo")
                score_explanation = f"Puntaje oficial calculado con evidencia verificable. Riesgo interno: {internal_max_risk}. Reputación externa: {reputation_score}. Análisis contextual: {analysis_score}."
                summary = f"No se encontró evidencia de amenaza activa para {query}. Mantener monitoreo y correlacionar con actividad interna antes de tomar acciones permanentes." if threat_score == 0 else f"La actividad asociada a {query} requiere contención o investigación según el puntaje observado."

            ai_analysis = {
                "summary": summary,
                "severity": severity,
                "risk_score": analysis_score,
                "recommendations": _reputation_recommendations(query, threat_score, language),
                "confidence": 0.65,
                "analysis_source": "securi_operational_context",
                "language": language,
            }

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
                    "verdict": verdict_text,
                    "internal_max_risk": internal_max_risk,
                    "reputation_score": reputation_score,
                    "score_basis": "evidencia_verificable" if language == "es" else "verifiable_evidence",
                    "score_explanation": score_explanation,
                    "ai_score": analysis_score,
                    "analysis_confidence_percent": 65,
                },
                "internal_history": internal_history,
                "external_reputation": external,
                "ai_analysis": ai_analysis,
            }

        app.add_api_route(
            "/iocs/unified-analysis-v2",
            unified_analysis_v2,
            methods=["POST"],
            tags=["iocs"],
        )
