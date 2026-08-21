"""Bilingual threat-analysis presentation and Groq validation patch for SecuRI.

This patch improves the IOC/unified threat hunting experience without changing the
stored DB schema. It keeps Groq as the structured analysis engine, reduces repeated
AI wording in executive summaries, makes recommendations resolution-oriented, and
allows analysts to switch the IOC analysis output between Spanish and English.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import json
import os
import re
import sys
from pathlib import Path


SEVERITY_ORDER = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

SUPPORTED_LANGUAGES = {"es", "en"}


def _normalize_language(value: str | None) -> str:
    clean = (value or os.getenv("SECURI_DEFAULT_LANGUAGE") or "es").strip().lower()
    if clean in ["spanish", "español", "espanol"]:
        return "es"
    if clean in ["english", "ingles", "inglés"]:
        return "en"
    return clean if clean in SUPPORTED_LANGUAGES else "es"


def _language_from_event(event) -> str:
    if isinstance(event, dict):
        return _normalize_language(
            event.get("language")
            or event.get("lang")
            or event.get("output_language")
            or event.get("ui_language")
        )
    return _normalize_language(None)


def _safe_int(value, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def _safe_confidence(value, default: float = 0.65) -> float:
    try:
        confidence = float(value)
    except Exception:
        confidence = default

    if confidence > 1:
        confidence = confidence / 100

    return max(0.0, min(1.0, confidence))


def _classify_ioc_from_text(value: str) -> str:
    clean = (value or "").strip()

    if not clean:
        return "resource"

    try:
        import ipaddress

        ipaddress.ip_address(clean)
        return "ip"
    except Exception:
        pass

    if clean.startswith("http://") or clean.startswith("https://"):
        return "url"

    if re.fullmatch(r"[a-fA-F0-9]{32}", clean):
        return "md5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", clean):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", clean):
        return "sha256"

    if "@" in clean:
        return "user"

    if "." in clean:
        return "domain"

    return "resource"


def _resolution_recommendations(ioc: str, ioc_type: str, score: int, language: str = "es") -> list[str]:
    lang = _normalize_language(language)
    target = ioc or ("el indicador" if lang == "es" else "the indicator")
    kind = ioc_type or _classify_ioc_from_text(target)

    if lang == "en":
        if score >= 90:
            if kind == "ip":
                return [
                    f"Block IP {target} on firewall, WAF, proxy, VPN and perimeter controls.",
                    f"Search for connections to or from {target} in firewall, proxy, EDR, DNS and authentication logs from the last 72 hours.",
                    "Identify impacted assets, users and services, and isolate compromised endpoints.",
                    "Create or update a critical case with evidence, timeline, actions taken and owners.",
                    "Keep enhanced monitoring for 24 to 48 hours to confirm there are no new connection attempts.",
                ]
            if kind in ["domain", "url"]:
                return [
                    f"Block {target} in DNS, proxy, firewall and secure browsing controls.",
                    f"Search for access to {target} in proxy, DNS, browser, EDR and email logs.",
                    "Review or isolate endpoints that resolved or visited the indicator.",
                    "Remove related emails, shortcuts, downloaded files or processes when tied to phishing or malware delivery.",
                    "Create a critical case and document scope, containment and remediation.",
                ]
            return [
                f"Treat {target} as critical and block it on applicable controls.",
                "Search for the indicator in logs, endpoints, servers, email and security tools.",
                "Isolate impacted assets and preserve evidence before cleanup.",
                "Create a critical case with owners, evidence and remediation plan.",
            ]
        if score >= 70:
            return [
                f"Apply preventive blocking or watchlisting for {target} according to available controls.",
                "Review related events from the last 24 to 72 hours and confirm users, assets and applications involved.",
                "Escalate to security operations if multiple events, failed authentications, lateral movement or exfiltration signals appear.",
                "Document the finding in a high-priority case and close it only with containment evidence.",
            ]
        if score >= 40:
            return [
                f"Keep {target} under observation and correlate it with authentication, proxy, firewall and endpoint activity.",
                "Validate whether the indicator belongs to a legitimate business service before permanently allowing it.",
                "Create an investigation task and close it only when benign activity or containment is evidenced.",
            ]
        return [
            f"Record {target} as a low-risk indicator and keep the evidence for future reference.",
            "Do not block permanently without new evidence, but keep correlation enabled if it appears again in security events.",
            "Close as monitoring when there are no internal matches or relevant external signals.",
        ]

    if score >= 90:
        if kind == "ip":
            return [
                f"Bloquear la IP {target} en firewall, WAF, proxy, VPN y controles perimetrales.",
                f"Buscar conexiones hacia o desde {target} en logs de firewall, proxy, EDR, DNS y autenticación de las últimas 72 horas.",
                "Identificar equipos, usuarios y servicios que tuvieron comunicación con el indicador y aislar los activos comprometidos.",
                "Crear o actualizar un caso crítico con evidencias, línea de tiempo, acciones tomadas y responsables.",
                "Mantener monitoreo reforzado por 24 a 48 horas para confirmar que no existan nuevos intentos de conexión.",
            ]
        if kind in ["domain", "url"]:
            return [
                f"Bloquear {target} en DNS, proxy, firewall y herramientas de navegación segura.",
                f"Buscar accesos a {target} en logs de proxy, DNS, navegador, EDR y correo electrónico.",
                "Aislar o revisar los endpoints que resolvieron o visitaron el indicador.",
                "Eliminar correos, accesos directos o procesos asociados si el indicador proviene de phishing o descarga maliciosa.",
                "Crear caso crítico y documentar alcance, contención y remediación.",
            ]
        return [
            f"Tratar el indicador {target} como crítico y bloquearlo en los controles donde aplique.",
            "Buscar presencia del indicador en logs, endpoints, servidores, correo y herramientas de seguridad.",
            "Aislar activos impactados y preservar evidencia antes de ejecutar limpieza.",
            "Crear caso crítico con responsables, evidencias y plan de remediación.",
        ]
    if score >= 70:
        return [
            f"Aplicar bloqueo preventivo o lista de observación para {target} según el control disponible.",
            "Revisar eventos relacionados en las últimas 24 a 72 horas y confirmar usuarios, activos y aplicaciones involucradas.",
            "Escalar a operación de seguridad si se observan múltiples eventos, autenticaciones fallidas, movimiento lateral o exfiltración.",
            "Documentar el hallazgo en un caso de prioridad alta y cerrar con evidencia de contención.",
        ]
    if score >= 40:
        return [
            f"Mantener {target} bajo observación y correlacionar con autenticación, proxy, firewall y endpoint.",
            "Validar si el indicador pertenece a un servicio legítimo del negocio antes de permitirlo permanentemente.",
            "Crear tarea de investigación y cerrar únicamente cuando exista evidencia suficiente de benignidad o contención.",
        ]
    return [
        f"Registrar {target} como indicador de bajo riesgo y conservar evidencia para referencia futura.",
        "No bloquear de forma permanente sin nueva evidencia, pero mantener correlación si vuelve a aparecer en eventos de seguridad.",
        "Cerrar como monitoreo si no existen coincidencias internas ni señales externas relevantes.",
    ]


def _summary_from_event(event: object, severity: str, risk_score: int, language: str = "es") -> str:
    lang = _normalize_language(language)
    try:
        data = event if isinstance(event, dict) else json.loads(event)
    except Exception:
        data = {}

    ioc = data.get("ioc") or data.get("query") or data.get("sourceIPAddress") or data.get("ip")
    if not ioc:
        ioc = "el indicador analizado" if lang == "es" else "the analyzed indicator"

    if lang == "en":
        if risk_score >= 90:
            return (
                f"Critical risk was identified for {ioc}. "
                "The available evidence justifies immediate containment, scope review and security case creation."
            )
        if risk_score >= 70:
            return (
                f"High-risk activity was identified for {ioc}. "
                "Preventive containment, correlation with internal events and impacted asset validation are required."
            )
        if risk_score >= 40:
            return (
                f"Activity requiring review was identified for {ioc}. "
                "It must be correlated with internal logs before allowing or dismissing the indicator."
            )
        return (
            f"There is not enough evidence to classify {ioc} as an active threat. "
            "Keep monitoring and retain the result as operational reference."
        )

    if risk_score >= 90:
        return (
            f"Se identificó riesgo crítico asociado a {ioc}. "
            "La evidencia disponible justifica contención inmediata, revisión de alcance y apertura de caso de seguridad."
        )
    if risk_score >= 70:
        return (
            f"Se identificó actividad de alto riesgo asociada a {ioc}. "
            "Requiere contención preventiva, correlación con eventos internos y validación de activos afectados."
        )
    if risk_score >= 40:
        return (
            f"Se identificó actividad que requiere revisión para {ioc}. "
            "Debe correlacionarse con logs internos antes de permitir o descartar el indicador."
        )
    return (
        f"No se encontró evidencia suficiente para clasificar {ioc} como amenaza activa. "
        "Mantener monitoreo y conservar el resultado como referencia operacional."
    )


def analyze_security_event_structured_localized(event) -> dict:
    """Run Groq structured analysis and return operational output in the requested language."""
    language = _language_from_event(event)
    model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    language_name = "English" if language == "en" else "Spanish"

    try:
        from groq import Groq

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not configured" if language == "en" else "GROQ_API_KEY no está configurada")

        if isinstance(event, str):
            event_text = event
        else:
            event_text = json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
You are a senior SOC analyst. Analyze the event/IOC and return ONLY valid JSON.
Do not use markdown. Do not invent evidence. All visible text must be in {language_name}.
Recommendations must be concrete resolution actions, not ambiguous suggestions.
Avoid overusing the terms AI/IA in the executive summary.

INPUT:
{event_text}

EXACT JSON OUTPUT:
{{
  "provider": "AWS|Azure|GCP|Linux|Web|Firewall|OnPrem|Generic",
  "summary": "Brief executive summary in {language_name}.",
  "severity": "Low|Medium|High|Critical",
  "risk_score": 0,
  "ips": [],
  "domains": [],
  "urls": [],
  "users": [],
  "resources": [],
  "actions": [],
  "mitre_techniques": [],
  "evidence": [],
  "recommendations": [
    "Concrete containment or blocking action.",
    "Concrete investigation action.",
    "Concrete remediation or closure action."
  ],
  "confidence": 0.0,
  "model_used": "{model}",
  "prompt_version": "structured-bilingual-v3",
  "language": "{language}"
}}
"""

        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"You are a senior SOC analyst. Return ONLY valid JSON. "
                        f"Do not invent evidence. Respond in {language_name}. "
                        "Recommendations must be resolution-oriented."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=1200,
        )

        content = completion.choices[0].message.content.strip()
        if content.startswith("```"):
            content = content.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(content)

        risk_score = _safe_int(parsed.get("risk_score"), 50)
        severity = SEVERITY_ORDER.get(str(parsed.get("severity", "Medium")).lower(), "Medium")
        ioc = ""
        if isinstance(event, dict):
            ioc = event.get("ioc") or event.get("query") or ""
        ioc_type = (event.get("ioc_type") if isinstance(event, dict) else None) or _classify_ioc_from_text(ioc)

        recommendations = parsed.get("recommendations") or []
        if not recommendations:
            recommendations = _resolution_recommendations(ioc, ioc_type, risk_score, language)

        return {
            "provider": parsed.get("provider", "Generic"),
            "summary": parsed.get("summary") or _summary_from_event(event, severity, risk_score, language),
            "severity": severity,
            "risk_score": risk_score,
            "ips": parsed.get("ips", []) or [],
            "domains": parsed.get("domains", []) or [],
            "urls": parsed.get("urls", []) or [],
            "users": parsed.get("users", []) or [],
            "resources": parsed.get("resources", []) or [],
            "actions": parsed.get("actions", []) or [],
            "mitre_techniques": parsed.get("mitre_techniques", []) or [],
            "evidence": parsed.get("evidence", []) or [],
            "recommendations": recommendations,
            "confidence": _safe_confidence(parsed.get("confidence"), 0.65),
            "model_used": parsed.get("model_used", model),
            "prompt_version": parsed.get("prompt_version", "structured-bilingual-v3"),
            "analysis_source": "groq_structured",
            "language": language,
        }

    except Exception as exc:
        ioc = ""
        if isinstance(event, dict):
            ioc = event.get("ioc") or event.get("query") or event.get("sourceIPAddress") or ""
        ioc_type = (event.get("ioc_type") if isinstance(event, dict) else None) or _classify_ioc_from_text(ioc)
        risk_score = 50
        severity = "Medium"

        fallback_evidence = (
            "Structured analysis engine did not return a valid response."
            if language == "en"
            else "No se obtuvo respuesta estructurada del motor de análisis."
        )

        return {
            "provider": "Generic",
            "summary": _summary_from_event(event, severity, risk_score, language),
            "severity": severity,
            "risk_score": risk_score,
            "ips": [ioc] if ioc_type == "ip" and ioc else [],
            "domains": [ioc] if ioc_type == "domain" and ioc else [],
            "urls": [ioc] if ioc_type == "url" and ioc else [],
            "users": [],
            "resources": [],
            "actions": [],
            "mitre_techniques": [],
            "evidence": [fallback_evidence],
            "recommendations": _resolution_recommendations(ioc, ioc_type, risk_score, language),
            "confidence": 0.5,
            "model_used": model,
            "prompt_version": "structured-bilingual-v3",
            "analysis_source": "local_operational_fallback",
            "language": language,
            "error": str(exc),
        }


# Backward-compatible name used by the first draft of this patch.
analyze_security_event_structured_es = analyze_security_event_structured_localized


def build_unified_ioc_verdict_localized(
    ioc: str,
    ioc_type: str,
    internal_history: list[dict],
    external_reputation: dict | None,
    ai_result: dict,
) -> dict:
    language = _normalize_language(ai_result.get("language") if isinstance(ai_result, dict) else None)

    internal_max_risk = 0
    for item in internal_history or []:
        internal_max_risk = max(internal_max_risk, _safe_int(item.get("risk_score"), 0))

    reputation_score = 0
    if external_reputation and external_reputation.get("available"):
        reputation_score = _safe_int(
            external_reputation.get("abuse_confidence_score")
            or external_reputation.get("score")
            or 0,
            0,
        )

    analysis_score = _safe_int(ai_result.get("risk_score"), 0)
    threat_score = max(internal_max_risk, reputation_score)
    unified_score = threat_score

    if language == "en":
        if unified_score >= 90:
            verdict = "Critical"
        elif unified_score >= 70:
            verdict = "High risk"
        elif unified_score >= 40:
            verdict = "Needs review"
        elif unified_score > 0:
            verdict = "Low risk / monitor"
        else:
            verdict = "No threat evidence"
        score_basis = "verifiable_evidence"
        evidence_labels = {
            "internal": "internal_history",
            "external": "external_reputation",
            "none": "no_positive_evidence",
        }
        score_explanation = (
            f"The official score was calculated using verifiable evidence. "
            f"Maximum internal risk: {internal_max_risk}. "
            f"External reputation: {reputation_score}. "
            f"Contextual analysis: {analysis_score}. "
            "Contextual analysis supports interpretation, while the official score remains based on internal evidence and external reputation."
        )
    else:
        if unified_score >= 90:
            verdict = "Crítico"
        elif unified_score >= 70:
            verdict = "Alto riesgo"
        elif unified_score >= 40:
            verdict = "Requiere revisión"
        elif unified_score > 0:
            verdict = "Bajo riesgo / monitoreo"
        else:
            verdict = "Sin evidencia de amenaza"
        score_basis = "evidencia_verificable"
        evidence_labels = {
            "internal": "historial_interno",
            "external": "reputacion_externa",
            "none": "sin_evidencia_positiva",
        }
        score_explanation = (
            f"El puntaje oficial se calculó con evidencia verificable. "
            f"Riesgo interno máximo: {internal_max_risk}. "
            f"Reputación externa: {reputation_score}. "
            f"Análisis contextual: {analysis_score}. "
            "El análisis contextual complementa la interpretación, pero el puntaje oficial se mantiene basado en evidencia interna y reputación externa."
        )

    confidence = _safe_confidence(ai_result.get("confidence"), 0.5)
    if external_reputation and external_reputation.get("available"):
        confidence = min(1.0, confidence + 0.15)
    if internal_history:
        confidence = min(1.0, confidence + 0.15)

    evidence_sources = []
    if internal_max_risk > 0:
        evidence_sources.append(evidence_labels["internal"])
    if reputation_score > 0:
        evidence_sources.append(evidence_labels["external"])
    if not evidence_sources:
        evidence_sources.append(evidence_labels["none"])

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "unified_score": unified_score,
        "threat_score": threat_score,
        "severity": "Critical" if unified_score >= 90 else "High" if unified_score >= 70 else "Medium" if unified_score >= 40 else "Low",
        "verdict": verdict,
        "internal_max_risk": internal_max_risk,
        "reputation_score": reputation_score,
        "evidence_sources": evidence_sources,
        "score_basis": score_basis,
        "score_explanation": score_explanation,
        "ai_score": analysis_score,
        "ai_score_type": "contextual_only",
        "confidence": round(confidence, 2),
        "analysis_confidence_percent": int(round(confidence * 100)),
        "language": language,
    }


build_unified_ioc_verdict_es = build_unified_ioc_verdict_localized


def _patch_frontend_text() -> None:
    index_path = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

    try:
        html = index_path.read_text(encoding="utf-8")
    except OSError:
        return

    replacements = {
        "Interpretación AI:": "Análisis técnico:",
        "AI Score informativo": "Análisis contextual",
        "AI score informativo": "Análisis contextual",
        "El AI Score es informativo.": "El análisis contextual es informativo.",
        "La IA apoya la interpretación, pero no modifica el puntaje oficial si no existe evidencia interna o reputación externa.": "El análisis contextual complementa la interpretación; el puntaje oficial se mantiene basado en evidencia verificable.",
        "Structured AI analysis unavailable.": "No se obtuvo análisis estructurado del motor de análisis.",
        "Review recent logs for connections involving this IP.": "Revisar logs recientes de firewall, proxy, DNS, autenticación y endpoint relacionados con esta IP.",
        "Check whether this IP appears in authentication, firewall or proxy logs.": "Confirmar si la IP aparece en eventos de autenticación, firewall, proxy, VPN o EDR.",
        "Block or monitor the IP if it appears in high-risk activity.": "Bloquear la IP si tiene reputación crítica o actividad interna de alto riesgo.",
        "Correlate this IP with users, assets and timestamps before taking containment action.": "Relacionar la IP con usuarios, activos y horarios para documentar alcance y cierre del caso.",
        'fetch("/iocs/unified-analysis", {': 'fetch("/iocs/unified-analysis-localized", {',
        "body: JSON.stringify({ query })": "body: JSON.stringify({ query, language: getSecuriLanguage() })",
        'status.innerText = "Running unified IOC analysis...";': 'status.innerText = t("runningUnified");',
        'panel.innerText = "Consultando historial interno, reputación externa y análisis AI...";': 'panel.innerText = t("checkingUnified");',
        'panel.innerText = `Unified IOC analysis failed: ${data.detail || res.status}`;': 'panel.innerText = `${t("unifiedFailed")}: ${data.detail || res.status}`;',
        'status.innerText = "Unified analysis failed.";': 'status.innerText = t("unifiedFailed");',
        'status.innerText = `Unified IOC analysis completed for ${data.ioc || query}.`;': 'status.innerText = `${t("unifiedCompleted")} ${data.ioc || query}.`;',
        'panel.innerText = `Unified IOC analysis error: ${err.message}`;': 'panel.innerText = `${t("unifiedError")}: ${err.message}`;',
        'status.innerText = "Unified analysis error.";': 'status.innerText = t("unifiedError");',
        '<strong>Verdicto:</strong>': '<strong>${t("verdict")}:</strong>',
        '<strong>Resumen Ejecutivo:</strong>': '<strong>${t("executiveSummary")}:</strong>',
        '<strong>Análisis técnico:</strong>': '<strong>${t("technicalAnalysis")}:</strong>',
        '<strong>Reputación Externa:</strong>': '<strong>${t("externalReputation")}:</strong>',
        '<strong>Recomendaciones:</strong>': '<strong>${t("recommendations")}:</strong>',
        'Confianza del Análisis ${analysisConfidence}%': '${t("analysisConfidence")} ${analysisConfidence}%',
        'Puntaje de Amenaza ${threatScore}': '${t("threatScore")} ${threatScore}',
        '<strong>Tipo de IOC</strong>': '<strong>${t("iocType")}</strong>',
        '<strong>Puntaje de Amenaza</strong>': '<strong>${t("threatScore")}</strong>',
        '<strong>Riesgo Interno</strong>': '<strong>${t("internalRisk")}</strong>',
        '<strong>Reputación Externa</strong>': '<strong>${t("externalReputation")}</strong>',
        '<strong>Coincidencias Internas</strong>': '<strong>${t("internalMatches")}</strong>',
        '<strong>Análisis contextual</strong>': '<strong>${t("contextualAnalysis")}</strong>',
        '<strong>Confianza del análisis</strong>': '<strong>${t("analysisConfidence")}</strong>',
        '<strong>Base del Score</strong>': '<strong>${t("scoreBasis")}</strong>',
        'Ver Historial Interno': '${t("viewInternalHistory")}',
        'Ver Timeline': '${t("viewTimeline")}',
        'No hay recomendaciones disponibles.': '${t("noRecommendations")}',
        'No AI summary available.': '${t("noTechnicalAnalysis")}',
        'Unknown': '${t("unknown")}',
        'Needs Review': '${t("needsReview")}',
    }

    updated = html
    for old, new in replacements.items():
        updated = updated.replace(old, new)

    language_control = '''
        <div class="securi-language-switch" style="margin-top:8px;display:flex;gap:6px;align-items:center;">
          <span style="font-size:11px;color:#b8b8b8;font-weight:800;">Idioma</span>
          <select id="securiLanguageSelect" onchange="setSecuriLanguage(this.value)" style="min-height:30px;padding:4px 8px;border-radius:10px;">
            <option value="es">Español</option>
            <option value="en">English</option>
          </select>
        </div>'''

    if "securiLanguageSelect" not in updated:
        updated = updated.replace(
            "<small>SOC con Inteligencia Artificial</small>",
            "<small>SOC con Inteligencia Artificial</small>" + language_control,
        )

    language_script = r'''
    const SECURI_I18N = {
      es: {
        runningUnified: "Ejecutando análisis unificado de IOC...",
        checkingUnified: "Consultando historial interno, reputación externa y análisis técnico...",
        unifiedFailed: "El análisis unificado falló",
        unifiedCompleted: "Análisis unificado completado para",
        unifiedError: "Error en análisis unificado",
        verdict: "Veredicto",
        executiveSummary: "Resumen Ejecutivo",
        technicalAnalysis: "Análisis técnico",
        externalReputation: "Reputación Externa",
        recommendations: "Recomendaciones",
        analysisConfidence: "Confianza del análisis",
        threatScore: "Puntaje de Amenaza",
        iocType: "Tipo de IOC",
        internalRisk: "Riesgo Interno",
        internalMatches: "Coincidencias Internas",
        contextualAnalysis: "Análisis contextual",
        scoreBasis: "Base del Score",
        viewInternalHistory: "Ver Historial Interno",
        viewTimeline: "Ver Timeline",
        noRecommendations: "No hay recomendaciones disponibles.",
        noTechnicalAnalysis: "No hay análisis técnico disponible.",
        unknown: "Desconocido",
        needsReview: "Requiere revisión"
      },
      en: {
        runningUnified: "Running unified IOC analysis...",
        checkingUnified: "Checking internal history, external reputation and technical analysis...",
        unifiedFailed: "Unified analysis failed",
        unifiedCompleted: "Unified IOC analysis completed for",
        unifiedError: "Unified analysis error",
        verdict: "Verdict",
        executiveSummary: "Executive Summary",
        technicalAnalysis: "Technical Analysis",
        externalReputation: "External Reputation",
        recommendations: "Recommendations",
        analysisConfidence: "Analysis Confidence",
        threatScore: "Threat Score",
        iocType: "IOC Type",
        internalRisk: "Internal Risk",
        internalMatches: "Internal Matches",
        contextualAnalysis: "Contextual Analysis",
        scoreBasis: "Score Basis",
        viewInternalHistory: "View Internal History",
        viewTimeline: "View Timeline",
        noRecommendations: "No recommendations available.",
        noTechnicalAnalysis: "No technical analysis available.",
        unknown: "Unknown",
        needsReview: "Needs Review"
      }
    };

    function getSecuriLanguage() {
      return localStorage.getItem("securiLanguage") || "es";
    }

    function t(key) {
      const lang = getSecuriLanguage();
      return (SECURI_I18N[lang] && SECURI_I18N[lang][key]) || SECURI_I18N.es[key] || key;
    }

    function setSecuriLanguage(lang) {
      const normalized = lang === "en" ? "en" : "es";
      localStorage.setItem("securiLanguage", normalized);
      const selector = document.getElementById("securiLanguageSelect");
      if (selector) selector.value = normalized;
    }

    document.addEventListener("DOMContentLoaded", () => {
      const selector = document.getElementById("securiLanguageSelect");
      if (selector) selector.value = getSecuriLanguage();
    });
'''

    if "const SECURI_I18N" not in updated:
        updated = updated.replace("    let authToken =", language_script + "\n    let authToken =", 1)

    if updated != html:
        try:
            index_path.write_text(updated, encoding="utf-8")
        except OSError:
            return


def _add_localized_ioc_route(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    for route in getattr(app, "routes", []):
        if getattr(route, "path", None) == "/iocs/unified-analysis-localized":
            return

    def unified_ioc_analysis_localized(
        payload: dict,
        db=main_module.Depends(main_module.get_db),
        current_user=main_module.Depends(main_module.get_current_user),
    ):
        query = (payload.get("query") or "").strip()
        language = _normalize_language(payload.get("language") or payload.get("lang"))

        if len(query) < 2:
            detail = "IOC query must have at least 2 characters" if language == "en" else "El IOC debe tener al menos 2 caracteres"
            raise main_module.HTTPException(status_code=400, detail=detail)

        ioc_type = main_module.classify_ioc_value(query)
        obs_query = db.query(main_module.IOCObservation).filter(main_module.IOCObservation.ioc == query)

        if not main_module.is_master_super_admin(current_user):
            obs_query = obs_query.filter(main_module.IOCObservation.company_id == current_user.company_id)

        observations = obs_query.order_by(main_module.IOCObservation.created_at.desc()).limit(25).all()
        internal_history = []

        for obs in observations:
            report = None
            if obs.report_id:
                report_query = db.query(main_module.AnalysisReport).filter(main_module.AnalysisReport.id == obs.report_id)
                if not main_module.is_master_super_admin(current_user):
                    report_query = report_query.filter(main_module.AnalysisReport.company_id == current_user.company_id)
                report = report_query.first()

            parsed_result = {}
            if report:
                try:
                    parsed_result = json.loads(report.result_json or "{}")
                except Exception:
                    parsed_result = {}

            ai_struct = parsed_result.get("ai_structured_analysis", {}) or {}
            internal_history.append({
                "observation_id": obs.id,
                "ioc": obs.ioc,
                "type": obs.type,
                "seen_at": obs.created_at,
                "report_id": report.id if report else None,
                "report_title": report.title if report else None,
                "risk_score": report.risk_score if report else 0,
                "severity": ai_struct.get("severity", "Unknown"),
                "summary": ai_struct.get("summary"),
            })

        external_reputation = None
        if ioc_type == "ip":
            if main_module.is_public_ip(query):
                external_reputation = main_module.check_ip_abuse(query)
            else:
                external_reputation = {
                    "ip": query,
                    "source": "Local validation",
                    "available": False,
                    "error": (
                        "Private, reserved, local or non-public IP. External reputation skipped."
                        if language == "en"
                        else "IP privada, reservada, local o no pública. Se omitió reputación externa."
                    ),
                }

        analysis_input = {
            "analysis_type": "unified_ioc_analysis",
            "ioc": query,
            "ioc_type": ioc_type,
            "internal_history": internal_history,
            "external_reputation": external_reputation,
            "language": language,
            "instructions": [
                "Use only the provided evidence.",
                "Do not invent reputation, geolocation or threat actor attribution.",
                "Generate the analyst summary and recommendations in the requested language.",
                "Recommendations must be concrete resolution actions.",
            ],
        }

        ai_result = analyze_security_event_structured_localized(analysis_input)
        verdict = build_unified_ioc_verdict_localized(
            ioc=query,
            ioc_type=ioc_type,
            internal_history=internal_history,
            external_reputation=external_reputation,
            ai_result=ai_result,
        )

        main_module.audit_action(
            db=db,
            current_user=current_user,
            action="UNIFIED_IOC_ANALYSIS_LOCALIZED",
            resource_type="ioc",
            resource_id=query,
            details={
                "ioc": query,
                "ioc_type": ioc_type,
                "language": language,
                "unified_score": verdict["unified_score"],
                "severity": verdict["severity"],
                "internal_matches": len(internal_history),
                "has_external_reputation": bool(external_reputation),
            },
        )

        return {
            "ioc": query,
            "ioc_type": ioc_type,
            "language": language,
            "verdict": verdict,
            "internal_history": internal_history,
            "external_reputation": external_reputation,
            "ai_analysis": ai_result,
        }

    app.add_api_route(
        "/iocs/unified-analysis-localized",
        unified_ioc_analysis_localized,
        methods=["POST"],
        tags=["iocs"],
    )


def apply_spanish_analysis_patch(main_module) -> None:
    try:
        import app.analyzer as analyzer

        analyzer.analyze_security_event_structured = analyze_security_event_structured_localized
        main_module.analyze_security_event_structured = analyze_security_event_structured_localized
    except Exception:
        pass

    main_module.build_unified_ioc_verdict = build_unified_ioc_verdict_localized
    _add_localized_ioc_route(main_module)
    _patch_frontend_text()


class _SpanishAnalysisLoader(importlib.abc.Loader):
    def __init__(self, wrapped_loader):
        self.wrapped_loader = wrapped_loader

    def create_module(self, spec):
        if hasattr(self.wrapped_loader, "create_module"):
            return self.wrapped_loader.create_module(spec)
        return None

    def exec_module(self, module):
        self.wrapped_loader.exec_module(module)
        apply_spanish_analysis_patch(module)


class _SpanishAnalysisFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != "app.main":
            return None

        try:
            sys.meta_path.remove(self)
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        finally:
            sys.meta_path.insert(0, self)

        if spec and spec.loader and not isinstance(spec.loader, _SpanishAnalysisLoader):
            spec.loader = _SpanishAnalysisLoader(spec.loader)

        return spec


def install_spanish_analysis_patch() -> None:
    loaded_main = sys.modules.get("app.main")
    if loaded_main:
        apply_spanish_analysis_patch(loaded_main)
        return

    if not any(isinstance(finder, _SpanishAnalysisFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _SpanishAnalysisFinder())
