"""Spanish threat-analysis presentation and Groq validation patch for SecuRI.

This patch improves the IOC/unified threat hunting experience without changing the
stored DB schema. It keeps Groq as the structured analysis engine, removes user-
visible English fallback text, reduces repeated AI wording in executive summaries,
and makes recommendations resolution-oriented.
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


def _resolution_recommendations(ioc: str, ioc_type: str, score: int) -> list[str]:
    target = ioc or "el indicador"
    kind = ioc_type or _classify_ioc_from_text(target)

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


def _spanish_summary_from_event(event: object, severity: str, risk_score: int) -> str:
    try:
        data = event if isinstance(event, dict) else json.loads(event)
    except Exception:
        data = {}

    ioc = data.get("ioc") or data.get("query") or data.get("sourceIPAddress") or data.get("ip") or "el indicador analizado"
    ioc_type = data.get("ioc_type") or _classify_ioc_from_text(str(ioc))

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


def analyze_security_event_structured_es(event) -> dict:
    """Run Groq structured analysis and always return Spanish operational output."""
    model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

    try:
        from groq import Groq

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY no está configurada")

        if isinstance(event, str):
            event_text = event
        else:
            event_text = json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
Eres un analista SOC senior. Analiza el evento/IOC y responde SOLO JSON válido.
No uses markdown. No inventes evidencia. Todo el contenido visible debe estar en español.
Las recomendaciones deben ser acciones de resolución, no frases ambiguas.

INPUT:
{event_text}

OUTPUT JSON EXACTO:
{{
  "provider": "AWS|Azure|GCP|Linux|Web|Firewall|OnPrem|Generic",
  "summary": "Resumen ejecutivo breve, sin repetir el término IA.",
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
    "Acción concreta de contención o bloqueo.",
    "Acción concreta de investigación.",
    "Acción concreta de remediación o cierre."
  ],
  "confidence": 0.0,
  "model_used": "{model}",
  "prompt_version": "structured-es-v2"
}}
"""

        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres un analista SOC senior. Devuelve SOLO JSON válido. "
                        "No inventes evidencia. Responde todo en español. "
                        "Las recomendaciones deben ser resolutivas."
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
            recommendations = _resolution_recommendations(ioc, ioc_type, risk_score)

        return {
            "provider": parsed.get("provider", "Generic"),
            "summary": parsed.get("summary") or _spanish_summary_from_event(event, severity, risk_score),
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
            "prompt_version": parsed.get("prompt_version", "structured-es-v2"),
            "analysis_source": "groq_structured",
        }

    except Exception as exc:
        ioc = ""
        if isinstance(event, dict):
            ioc = event.get("ioc") or event.get("query") or event.get("sourceIPAddress") or ""
        ioc_type = (event.get("ioc_type") if isinstance(event, dict) else None) or _classify_ioc_from_text(ioc)
        risk_score = 50
        severity = "Medium"

        return {
            "provider": "Generic",
            "summary": _spanish_summary_from_event(event, severity, risk_score),
            "severity": severity,
            "risk_score": risk_score,
            "ips": [ioc] if ioc_type == "ip" and ioc else [],
            "domains": [ioc] if ioc_type == "domain" and ioc else [],
            "urls": [ioc] if ioc_type == "url" and ioc else [],
            "users": [],
            "resources": [],
            "actions": [],
            "mitre_techniques": [],
            "evidence": ["No se obtuvo respuesta estructurada del motor de análisis."],
            "recommendations": _resolution_recommendations(ioc, ioc_type, risk_score),
            "confidence": 0.5,
            "model_used": model,
            "prompt_version": "structured-es-v2",
            "analysis_source": "local_operational_fallback",
            "error": str(exc),
        }


def build_unified_ioc_verdict_es(
    ioc: str,
    ioc_type: str,
    internal_history: list[dict],
    external_reputation: dict | None,
    ai_result: dict,
) -> dict:
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

    confidence = _safe_confidence(ai_result.get("confidence"), 0.5)
    if external_reputation and external_reputation.get("available"):
        confidence = min(1.0, confidence + 0.15)
    if internal_history:
        confidence = min(1.0, confidence + 0.15)

    evidence_sources = []
    if internal_max_risk > 0:
        evidence_sources.append("historial_interno")
    if reputation_score > 0:
        evidence_sources.append("reputacion_externa")
    if not evidence_sources:
        evidence_sources.append("sin_evidencia_positiva")

    score_explanation = (
        f"El puntaje oficial se calculó con evidencia verificable. "
        f"Riesgo interno máximo: {internal_max_risk}. "
        f"Reputación externa: {reputation_score}. "
        f"Análisis contextual: {analysis_score}. "
        "El análisis contextual complementa la interpretación, pero el puntaje oficial se mantiene basado en evidencia interna y reputación externa."
    )

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
        "score_basis": "evidencia_verificable",
        "score_explanation": score_explanation,
        "ai_score": analysis_score,
        "ai_score_type": "contextual_only",
        "confidence": round(confidence, 2),
        "analysis_confidence_percent": int(round(confidence * 100)),
    }


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
        "Confianza del Análisis": "Confianza del análisis",
        "Review recent logs for connections involving this IP.": "Revisar logs recientes de firewall, proxy, DNS, autenticación y endpoint relacionados con esta IP.",
        "Check whether this IP appears in authentication, firewall or proxy logs.": "Confirmar si la IP aparece en eventos de autenticación, firewall, proxy, VPN o EDR.",
        "Block or monitor the IP if it appears in high-risk activity.": "Bloquear la IP si tiene reputación crítica o actividad interna de alto riesgo.",
        "Correlate this IP with users, assets and timestamps before taking containment action.": "Relacionar la IP con usuarios, activos y horarios para documentar alcance y cierre del caso.",
    }

    updated = html
    for old, new in replacements.items():
        updated = updated.replace(old, new)

    if updated != html:
        try:
            index_path.write_text(updated, encoding="utf-8")
        except OSError:
            return


def apply_spanish_analysis_patch(main_module) -> None:
    try:
        import app.analyzer as analyzer

        analyzer.analyze_security_event_structured = analyze_security_event_structured_es
        main_module.analyze_security_event_structured = analyze_security_event_structured_es
    except Exception:
        pass

    main_module.build_unified_ioc_verdict = build_unified_ioc_verdict_es
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
