"""Safe Groq analysis wrapper for SecuRI.

The previous default model could return 400 if the account/model combination is
not available. This wrapper keeps GROQ_MODEL configurable, but retries with a
small list of known Groq model IDs before falling back to operational guidance.
"""

from __future__ import annotations

import json
import os
from typing import Iterable

from groq import Groq

DEFAULT_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
FALLBACK_MODELS = [
    DEFAULT_MODEL,
    "openai/gpt-oss-20b",
    "llama-3.1-8b-instant",
]


def _unique_models(models: Iterable[str]) -> list[str]:
    result = []
    for model in models:
        clean = (model or "").strip()
        if clean and clean not in result:
            result.append(clean)
    return result


def _client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY no está configurado")
    return Groq(api_key=api_key)


def _chat_completion(messages: list[dict], temperature: float, max_tokens: int) -> tuple[str, str]:
    last_error: Exception | None = None

    for model in _unique_models(FALLBACK_MODELS):
        try:
            completion = _client().chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = completion.choices[0].message.content or ""
            return content, model
        except Exception as exc:
            last_error = exc
            text = str(exc).lower()
            name = exc.__class__.__name__.lower()

            retryable_model_error = (
                "400" in text
                or "badrequest" in name
                or "model" in text
                or "decommission" in text
                or "deprecated" in text
            )

            if retryable_model_error:
                continue
            raise

    if last_error:
        raise last_error

    raise RuntimeError("No se pudo ejecutar Groq")


def analyze_security_event(event) -> str:
    try:
        event_text = event if isinstance(event, str) else json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
Eres un analista SOC senior especializado en seguridad multi-cloud y on-prem.

Analiza el siguiente evento o log:

{event_text}

Responde en español con este formato:

### Proveedor Detectado
AWS, Azure, GCP, Linux, Web, Firewall o Genérico.

### Resumen Ejecutivo
Qué ocurrió.

### Severidad
Low, Medium, High o Critical.

### Evidencia Observada
IPs, usuario, recurso, acción, error o evento relevante.

### Impacto
Riesgo potencial.

### MITRE ATT&CK
Táctica y técnica probable.

### Acciones Recomendadas
Contención, investigación y remediación.

### Escalamiento
Sí/No y a quién.
"""

        content, _model = _chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": "Eres un analista SOC senior. No inventes evidencia. Sé claro, técnico y accionable.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=1400,
        )
        return content

    except Exception as exc:
        return (
            "No se obtuvo análisis técnico desde Groq. "
            "Se debe continuar con revisión operacional basada en evidencia. "
            f"Detalle técnico: {str(exc)}"
        )


def analyze_security_event_structured(event) -> dict:
    try:
        event_text = event if isinstance(event, str) else json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
Eres un analista SOC senior especializado en seguridad multi-cloud y on-prem.

Analiza el siguiente evento/log y responde SOLO en JSON válido.
No agregues markdown, no agregues explicaciones fuera del JSON.
No inventes evidencia.
Las recomendaciones deben ser acciones resolutivas de contención, investigación y remediación.
Evita mencionar IA o AI en el contenido visible para el usuario.

INPUT:
{event_text}

OUTPUT JSON EXACTO:
{{
  "provider": "AWS|Azure|GCP|Linux|Web|Firewall|Generic",
  "summary": "Resumen ejecutivo breve, técnico y sin mencionar IA.",
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
  "recommendations": [],
  "confidence": 0.0,
  "model_used": "{DEFAULT_MODEL}",
  "prompt_version": "structured-v3"
}}
"""

        content, model_used = _chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres un analista SOC senior. Devuelve SOLO JSON válido. "
                        "No inventes evidencia. No uses markdown. "
                        "Todas las recomendaciones deben ser accionables y resolutivas."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=1000,
        )

        clean = content.strip()
        if clean.startswith("```"):
            clean = clean.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(clean)

        return {
            "provider": parsed.get("provider", "Generic"),
            "summary": parsed.get("summary", ""),
            "severity": parsed.get("severity", "Medium"),
            "risk_score": int(parsed.get("risk_score", 50) or 50),
            "ips": parsed.get("ips", []) or [],
            "domains": parsed.get("domains", []) or [],
            "urls": parsed.get("urls", []) or [],
            "users": parsed.get("users", []) or [],
            "resources": parsed.get("resources", []) or [],
            "actions": parsed.get("actions", []) or [],
            "mitre_techniques": parsed.get("mitre_techniques", []) or [],
            "evidence": parsed.get("evidence", []) or [],
            "recommendations": parsed.get("recommendations", []) or [],
            "confidence": float(parsed.get("confidence", 0.5) or 0.5),
            "model_used": parsed.get("model_used", model_used),
            "prompt_version": parsed.get("prompt_version", "structured-v3"),
        }

    except Exception as exc:
        return {
            "provider": "Generic",
            "summary": "No se obtuvo análisis técnico estructurado. Se debe continuar con revisión operacional basada en la evidencia disponible.",
            "severity": "Medium",
            "risk_score": 50,
            "ips": [],
            "domains": [],
            "urls": [],
            "users": [],
            "resources": [],
            "actions": [],
            "mitre_techniques": [],
            "evidence": [
                "El motor estructurado no devolvió una respuesta válida para este evento."
            ],
            "recommendations": [
                "Revisar el evento original y confirmar origen, usuario, activo, hora y acción observada.",
                "Correlacionar el indicador con logs de firewall, proxy, DNS, autenticación, EDR y sistemas críticos.",
                "Aplicar bloqueo preventivo si el indicador tiene reputación externa crítica o actividad interna asociada.",
                "Crear o actualizar un caso de investigación con evidencias, responsables y acciones de cierre.",
            ],
            "confidence": 0.5,
            "model_used": DEFAULT_MODEL,
            "prompt_version": "structured-v3",
            "error": str(exc),
        }


def install_groq_safe_analysis_patch() -> None:
    from app import analyzer

    analyzer.MODEL = DEFAULT_MODEL
    analyzer.analyze_security_event = analyze_security_event
    analyzer.analyze_security_event_structured = analyze_security_event_structured
