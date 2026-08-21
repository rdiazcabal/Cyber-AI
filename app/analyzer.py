import os
import json
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")


def analyze_security_event(event) -> str:
    try:
        if isinstance(event, str):
            event_text = event
        else:
            event_text = json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
            Eres un analista SOC senior especializado en multi-cloud security.

            Debes analizar eventos y logs de:
            - AWS CloudTrail, GuardDuty, Security Hub, VPC Flow Logs
            - Azure Entra ID, Activity Logs, Defender for Cloud, NSG Logs
            - GCP Cloud Audit Logs, Security Command Center, IAM, VPC Logs
            - Linux auth logs, web logs, firewall logs y texto plano

            Analiza el siguiente input:

            {event_text}

            Responde en español con este formato:

            ### Proveedor Detectado
            AWS, Azure, GCP, Linux, Web, Firewall o Genérico.

            ### Resumen Ejecutivo
            Qué ocurrió.

            ### Severidad
            Low, Medium, High o Critical.

            ### Evidencia Observada
            IPs, usuario, recurso, acción, error, evento relevante.

            ### Impacto
            Riesgo potencial.

            ### MITRE ATT&CK
            Táctica y técnica probable.

            ### Acciones Recomendadas
            Contención, investigación y remediación.

            ### Escalamiento
            Sí/No y a quién.
            """

        completion = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "Eres un analista SOC senior. No inventes evidencia. Sé claro, técnico y accionable."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=1400
        )

        return completion.choices[0].message.content

    except Exception as e:
        return f"ERROR GROQ: {str(e)}"


def analyze_security_event_structured(event) -> dict:
    """
    Structured Groq analysis for internal scoring, IOC extraction and threat search.
    This does NOT replace analyze_security_event().
    It complements the existing Spanish human-readable SOC report.
    """
    try:
        if isinstance(event, str):
            event_text = event
        else:
            event_text = json.dumps(event, indent=2, ensure_ascii=False)

        prompt = f"""
Eres un analista SOC senior especializado en multi-cloud security.

Analiza el siguiente evento/log y responde SOLO en JSON válido.
No agregues markdown, no agregues explicaciones fuera del JSON.
No inventes evidencia.
Las recomendaciones deben ser acciones resolutivas de contención, investigación y remediación.

INPUT:
{event_text}

OUTPUT JSON EXACTO:
{{
  "provider": "AWS|Azure|GCP|Linux|Web|Firewall|Generic",
  "summary": "Resumen ejecutivo breve sin repetir IA.",
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
  "model_used": "{MODEL}",
  "prompt_version": "structured-v2"
}}
"""

        completion = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres un analista SOC senior. "
                        "Devuelve SOLO JSON válido. "
                        "No inventes evidencia. "
                        "No uses markdown. "
                        "Todas las recomendaciones deben ser accionables y resolutivas."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=1000
        )

        content = completion.choices[0].message.content.strip()

        if content.startswith("```"):
            content = content.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(content)

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
            "model_used": parsed.get("model_used", MODEL),
            "prompt_version": parsed.get("prompt_version", "structured-v2"),
        }

    except Exception as e:
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
                "Crear o actualizar un caso de investigación con evidencias, responsables y acciones de cierre."
            ],
            "confidence": 0.5,
            "model_used": MODEL,
            "prompt_version": "structured-v2",
            "error": str(e)
        }
