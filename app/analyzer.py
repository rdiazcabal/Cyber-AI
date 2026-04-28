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
            event_text = json.dumps(event, indent=2)

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