"""Build-time frontend patch for SecuRI IOC rendering.

This script runs during Docker image build after the frontend is copied into the
image. It applies direct changes to frontend/index.html so the deployed static UI
uses the new IOC wording, localized endpoint and full country display.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT / "frontend" / "index.html"


def replace_once(content: str, old: str, new: str, label: str) -> str:
    if old not in content:
        raise RuntimeError(f"Missing expected frontend block: {label}")
    return content.replace(old, new, 1)


def replace_all(content: str, replacements: dict[str, str]) -> str:
    updated = content
    for old, new in replacements.items():
        updated = updated.replace(old, new)
    return updated


def main() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")

    # Add visible language selector inside Threat Hunting if it does not exist.
    if "iocAnalysisLanguage" not in html:
        html = replace_once(
            html,
            """              <div class=\"threat-actions\">""",
            """              <div class=\"input-row\" style=\"max-width:260px;\">
                <label>Idioma del análisis</label>
                <select id=\"iocAnalysisLanguage\">
                  <option value=\"es\">Español</option>
                  <option value=\"en\">English</option>
                </select>
              </div>

              <div class=\"threat-actions\">""",
            "language selector",
        )

    # Add localized helpers before unified IOC analysis.
    if "function getIOCAnalysisLanguage()" not in html:
        html = replace_once(
            html,
            """    async function runUnifiedIOCAnalysis() {""",
            """    function getIOCAnalysisLanguage() {
      const select = document.getElementById(\"iocAnalysisLanguage\");
      return select && select.value ? select.value : \"es\";
    }

    function getIOCLabels() {
      const lang = getIOCAnalysisLanguage();

      if (lang === \"en\") {
        return {
          running: \"Running unified IOC analysis...\",
          consulting: \"Checking internal history, external reputation and technical analysis...\",
          failed: \"Unified IOC analysis failed.\",
          completed: \"Unified IOC analysis completed for\",
          error: \"Unified IOC analysis error\",
          evidence: \"Verifiable evidence\",
          executiveSummary: \"Executive Summary\",
          technicalAnalysis: \"Technical Analysis\",
          note: \"Note: Contextual analysis is informational. The official threat score is calculated using verifiable evidence.\",
          iocType: \"IOC Type\",
          threatScore: \"Threat Score\",
          internalRisk: \"Internal Risk\",
          externalReputation: \"External Reputation\",
          internalMatches: \"Internal Matches\",
          contextualScore: \"Contextual Score\",
          analysisConfidence: \"Analysis Confidence\",
          scoreBasis: \"Score Basis\",
          recommendations: \"Recommendations\",
          source: \"Source\",
          abuseScore: \"Abuse Score\",
          reports: \"Reports\",
          country: \"Country\",
          noRecommendations: \"No recommendations available.\",
          noExternal: \"No external reputation information is available for this IOC type.\",
          viewInternal: \"View Internal History\",
          viewTimeline: \"View Timeline\",
          needsReview: \"Needs Review\"
        };
      }

      return {
        running: \"Ejecutando análisis unificado de IOC...\",
        consulting: \"Consultando historial interno, reputación externa y análisis técnico...\",
        failed: \"Falló el análisis unificado.\",
        completed: \"Análisis unificado completado para\",
        error: \"Error en análisis unificado\",
        evidence: \"Evidencia verificable\",
        executiveSummary: \"Resumen Ejecutivo\",
        technicalAnalysis: \"Análisis técnico\",
        note: \"Nota: El análisis contextual es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.\",
        iocType: \"Tipo de IOC\",
        threatScore: \"Puntaje de Amenaza\",
        internalRisk: \"Riesgo Interno\",
        externalReputation: \"Reputación Externa\",
        internalMatches: \"Coincidencias Internas\",
        contextualScore: \"Análisis Contextual\",
        analysisConfidence: \"Confianza del Análisis\",
        scoreBasis: \"Base del Score\",
        recommendations: \"Recomendaciones\",
        source: \"Fuente\",
        abuseScore: \"Puntaje de Abuso\",
        reports: \"Reportes\",
        country: \"País\",
        noRecommendations: \"No hay recomendaciones disponibles.\",
        noExternal: \"No hay información externa sobre la reputación de este tipo de IOC.\",
        viewInternal: \"Ver Historial Interno\",
        viewTimeline: \"Ver Timeline\",
        needsReview: \"Requiere revisión\"
      };
    }

    function getCountryDisplay(value) {
      if (!value) return \"N/A\";

      if (typeof value === \"string\") {
        return value;
      }

      return value.country_name || value.country || value.country_full_name || value.country_code || \"N/A\";
    }

    async function runUnifiedIOCAnalysis() {""",
            "localized IOC helpers",
        )

    # Directly change the old IOC unified function behavior.
    html = replace_all(
        html,
        {
            "status.innerText = \"Running unified IOC analysis...\";": "const labels = getIOCLabels();\n      const language = getIOCAnalysisLanguage();\n\n      status.innerText = labels.running;",
            "panel.innerText = \"Consultando historial interno, reputación externa y análisis AI...\";": "panel.innerText = labels.consulting;",
            "await fetch(\"/iocs/unified-analysis\", {": "await fetch(\"/iocs/unified-analysis-localized\", {",
            "body: JSON.stringify({ query })": "body: JSON.stringify({ query, language })",
            "panel.innerText = `Unified IOC analysis failed: ${data.detail || res.status}`;": "panel.innerText = `${labels.failed}: ${data.detail || res.status}`;",
            "status.innerText = \"Unified analysis failed.\";": "status.innerText = labels.failed;",
            "? \"Evidencia verificable\"": "? labels.evidence",
            "AI score informativo: ${aiScore}.": "Análisis contextual: ${aiScore}.",
            "La IA apoya la interpretación, pero no modifica el puntaje oficial si no existe evidencia interna o reputación externa.": "El análisis contextual complementa la interpretación; el puntaje oficial se mantiene basado en evidencia verificable.",
            "const aiSummary = ai.summary || \"No AI summary available.\";": "const aiSummary = ai.summary || (language === \"en\" ? \"No structured technical analysis was returned.\" : \"No se obtuvo análisis técnico estructurado.\");",
            "No hay recomendaciones disponibles.": "${labels.noRecommendations}",
            "País: ${escapeHtml(reputation.country_code || \"N/A\")}": "${labels.country}: ${escapeHtml(getCountryDisplay(reputation))}",
            "status.innerText = `Unified IOC analysis completed for ${data.ioc || query}.`;": "status.innerText = `${labels.completed} ${data.ioc || query}.`;",
            "<strong>Verdicto:</strong> ${escapeHtml(verdict.verdict || \"Needs Review\")}": "<strong>Verdicto:</strong> ${escapeHtml(verdict.verdict || labels.needsReview)}",
            "<strong>Resumen Ejecutivo:</strong> ${escapeHtml(enterpriseSummary)}": "<strong>${labels.executiveSummary}:</strong> ${escapeHtml(enterpriseSummary)}",
            "<strong>Interpretación AI:</strong> ${escapeHtml(aiSummary)}": "<strong>${labels.technicalAnalysis}:</strong> ${escapeHtml(aiSummary)}",
            "Nota: El AI Score es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.": "${labels.note}",
            "<strong>Tipo de IOC</strong>": "<strong>${labels.iocType}</strong>",
            "<strong>Puntaje de Amenaza</strong>": "<strong>${labels.threatScore}</strong>",
            "<strong>Riesgo Interno</strong>": "<strong>${labels.internalRisk}</strong>",
            "<strong>Reputación Externa</strong>": "<strong>${labels.externalReputation}</strong>",
            "<strong>Coincidencias Internas</strong>": "<strong>${labels.internalMatches}</strong>",
            "<strong>AI Score Informativo</strong>": "<strong>${labels.contextualScore}</strong>",
            "<strong>Confianza del Análisis</strong>": "<strong>${labels.analysisConfidence}</strong>",
            "<strong>Base del Score</strong>": "<strong>${labels.scoreBasis}</strong>",
            "<strong>Reputación Externa:</strong>": "<strong>${labels.externalReputation}:</strong>",
            "<strong>Recomendaciones:</strong>": "<strong>${labels.recommendations}:</strong>",
            "Ver Historial Interno": "${labels.viewInternal}",
            "Ver Timeline": "${labels.viewTimeline}",
            "panel.innerText = `Unified IOC analysis error: ${err.message}`;": "panel.innerText = `${labels.error}: ${err.message}`;",
            "status.innerText = \"Unified analysis error.\";": "status.innerText = labels.error;",
            "<b>País:</b> ${escapeHtml(data.summary.country || \"N/A\")}<br>": "<b>País:</b> ${escapeHtml(data.summary.country_name || data.summary.country || data.summary.country_code || \"N/A\")}<br>",
            "<b>Country:</b> ${ip.country_code || \"N/A\"}<br>": "<b>Country:</b> ${ip.country_name || ip.country || ip.country_code || \"N/A\"}<br>",
        },
    )

    # Replace only the external reputation fallback text in the template literal.
    html = html.replace(
        "\"No hay información externa sobre la reputación de este tipo de IOC.\"",
        "labels.noExternal",
    )

    INDEX_PATH.write_text(html, encoding="utf-8")
    print("SecuRI frontend build patch applied.")


if __name__ == "__main__":
    main()
