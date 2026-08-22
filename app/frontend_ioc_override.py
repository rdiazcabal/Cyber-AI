"""Safe source-level IOC text override for the SecuRI index page.

This module does not use middleware and does not modify compressed responses.
It installs a high-priority route for `/` that reads the static index.html,
applies exact text-only replacements for the IOC unified analysis panel, and
then returns normal HTMLResponse content. Starlette/FastAPI middleware can then
apply compression safely after the route response is created.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import HTMLResponse, FileResponse
from starlette.routing import Route


INDEX_PATH = Path("frontend/index.html")

REPLACEMENTS = {
    'panel.innerText = "Consultando historial interno, reputación externa y análisis AI...";':
        'panel.innerText = "Consultando historial interno, reputación externa y análisis técnico...";',

    'const ai = data.ai_analysis || {};':
        'const technicalAnalysis = data.technical_analysis || data.ai_analysis || {};',

    'const aiScore = Number(verdict.ai_score ?? 0);':
        'const contextualScore = Number(verdict.contextual_score ?? verdict.ai_score ?? technicalAnalysis.risk_score ?? 0);',

    'AI score informativo: ${aiScore}.\n      La IA apoya la interpretación, pero no modifica el puntaje oficial si no existe evidencia interna o reputación externa.':
        'Análisis contextual: ${contextualScore}.\n      El análisis contextual complementa la interpretación; el puntaje oficial se mantiene basado en evidencia verificable.',

    'const aiSummary = ai.summary || "No AI summary available.";':
        'const technicalSummary = technicalAnalysis.summary || "No se obtuvo análisis técnico estructurado. Se debe continuar con revisión operacional basada en la evidencia disponible.";',

    'const recommendationsHtml = (ai.recommendations || [])':
        'const recommendationsHtml = (technicalAnalysis.recommendations || [])',

    'País: ${escapeHtml(reputation.country_code || "N/A")}':
        'País: ${escapeHtml(reputation.country_name || reputation.country || reputation.country_code || "N/A")}',

    '<strong>Interpretación AI:</strong> ${escapeHtml(aiSummary)}':
        '<strong>Análisis técnico:</strong> ${escapeHtml(technicalSummary)}',

    'Nota: El AI Score es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.':
        'Nota: El análisis contextual es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.',

    '<strong>AI Score Informativo</strong>\n            ${aiScore}':
        '<strong>Análisis Contextual</strong>\n            ${contextualScore}',

    'const res = await fetch("/iocs/unified-analysis", {':
        'const res = await fetch("/iocs/unified-analysis-v2", {',
}


def _patched_index_html() -> str:
    html = INDEX_PATH.read_text(encoding="utf-8")
    for old, new in REPLACEMENTS.items():
        html = html.replace(old, new)
    return html


def install_frontend_ioc_override(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    if getattr(app.state, "securi_ioc_index_text_override_installed", False):
        return

    app.state.securi_ioc_index_text_override_installed = True

    async def securi_index_text_override(request):
        try:
            html = _patched_index_html()
        except Exception:
            return FileResponse(INDEX_PATH)

        return HTMLResponse(
            content=html,
            headers={"Cache-Control": "no-store"},
        )

    app.router.routes.insert(
        0,
        Route("/", endpoint=securi_index_text_override, methods=["GET"]),
    )
