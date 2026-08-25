"""Safe frontend loader for report workflow assets.

This module only appends one static script tag to the rendered index page.
It does not rewrite existing JavaScript, does not touch compressed responses,
and does not perform text replacements inside inline scripts.

Important: frontend/index.html contains literal </body> strings inside JavaScript
template literals used for report popups. Therefore this loader must insert the
asset before the final real </body>, not the first occurrence.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse, HTMLResponse
from starlette.routing import Route


INDEX_PATH = Path("frontend/index.html")
REPORT_WORKFLOW_SCRIPT = '<script src="/assets/report_workflow_fix.js?v=20260825-source-loader-2"></script>'


def _with_report_workflow_script(html: str) -> str:
    if "report_workflow_fix.js" in html:
        return html

    lower_html = html.lower()
    body_pos = lower_html.rfind("</body>")
    last_script_close = lower_html.rfind("</script>")

    if body_pos != -1 and body_pos > last_script_close:
        return html[:body_pos] + f"  {REPORT_WORKFLOW_SCRIPT}\n" + html[body_pos:]

    return html + "\n" + REPORT_WORKFLOW_SCRIPT + "\n"


def install_report_frontend_loader(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    if getattr(app.state, "securi_report_frontend_loader_installed", False):
        return

    app.state.securi_report_frontend_loader_installed = True

    async def securi_report_index_loader(request):
        try:
            html = INDEX_PATH.read_text(encoding="utf-8")
            html = _with_report_workflow_script(html)
        except Exception:
            return FileResponse(INDEX_PATH)

        return HTMLResponse(
            content=html,
            headers={"Cache-Control": "no-store"},
        )

    app.router.routes.insert(
        0,
        Route("/", endpoint=securi_report_index_loader, methods=["GET"]),
    )
