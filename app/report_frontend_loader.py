"""Safe frontend loader for report workflow assets.

This module only appends one static script tag to the source index page.
It does not rewrite existing JavaScript, does not touch compressed responses,
and does not perform text replacements inside frontend/index.html.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse, HTMLResponse
from starlette.routing import Route


INDEX_PATH = Path("frontend/index.html")
REPORT_WORKFLOW_SCRIPT = '<script src="/assets/report_workflow_fix.js?v=20260825-source-loader-1"></script>'


def _with_report_workflow_script(html: str) -> str:
    if "report_workflow_fix.js" in html:
        return html

    if "</body>" in html:
        return html.replace("</body>", f"  {REPORT_WORKFLOW_SCRIPT}\n</body>", 1)

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
