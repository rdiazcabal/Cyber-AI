"""Static asset loader for the IOC unified UI fix.

This loader only adds the existing /assets/ioc_unified_fix.js script to the
main index response. It does not rewrite frontend files during Docker build and
it removes compression-specific headers before returning the modified HTML so the
browser does not receive an invalid Content-Encoding response.
"""

from __future__ import annotations

from starlette.responses import Response

SCRIPT_TAG = '<script src="/assets/ioc_unified_fix.js?v=20260821-2"></script>'


def install_frontend_ioc_override(main_module) -> None:
    app = getattr(main_module, "app", None)
    if not app:
        return

    if getattr(app.state, "securi_ioc_unified_override_installed", False):
        return

    app.state.securi_ioc_unified_override_installed = True

    @app.middleware("http")
    async def securi_ioc_unified_asset_loader(request, call_next):
        response = await call_next(request)

        if request.url.path not in {"/"}:
            return response

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return response

        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        html = body.decode("utf-8", errors="ignore")

        if "ioc_unified_fix.js" not in html and "</body>" in html:
            html = html.replace("</body>", f"{SCRIPT_TAG}\n</body>", 1)

        headers = dict(response.headers)
        headers.pop("content-length", None)
        headers.pop("content-encoding", None)
        headers.pop("Content-Length", None)
        headers.pop("Content-Encoding", None)
        headers["Cache-Control"] = "no-store"

        return Response(
            content=html,
            status_code=response.status_code,
            headers=headers,
            media_type="text/html",
        )
