"""Inject the global SecuRI i18n runtime into all HTML entrypoints.

The current UI is static HTML plus JavaScript. This build-time patch avoids
editing every template manually and makes the Spanish/English switch available
across the whole application, including admin.html.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SCRIPT_TAG = '<script src="/assets/securi_i18n_global.js?v=global-i18n-v1"></script>'


def inject_script(path: Path) -> bool:
    if not path.exists():
        return False

    html = path.read_text(encoding="utf-8")
    if "securi_i18n_global.js" in html:
        return False

    if "</body>" in html:
        updated = html.replace("</body>", f"  {SCRIPT_TAG}\n</body>", 1)
    elif "</html>" in html:
        updated = html.replace("</html>", f"  {SCRIPT_TAG}\n</html>", 1)
    else:
        updated = html + "\n" + SCRIPT_TAG + "\n"

    path.write_text(updated, encoding="utf-8")
    return True


def main() -> None:
    changed = []
    for name in ["index.html", "admin.html"]:
        html_path = FRONTEND / name
        if inject_script(html_path):
            changed.append(str(html_path.relative_to(ROOT)))

    if changed:
        print("SecuRI global i18n injected into: " + ", ".join(changed))
    else:
        print("SecuRI global i18n already present or no HTML entrypoints changed.")


if __name__ == "__main__":
    main()
