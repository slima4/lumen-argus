"""Dashboard HTML — community 4-page SPA with hash-based routing.

Assembled from separate static files at import time:
  static/base.html  — HTML skeleton with {{STYLE}} and {{SCRIPT}} placeholders
  static/style.css  — all CSS
  static/js/         — per-page JS modules concatenated in order

All dynamic content rendered via textContent/DOM APIs (XSS-safe).
The only innerHTML usage is for static SVG icon constants defined
in the JS source code — these are hardcoded strings, never user data.
No external dependencies, no build step, no CDN.
"""

import os

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def _read_static(filename):
    """Read a static asset file from the dashboard/static/ directory."""
    path = os.path.join(_STATIC_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


_JS_MODULES = [
    "js/core.js",
    "js/dashboard.js",
    "js/findings.js",
    "js/audit.js",
    "js/settings.js",
    "js/notifications.js",
    "js/rules.js",
    "js/pipeline.js",
    "js/init.js",
]


def _build_dashboard_html():
    """Assemble the dashboard SPA from static HTML, CSS, and JS files.

    JS is concatenated from per-page modules in _JS_MODULES order.
    Runs once at import time. The result is cached in COMMUNITY_DASHBOARD_HTML.
    """
    template = _read_static("base.html")
    css = _read_static("style.css")
    js = "\n".join(_read_static(m) for m in _JS_MODULES)
    html = template.replace("{{STYLE}}", css).replace("{{SCRIPT}}", js)
    assert "{{STYLE}}" not in html, "Unreplaced {{STYLE}} placeholder"
    assert "{{SCRIPT}}" not in html, "Unreplaced {{SCRIPT}} placeholder"
    return html


try:
    COMMUNITY_DASHBOARD_HTML = _build_dashboard_html()
except FileNotFoundError:
    # Fallback if static files are missing (broken install)
    COMMUNITY_DASHBOARD_HTML = (
        "<!DOCTYPE html><html><head><title>lumen-argus</title></head>"
        "<body><h1>Dashboard static files are missing</h1>"
        "<p>Re-install the package: <code>pip install -e .</code></p>"
        "</body></html>"
    )
