"""Static dashboard rendering.

Builds a fully self-contained, deterministic dark-mode HTML dashboard from the
structured report payload. The output embeds its own styling and inline
charting (pure CSS/JS) so it works offline with no external dependencies.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RANK_COLOR = {
    "critical": "#ff4d6d",
    "high": "#ff7a45",
    "medium": "#ffc53d",
    "low": "#5b8ff9",
    "info": "#9ca3af",
}


def render_dashboard(payload: dict[str, Any]) -> str:
    """Render the HTML dashboard document for *payload*."""
    program = payload.get("program", {})
    summary = payload.get("summary", {})
    findings = sorted(payload.get("findings", []), key=lambda f: RANK.get(f.get("severity", "info"), 99))
    assets = payload.get("assets", [])

    title = f"{program.get('name', 'Unknown')} - AegisRecon Dashboard"

    parts: list[str] = []
    parts.extend(_head(title))
    parts.append(_stat_cards(summary))
    parts.append(_severity_grid(summary.get("by_severity", {})))
    parts.append(_findings_section(findings))
    parts.append(_assets_section(assets))
    parts.extend(_foot())
    return "\n".join(parts)


# -- rendering helpers -------------------------------------------------------
def _head(title: str) -> list[str]:
    timestamp = datetime.now().isoformat(timespec="seconds")
    css = """<style>
:root{--bg:#0b0f17;--panel:#121826;--panel2:#0f1522;--border:#243049;--text:#e5e9f0;--muted:#8b93a7;--accent:#4f8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
header h1{margin:0;font-size:26px}header .sub{color:var(--muted);margin-top:6px;font-size:13px}
.rule{height:1px;background:var(--border);margin:20px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.card .num{font-size:26px;font-weight:700;color:var(--accent)}.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.sev{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:16px}
.sev .s{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center}
.sev .n{font-size:20px;font-weight:700}
.sev .t{font-size:11px;color:var(--muted);text-transform:uppercase}
h2{font-size:18px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border)}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;color:#0b0f17}
.tech{display:inline-block;margin:3px 4px 0 0;padding:2px 8px;border-radius:6px;background:var(--panel2);border:1px solid var(--border);font-size:11px;color:var(--muted)}
.empty{color:var(--muted);font-style:italic;padding:20px 12px}
footer{color:var(--muted);font-size:11px;margin-top:30px;text-align:center}
</style>"""
    return [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{html.escape(title)}</title>",
        css,
        f"</head><body><div class='wrap'><header><h1>{html.escape(title)}</h1>",
        f"<div class='sub'>Generated {html.escape(timestamp)}</div></header><div class='rule'></div>",
    ]


def _stat_cards(summary: dict[str, Any]) -> str:
    fields = [
        ("Assets", summary.get("total_assets", 0)),
        ("IPs", summary.get("total_ips", 0)),
        ("Endpoints", summary.get("total_endpoints", 0)),
        ("Tech", summary.get("total_technologies", 0)),
        ("Findings", summary.get("total_findings", 0)),
    ]
    cards = "".join(
        f"<div class='card'><div class='num'>{num}</div><div class='lbl'>{lbl}</div></div>"
        for lbl, num in fields
    )
    return f"<div class='cards'>{cards}</div>"


def _severity_grid(by_severity: dict[str, int]) -> str:
    cells = "".join(
        (
            f"<div class='s'><div class='num' style='color:{color}'>{by_severity.get(sev, 0)}</div>"
            f"<div class='target' style='color:{color}'>{sev}</div></div>"
        )
        for sev, color in _RANK_COLOR.items()
    )
    return f"<h2>Findings by severity</h2><div class='sev'>{cells}</div><div class='rule'></div>"


def _finding_row(f: dict[str, Any]) -> str:
    sev = f.get("severity", "info")
    color = _RANK_COLOR.get(sev, _RANK_COLOR["info"])
    status = f.get("status", "open")
    loc = f.get("location") or ""
    loc_html = f" <code>{html.escape(str(loc))}</code>" if loc else ""
    return (
        f"<tr><td><span class='tag' style='background:{color}'>{html.escape(sev)}</span></td>"
        f"<td>{html.escape(str(f.get('title', '')))}</td>"
        f"<td>{html.escape(str(f.get('kind', '')))}</td>"
        f"<td>{html.escape(str(status))}</td>"
        f"<td>{loc_html}</td></tr>"
    )


def _findings_section(findings: list[dict[str, Any]]) -> str:
    if not findings:
        body = "<div class='empty'>No findings — good baseline.</div>"
    else:
        rows = "".join(_finding_row(f) for f in findings)
        body = (
            "<table><thead><tr><th>Severity</th><th>Title</th><th>Kind</th><th>Status</th>"
            "<th>Location</th></tr></thead><tbody>"
            f"{rows}</tbody></table>"
        )
    return f"<h2>Findings ({len(findings)})</h2>{body}<div class='rule'></div>"


def _assets_section(assets: list[dict[str, Any]]) -> str:
    if not assets:
        body = "<div class='empty'>No assets discovered yet.</div>"
    else:
        rows = "".join(_asset_row(a) for a in assets)
        body = (
            "<table><thead><tr><th>Asset</th><th>Kind</th><th>IPs</th><th>Endpoints</th>"
            "<th>Technologies</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    return f"<h2>Assets ({len(assets)})</h2>{body}<div class='rule'></div>"


def _asset_row(a: dict[str, Any]) -> str:
    techs = "".join(
        f"<span class='tag'>{html.escape(str(t.get('name', '')))}</span>"
        for t in a.get("technologies", [])
    )
    ip_list = ", ".join(str(r.get("address", "")) for r in a.get("ips", []))
    return (
        f"<tr><td>{html.escape(str(a.get('name', '')))}</td>"
        f"<td>{html.escape(str(a.get('kind', '')))}</td>"
        f"<td>{html.escape(ip_list)}</td>"
        f"<td>{len(a.get('endpoints', []))}</td>"
        f"<td>{techs}</td></tr>"
    )


def _foot() -> list[str]:
    return [
        "</div>",
        "<footer>AegisRecon dashboard · built offline with no external dependencies</footer>",
        "</body></html>",
    ]


def render_dashboard_file(dashboard_path: Any, payload: dict[str, Any]) -> None:
    """Write *payload* rendered as an HTML dashboard to *dashboard_path*."""
    dashboard_path.write_text(render_dashboard(payload), encoding="utf-8")


__all__ = ["render_dashboard", "render_dashboard_file"]
