"""Standalone HTML dashboard rendering for stored syslog events."""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from .parser import SEVERITY_NAMES, format_timestamp, utcnow
from .store import Store, Stats

__all__ = ["SEVERITY_COLORS", "build_dashboard", "render_dashboard"]

#: Colours used by the severity bars and badges.
SEVERITY_COLORS = {
    "emerg": "#7f1d1d",
    "alert": "#991b1b",
    "crit": "#b91c1c",
    "err": "#dc2626",
    "warning": "#d97706",
    "notice": "#2563eb",
    "info": "#0f766e",
    "debug": "#475569",
}

_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 32px 24px 48px;
  font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: #f8fafc;
  color: #0f172a;
}
main { max-width: 1100px; margin: 0 auto; }
h1 { margin: 0 0 4px; font-size: 28px; }
h2 { margin: 32px 0 12px; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
.generated { margin: 0 0 24px; color: #475569; font-size: 13px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; }
.card {
  flex: 1 1 160px; background: #ffffff; border: 1px solid #e2e8f0;
  border-radius: 10px; padding: 14px 16px;
}
.card .value { display: block; font-size: 26px; font-weight: 700; }
.card .label { color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
table { width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #e2e8f0; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #e2e8f0; font-size: 13px; vertical-align: top; }
th { background: #f1f5f9; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #475569; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.bars { display: grid; gap: 8px; }
.bar-row { display: grid; grid-template-columns: 90px 1fr 60px; gap: 10px; align-items: center; }
.bar-label { font-size: 13px; font-weight: 600; }
.bar-track { background: #e2e8f0; border-radius: 4px; height: 14px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; }
.bar-value { font-size: 13px; text-align: right; font-variant-numeric: tabular-nums; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; color: #ffffff; font-size: 11px; font-weight: 600; }
.msg { max-width: 520px; overflow-wrap: anywhere; }
footer { margin-top: 36px; color: #64748b; font-size: 12px; }
@media (prefers-color-scheme: dark) {
  body { background: #0f172a; color: #e2e8f0; }
  .card, table { background: #1e293b; border-color: #334155; }
  th { background: #273449; color: #cbd5e1; }
  th, td { border-color: #334155; }
  h2 { border-color: #334155; }
  .bar-track { background: #334155; }
}
"""


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _severity_badge(severity: int) -> str:
    name = SEVERITY_NAMES[severity] if 0 <= severity < len(SEVERITY_NAMES) else f"severity-{severity}"
    colour = SEVERITY_COLORS.get(name, "#475569")
    return f'<span class="badge" style="background:{colour}">{_escape(name)}</span>'


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    header_html = "".join(
        f'<th class="{"num" if index in numeric else ""}">{_escape(title)}</th>'
        for index, title in enumerate(headers)
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="{"num" if index in numeric else ""}">{cell}</td>'
            for index, cell in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(headers)}">No data</td></tr>')
    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_dashboard(
    stats: Stats,
    recent: list[dict[str, Any]],
    title: str = "Syslog Router dashboard",
    generated_at: datetime | None = None,
) -> str:
    """Render a complete, self-contained HTML dashboard document."""
    moment = format_timestamp(generated_at or utcnow())
    host_count = len(stats.top_hosts)
    app_count = len(stats.top_apps)
    counter_total = sum(count for _, count in stats.counters)
    maximum = max(stats.severity.values(), default=0)

    cards = [
        ("events", str(stats.events), "stored events"),
        ("hosts", str(host_count), "hosts seen"),
        ("apps", str(app_count), "applications seen"),
        ("counters", str(counter_total), "counter hits"),
    ]
    card_html = "".join(
        f'<div class="card"><span class="value">{_escape(value)}</span>'
        f'<span class="label">{_escape(label)}</span></div>'
        for _, value, label in cards
    )

    severity_rows = []
    for name in SEVERITY_NAMES:
        count = stats.severity.get(name, 0)
        width = 0.0 if maximum == 0 else (count / maximum) * 100.0
        severity_rows.append(
            f'<div class="bar-row"><span class="bar-label">{_escape(name)}</span>'
            f'<div class="bar-track"><div class="bar-fill" '
            f'style="width:{width:.1f}%;background:{SEVERITY_COLORS[name]}"></div></div>'
            f'<span class="bar-value">{count}</span></div>'
        )

    host_table = _table(
        ["Host", "Events"],
        [[_escape(host), str(count)] for host, count in stats.top_hosts],
        numeric={1},
    )
    app_table = _table(
        ["Application", "Events"],
        [[_escape(app), str(count)] for app, count in stats.top_apps],
        numeric={1},
    )
    counter_table = _table(
        ["Counter", "Hits"],
        [[_escape(name), str(count)] for name, count in stats.counters],
        numeric={1},
    )
    recent_rows = [
        [
            _escape(event.get("ts") or ""),
            _escape(event.get("host") or "(unknown)"),
            _escape(event.get("app") or "-"),
            _severity_badge(int(event.get("severity") or 0)),
            f'<span class="msg">{_escape(event.get("msg") or "")}</span>',
        ]
        for event in recent
    ]
    recent_table = _table(
        ["Timestamp (UTC)", "Host", "Application", "Severity", "Message"],
        recent_rows,
    )
    window = f"{stats.first_ts or 'n/a'} .. {stats.last_ts or 'n/a'}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
<h1>{_escape(title)}</h1>
<p class="generated">Generated {_escape(moment)} &middot; window {_escape(window)}</p>
<section class="cards">{card_html}</section>
<h2>Severity distribution</h2>
<div class="bars">{''.join(severity_rows)}</div>
<h2>Top hosts</h2>
{host_table}
<h2>Top applications</h2>
{app_table}
<h2>Counters</h2>
{counter_table}
<h2>Recent events</h2>
{recent_table}
<footer>Generated by syslogrouter. This file is standalone: no external assets are referenced.</footer>
</main>
</body>
</html>
"""


def build_dashboard(
    db_path: str | Path,
    out_path: str | Path,
    title: str = "Syslog Router dashboard",
    now: datetime | None = None,
) -> Path:
    """Read the store at *db_path* and write a standalone dashboard to *out_path*."""
    generated_at = now or utcnow()
    with Store(db_path) as store:
        stats = store.stats()
        recent = store.recent(limit=20)
    document = render_dashboard(stats, recent, title=title, generated_at=generated_at)
    destination = Path(out_path)
    if destination.parent != Path("."):
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    return destination
