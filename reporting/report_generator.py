"""
nexsus/core/report_generator.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Professional report generator with multiple output formats:
  • JSON  — machine-readable full findings dump
  • CSV   — spreadsheet-friendly summary
  • HTML  — polished self-contained report with:
              - Executive summary with severity chart
              - Findings table with expandable detail
              - Assets inventory
              - Remediation checklist
              - Dark-mode, responsive CSS
  • Markdown — quick share / GitHub-compatible
"""
import csv
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from nexsus.config import Config
from nexsus.core.logger import Logger

_logger = Logger("ReportGenerator")


# ── Severity ordering ─────────────────────────────────────────────────────────
_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_SEV_COLORS = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#3498db",
    "Info":     "#95a5a6",
}


class ReportGenerator:
    """
    Generates scan reports in JSON, CSV, HTML, and Markdown formats.

    Usage::
        rg = ReportGenerator(findings, assets, scope_summary="example.com")
        paths = rg.generate()
        # Returns dict: {"json": Path, "csv": Path, "html": Path, "markdown": Path}
    """

    def __init__(
        self,
        findings: list[dict],
        assets:   dict,
        scope_summary: str = "",
        scan_duration_s: float = 0.0,
        formats: Optional[list[str]] = None,
    ):
        self.findings        = sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "Info"), 5))
        self.assets          = assets
        self.scope_summary   = scope_summary
        self.scan_duration_s = scan_duration_s
        self.formats         = formats or getattr(Config, "REPORT_FORMATS", ["json", "csv", "html", "markdown"])
        self._ts             = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._report_dir     = Path(Config.REPORT_DIR)
        self._report_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> dict[str, Path]:
        """Generate all configured report formats. Returns path dict."""
        out = {}
        for fmt in self.formats:
            try:
                fn = getattr(self, f"_write_{fmt}", None)
                if fn:
                    path = fn()
                    out[fmt] = path
                    _logger.success(f"Report [{fmt.upper()}]: {path}")
            except Exception as exc:
                _logger.error(f"Report generation failed [{fmt}]: {exc}")
        return out

    # ── Legacy static API ─────────────────────────────────────────────────────

    @staticmethod
    def generate_report(findings, assets, scope_summary=""):
        """Legacy entry-point called by older orchestrator code."""
        rg = ReportGenerator(findings, assets, scope_summary)
        return rg.generate()

    # ── JSON ─────────────────────────────────────────────────────────────────

    def _write_json(self) -> Path:
        path = self._report_dir / f"nexsus_report_{self._ts}.json"
        payload = {
            "meta": {
                "tool":        "Nexsus",
                "version":     getattr(Config, "VERSION", "3.0"),
                "generated":   datetime.now().isoformat(),
                "scope":       self.scope_summary,
                "duration_s":  round(self.scan_duration_s, 1),
            },
            "summary":  self._summary(),
            "findings": self.findings,
            "assets":   {
                k: list(v) if isinstance(v, set) else v
                for k, v in self.assets.items()
            },
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    # ── CSV ──────────────────────────────────────────────────────────────────

    def _write_csv(self) -> Path:
        path = self._report_dir / f"nexsus_report_{self._ts}.csv"
        fields = [
            "id", "title", "severity", "cvss", "vuln_type",
            "url", "parameter", "payload", "confidence",
            "evidence", "remediation", "confirmed", "module",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for f in self.findings:
                row = {k: f.get(k, "") for k in fields}
                # Truncate long fields
                for k in ("payload", "evidence"):
                    if len(str(row[k])) > 300:
                        row[k] = str(row[k])[:297] + "..."
                w.writerow(row)
        return path

    # ── Markdown ─────────────────────────────────────────────────────────────

    def _write_markdown(self) -> Path:
        path  = self._report_dir / f"nexsus_report_{self._ts}.md"
        summ  = self._summary()
        lines = [
            "# Nexsus Security Assessment Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Scope:** {self.scope_summary}  ",
            f"**Duration:** {round(self.scan_duration_s, 0):.0f}s",
            "",
            "## Executive Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            lines.append(f"| {sev} | {summ['by_severity'].get(sev, 0)} |")

        lines += ["", f"**Total findings:** {summ['total']}  ",
                  f"**Confirmed:** {summ['confirmed']}", ""]

        lines.append("## Findings")
        for i, f in enumerate(self.findings, 1):
            sev  = f.get("severity", "Info")
            cvss = f.get("cvss", "")
            lines += [
                f"",
                f"### {i}. {f.get('title','Finding')}",
                f"**Severity:** {sev}  **CVSS:** {cvss}  ",
                f"**URL:** `{f.get('url','')}`  ",
                f"**Parameter:** `{f.get('parameter','')}`  ",
                f"**Confirmed:** {f.get('confirmed', False)}",
                f"",
                f"**Evidence:**",
                f"```",
                str(f.get("evidence", ""))[:500],
                f"```",
                f"",
                f"**Remediation:** {f.get('remediation','')}",
            ]

        lines += ["", "## Assets", ""]
        for atype, vals in self.assets.items():
            lst = list(vals)[:20] if isinstance(vals, (set, list)) else []
            if lst:
                lines.append(f"**{atype.title()}** ({len(lst)} shown):")
                for v in lst:
                    lines.append(f"  - {v}")
                lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _write_html(self) -> Path:
        path = self._report_dir / f"nexsus_report_{self._ts}.html"
        summ = self._summary()
        html = _HTML_TEMPLATE.format(
            timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scope         = self.scope_summary,
            duration      = f"{round(self.scan_duration_s, 0):.0f}",
            total         = summ["total"],
            confirmed     = summ["confirmed"],
            critical      = summ["by_severity"].get("Critical", 0),
            high          = summ["by_severity"].get("High", 0),
            medium        = summ["by_severity"].get("Medium", 0),
            low           = summ["by_severity"].get("Low", 0),
            info          = summ["by_severity"].get("Info", 0),
            findings_rows = self._html_findings_rows(),
            assets_rows   = self._html_assets_rows(),
        )
        path.write_text(html, encoding="utf-8")
        return path

    def _html_findings_rows(self) -> str:
        rows = []
        for i, f in enumerate(self.findings):
            sev   = f.get("severity", "Info")
            color = _SEV_COLORS.get(sev, "#999")
            cvss  = f.get("cvss", "—")
            conf  = "✔" if f.get("confirmed") else "?"
            title = _esc(f.get("title", ""))
            url   = _esc(f.get("url", ""))
            param = _esc(f.get("parameter", ""))
            evid  = _esc(str(f.get("evidence", ""))[:400])
            remed = _esc(f.get("remediation", ""))
            rows.append(f"""
<tr>
  <td>{i+1}</td>
  <td><strong>{title}</strong><br><small>{conf}</small></td>
  <td><span class="sev-badge" style="background:{color}">{sev}</span></td>
  <td>{cvss}</td>
  <td><code>{url[:80]}</code></td>
  <td><code>{param}</code></td>
  <td><details><summary>Show</summary><pre>{evid}</pre>
      <p><strong>Fix:</strong> {remed}</p></details></td>
</tr>""")
        return "\n".join(rows)

    def _html_assets_rows(self) -> str:
        rows = []
        for atype, vals in self.assets.items():
            lst = list(vals)[:30] if isinstance(vals, (set, list)) else []
            if not lst:
                continue
            items = "".join(f"<li><code>{_esc(str(v))}</code></li>" for v in lst)
            rows.append(f"<tr><td><strong>{_esc(atype)}</strong></td>"
                        f"<td>{len(lst)} found<ul>{items}</ul></td></tr>")
        return "\n".join(rows)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _summary(self) -> dict:
        counter = Counter(f.get("severity", "Info") for f in self.findings)
        return {
            "total":       len(self.findings),
            "confirmed":   sum(1 for f in self.findings if f.get("confirmed")),
            "by_severity": dict(counter),
        }


def _esc(s: str) -> str:
    import html
    return html.escape(str(s))


# ── HTML template ─────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexsus Security Report</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d2b; --border: #2e3250;
    --text: #e0e0e0; --muted: #888; --accent: #6c63ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif;
         padding: 20px; }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 4px; }}
  h2 {{ color: #aaa; font-size: 1.1rem; margin: 24px 0 10px; text-transform: uppercase;
        letter-spacing: 1px; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
           padding: 16px 24px; min-width: 110px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .lbl {{ font-size: .75rem; color: var(--muted); margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .87rem; }}
  th {{ background: var(--surface); color: var(--accent); padding: 10px 12px;
        text-align: left; position: sticky; top: 0; }}
  td {{ border-bottom: 1px solid var(--border); padding: 10px 12px; vertical-align: top; }}
  tr:hover td {{ background: #1f2235; }}
  .sev-badge {{ border-radius: 4px; padding: 2px 8px; font-size: .75rem;
                font-weight: 700; color: #fff; white-space: nowrap; }}
  code {{ background: #252840; padding: 2px 6px; border-radius: 4px;
          font-size: .82rem; word-break: break-all; }}
  pre {{ background: #252840; padding: 10px; border-radius: 6px; overflow-x: auto;
         font-size: .8rem; margin: 6px 0; white-space: pre-wrap; word-break: break-all; }}
  details > summary {{ cursor: pointer; color: var(--accent); }}
  ul {{ padding-left: 18px; }}
  li {{ margin: 2px 0; }}
</style>
</head>
<body>
<h1>⚡ Nexsus Security Report</h1>
<div class="meta">
  Generated: {timestamp} &nbsp;|&nbsp;
  Scope: {scope} &nbsp;|&nbsp;
  Duration: {duration}s
</div>

<h2>Summary</h2>
<div class="cards">
  <div class="card"><div class="num">{total}</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num" style="color:#e74c3c">{critical}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:#e67e22">{high}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:#f1c40f">{medium}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:#3498db">{low}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num" style="color:#95a5a6">{info}</div><div class="lbl">Info</div></div>
  <div class="card"><div class="num" style="color:#2ecc71">{confirmed}</div><div class="lbl">Confirmed</div></div>
</div>

<h2>Findings</h2>
<table>
  <thead>
    <tr><th>#</th><th>Title</th><th>Severity</th><th>CVSS</th>
        <th>URL</th><th>Parameter</th><th>Evidence / Fix</th></tr>
  </thead>
  <tbody>
    {findings_rows}
  </tbody>
</table>

<h2>Assets Discovered</h2>
<table>
  <thead><tr><th>Type</th><th>Items</th></tr></thead>
  <tbody>{assets_rows}</tbody>
</table>
</body>
</html>"""

__all__ = ["ReportGenerator"]
