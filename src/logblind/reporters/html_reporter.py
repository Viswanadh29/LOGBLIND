"""HTML reporter — generates self-contained HTML reports with coverage heatmap."""

from __future__ import annotations

from datetime import datetime, timezone

from logblind import __version__
from logblind.models.analysis import CoverageReport, TechniqueGapResult


class HTMLReporter:
    """Generates a self-contained HTML report with interactive coverage heatmap."""

    def render(
        self,
        report: CoverageReport,
        gap_results: list[TechniqueGapResult],
    ) -> str:
        """Generate a complete HTML report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        techniques_html = self._build_technique_rows(gap_results)
        gaps_html = self._build_gaps_section(report)
        score = report.overall_score
        risk = report.risk_level
        risk_color = {"LOW RISK": "#22c55e", "MEDIUM RISK": "#eab308", "HIGH RISK": "#ef4444"}.get(risk, "#eab308")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LogBlind Report — {timestamp}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
    --green: #22c55e; --yellow: #eab308; --red: #ef4444; --cyan: #06b6d4;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.75rem; margin-bottom: .25rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
  .score-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 2rem; text-align: center; margin-bottom: 2rem;
  }}
  .score {{ font-size: 3.5rem; font-weight: 800; }}
  .risk {{ font-size: 1.1rem; font-weight: 600; margin-top: .5rem; }}
  .bar-bg {{ background: #334155; border-radius: 8px; height: 20px; margin: 1rem auto; max-width: 400px; }}
  .bar-fill {{ height: 100%; border-radius: 8px; transition: width .5s; }}
  .stats {{ display: flex; justify-content: center; gap: 2rem; margin-top: 1rem; }}
  .stat {{ text-align: center; }}
  .stat-num {{ font-size: 1.5rem; font-weight: 700; }}
  .stat-label {{ color: var(--muted); font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
  th {{ background: #0f172a; padding: .75rem 1rem; text-align: left; font-weight: 600; border-bottom: 2px solid var(--border); }}
  td {{ padding: .75rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: rgba(6, 182, 212, 0.05); }}
  .status-covered {{ color: var(--green); font-weight: 700; }}
  .status-partial {{ color: var(--yellow); font-weight: 700; }}
  .status-blind {{ color: var(--red); font-weight: 700; }}
  .gap-card {{
    background: var(--surface); border-left: 4px solid var(--red);
    padding: 1rem 1.25rem; margin-bottom: .75rem; border-radius: 0 8px 8px 0;
  }}
  .gap-header {{ font-weight: 600; margin-bottom: .25rem; }}
  .gap-reason {{ color: var(--muted); font-size: .9rem; }}
  .gap-fix {{ font-family: 'Cascadia Code', monospace; background: #0f172a; padding: .4rem .75rem; border-radius: 4px; margin-top: .5rem; font-size: .85rem; color: var(--cyan); display: inline-block; }}
  .section-title {{ font-size: 1.25rem; font-weight: 700; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; }}
  .footer {{ color: var(--muted); text-align: center; margin-top: 3rem; font-size: .8rem; }}
  a {{ color: var(--cyan); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
  <h1>LogBlind Audit Coverage Report</h1>
  <p class="subtitle">Generated {timestamp} &bull; LogBlind v{__version__}</p>

  <div class="score-card">
    <div class="score" style="color: {risk_color}">{score:.0f}%</div>
    <div class="risk" style="color: {risk_color}">{risk}</div>
    <div class="bar-bg"><div class="bar-fill" style="width: {score}%; background: {risk_color}"></div></div>
    <div class="stats">
      <div class="stat"><div class="stat-num">{report.total_techniques}</div><div class="stat-label">Techniques</div></div>
      <div class="stat"><div class="stat-num status-covered">{report.covered_count}</div><div class="stat-label">Covered</div></div>
      <div class="stat"><div class="stat-num status-partial">{report.partial_count}</div><div class="stat-label">Partial</div></div>
      <div class="stat"><div class="stat-num status-blind">{report.blind_count}</div><div class="stat-label">Blind</div></div>
    </div>
  </div>

  <div class="section-title">Technique Coverage</div>
  <table>
    <thead><tr><th>ATT&amp;CK ID</th><th>Technique</th><th>Coverage</th><th>Status</th><th>Gaps</th></tr></thead>
    <tbody>
{techniques_html}
    </tbody>
  </table>

  <div class="section-title">Critical Gaps ({len(report.critical_gaps)})</div>
{gaps_html}

  <div class="footer">
    <p>LogBlind v{__version__} &bull; <a href="https://github.com/VISWANADH/logblind">github.com/VISWANADH/logblind</a></p>
    <p>Report generated from audit policy analysis. Review and apply fixes responsibly.</p>
  </div>
</div>
</body>
</html>"""

    def _build_technique_rows(self, results: list[TechniqueGapResult]) -> str:
        rows = []
        for r in results:
            status_class = f"status-{r.status.value.lower()}"
            rows.append(
                f"      <tr>"
                f"<td><a href='https://attack.mitre.org/techniques/{r.technique_id.replace('.', '/')}/'>{r.technique_id}</a></td>"
                f"<td>{r.technique_name}</td>"
                f"<td>{r.coverage_percent:.0f}%</td>"
                f"<td class='{status_class}'>{r.status.symbol} {r.status.value}</td>"
                f"<td>{len(r.gaps)}</td>"
                f"</tr>"
            )
        return "\n".join(rows)

    def _build_gaps_section(self, report: CoverageReport) -> str:
        if not report.critical_gaps:
            return '  <p style="color: var(--green); font-weight: 600;">No critical gaps found!</p>'
        cards = []
        for gap in report.critical_gaps:
            fix_html = ""
            if gap.fix_command:
                fix_html = f'<div class="gap-fix">{gap.fix_command}</div>'
            cards.append(
                f'  <div class="gap-card">'
                f'<div class="gap-header">Event ID {gap.event_id} ({gap.channel})</div>'
                f'<div>{gap.condition}</div>'
                f'<div class="gap-reason">{gap.reason}</div>'
                f'{fix_html}'
                f'</div>'
            )
        return "\n".join(cards)
