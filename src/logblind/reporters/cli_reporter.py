"""CLI reporter -- renders analysis results as beautiful Rich terminal output."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from logblind.models.analysis import CoverageReport, TechniqueGapResult
from logblind.utils.console import console
from logblind.utils.validators import severity_to_int


class CLIReporter:
    """Renders coverage analysis as Rich terminal output."""

    def render(
        self,
        report: CoverageReport,
        gap_results: list[TechniqueGapResult],
        verbose: bool = False,
        min_severity: str | None = None,
    ) -> None:
        """Render the full analysis to the terminal."""
        self._render_summary(report)
        self._render_technique_table(gap_results)
        self._render_critical_gaps(report, min_severity)
        if verbose:
            self._render_verbose(gap_results)
        console.print("\nRun [bold cyan]logblind fix[/bold cyan] to generate a remediation script.")

    def _render_summary(self, report: CoverageReport) -> None:
        score = report.overall_score
        color = report.risk_color
        filled = int(score / 5)
        bar = f"[{color}]{'#' * filled}{'-' * (20 - filled)}[/{color}]"

        summary = Text()
        summary.append("Overall Coverage Score: ", style="bold")
        summary.append(f"{score:.0f}% ", style=f"bold {color}")

        console.print(Panel(summary, border_style=color))
        console.print(f"  {bar} [{color}][{report.risk_level}][/{color}]")
        console.print(
            f"\n  Techniques: [bold]{report.total_techniques}[/bold] | "
            f"[green]Covered: {report.covered_count}[/green] | "
            f"[yellow]Partial: {report.partial_count}[/yellow] | "
            f"[red]Blind: {report.blind_count}[/red]\n"
        )

    def _render_technique_table(self, gap_results: list[TechniqueGapResult]) -> None:
        table = Table(
            title="Lateral Movement Detection Coverage",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("ATT&CK ID", style="bold", width=12)
        table.add_column("Technique", width=35)
        table.add_column("Coverage", justify="right", width=10)
        table.add_column("Status", justify="center", width=12)
        table.add_column("Gaps", justify="center", width=6)

        for r in gap_results:
            c = r.status.color
            table.add_row(
                r.technique_id,
                r.technique_name,
                f"[{c}]{r.coverage_percent:.0f}%[/{c}]",
                f"{r.status.symbol} [{c}]{r.status.value}[/{c}]",
                f"[red]{len(r.gaps)}[/red]" if r.gaps else "[green]0[/green]",
            )
        console.print(table)
        console.print()

    def _render_critical_gaps(self, report: CoverageReport, min_severity: str | None) -> None:
        gaps = report.critical_gaps
        if min_severity:
            min_level = severity_to_int(min_severity)
            imp_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
            gaps = [g for g in gaps if imp_map.get(g.importance, 0) >= min_level]

        if not gaps:
            console.print("[bold green][+] No critical gaps found![/bold green]")
            return

        console.print("[bold red][-] CRITICAL GAPS FOUND:[/bold red]\n")
        for gap in gaps:
            ic = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow"}.get(
                gap.importance, "dim"
            )
            console.print(f"  [{ic}]> Event ID {gap.event_id}[/{ic}] ({gap.channel})")
            console.print(f"    {gap.condition}")
            console.print(f"    [dim]Reason:[/dim] {gap.reason}")
            if gap.fix_command and not gap.fix_command.startswith("#"):
                console.print(f"    [cyan]Fix:[/cyan] {gap.fix_command}")
            console.print()

    def _render_verbose(self, gap_results: list[TechniqueGapResult]) -> None:
        console.print("\n[bold]=== Detailed Technique Analysis ===[/bold]\n")
        for r in gap_results:
            tree = Tree(
                f"{r.status.symbol} [bold]{r.technique_id}[/bold] -- {r.technique_name} "
                f"[{r.status.color}]({r.coverage_percent:.0f}%)[/{r.status.color}]"
            )
            if r.gaps:
                gb = tree.add("[red]Missing Detections[/red]")
                for g in r.gaps:
                    gb.add(
                        f"EID {g.event_id} ({g.channel}): {g.condition}\n  [dim]{g.reason}[/dim]"
                    )
            if r.notes:
                nb = tree.add("[cyan]Notes[/cyan]")
                for n in r.notes:
                    nb.add(n)
            console.print(tree)
            console.print()
