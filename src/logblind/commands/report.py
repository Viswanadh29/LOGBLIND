"""The `logblind report` command — generates HTML/JSON reports from scan results."""

from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

import typer

from logblind.utils.console import console, print_banner, print_error, print_success

app = typer.Typer(help="Generate detailed HTML or JSON analysis reports.")


@app.callback(invoke_without_command=True)
def report(
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Exported audit policy CSV (offline mode).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file path.")] = Path("logblind_report.html"),
    format: Annotated[str, typer.Option("--format", help="Format: html, json.")] = "html",
    techniques: Annotated[Optional[str], typer.Option("--techniques", "-t", help="Filter ATT&CK IDs (comma-separated).")] = None,
) -> None:
    """Generate a detailed report from a scan. Defaults to HTML."""
    import platform

    from logblind.collectors.auditpol import AuditPolCollector, AuditPolError
    from logblind.collectors.registry import RegistryCollector
    from logblind.collectors.file_import import FileImportCollector, FileImportError
    from logblind.knowledge_base.loader import KnowledgeBaseLoader
    from logblind.analyzer.gap_detector import GapDetector
    from logblind.analyzer.coverage_scorer import CoverageScorer
    from logblind.reporters.html_reporter import HTMLReporter
    from logblind.reporters.json_reporter import JSONReporter

    print_banner()

    # Step 1: Collect audit policy
    with console.status("[bold green]Collecting audit policy...[/bold green]"):
        if file:
            console.print(f"  [cyan]>>[/cyan] Reading policy from file: [cyan]{file}[/cyan]")
            try:
                policy_snapshot = FileImportCollector().collect(file)
            except FileImportError as e:
                print_error(str(e))
                raise typer.Exit(code=1)
        else:
            if platform.system() != "Windows":
                print_error(
                    "LogBlind requires Windows to scan the local audit policy.\n"
                    "  Use [cyan]--file[/cyan] to analyze an exported policy CSV on any platform."
                )
                raise typer.Exit(code=1)
            console.print("  [cyan]>>[/cyan] Scanning local Windows audit policy...")
            try:
                policy_snapshot = AuditPolCollector().collect()
                registry_snapshot = RegistryCollector().collect()
                policy_snapshot.merge_registry(registry_snapshot)
            except AuditPolError as e:
                print_error(str(e))
                raise typer.Exit(code=1)

    console.print(f"  [green]OK[/green] Collected [bold]{len(policy_snapshot.subcategories)}[/bold] audit subcategories\n")

    # Step 2: Load knowledge base
    with console.status("[bold green]Loading knowledge base...[/bold green]"):
        kb = KnowledgeBaseLoader().load()

    technique_filter = [t.strip() for t in techniques.split(",")] if techniques else None
    console.print(f"  [green]OK[/green] Loaded [bold]{len(kb.techniques)}[/bold] ATT&CK technique mappings\n")

    # Step 3: Analyze
    with console.status("[bold green]Analyzing detection coverage...[/bold green]"):
        gap_results = GapDetector().analyze(policy_snapshot, kb, technique_filter=technique_filter)
        coverage_report = CoverageScorer().score(gap_results)

    # Step 4: Generate report
    if format == "json":
        if not str(output).endswith(".json"):
            output = output.with_suffix(".json")
        content = JSONReporter().render(coverage_report, gap_results)
    else:
        if not str(output).endswith(".html"):
            output = output.with_suffix(".html")
        content = HTMLReporter().render(coverage_report, gap_results)

    output.write_text(content, encoding="utf-8")
    print_success(f"Report saved to [bold cyan]{output}[/bold cyan]")

    if format == "html":
        console.print(f"  Open in browser: [cyan]start {output}[/cyan]")
