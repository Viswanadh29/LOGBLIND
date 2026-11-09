"""The `logblind export` command — ATT&CK Navigator layer export."""

from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

import typer

from logblind.utils.console import console, print_banner, print_error, print_success

app = typer.Typer(help="Export results as a MITRE ATT&CK Navigator layer.")


@app.callback(invoke_without_command=True)
def export(
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Exported audit policy CSV (offline mode).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output Navigator layer JSON.")] = Path("logblind_navigator.json"),
    layer_name: Annotated[str, typer.Option("--name", "-n", help="Layer name in Navigator.")] = "LogBlind Coverage",
    techniques: Annotated[Optional[str], typer.Option("--techniques", "-t", help="Filter ATT&CK IDs (comma-separated).")] = None,
) -> None:
    """Export scan results as a MITRE ATT&CK Navigator layer JSON.

    The generated JSON can be imported into ATT&CK Navigator at:
    https://mitre-attack.github.io/attack-navigator/
    """
    import platform

    from logblind.collectors.auditpol import AuditPolCollector, AuditPolError
    from logblind.collectors.registry import RegistryCollector
    from logblind.collectors.file_import import FileImportCollector, FileImportError
    from logblind.knowledge_base.loader import KnowledgeBaseLoader
    from logblind.analyzer.gap_detector import GapDetector
    from logblind.analyzer.coverage_scorer import CoverageScorer
    from logblind.reporters.navigator_export import NavigatorExporter

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

    # Step 4: Export Navigator layer
    exporter = NavigatorExporter()
    layer_json = exporter.export(coverage_report, gap_results, layer_name=layer_name)
    output.write_text(layer_json, encoding="utf-8")
    print_success(f"Navigator layer saved to [bold cyan]{output}[/bold cyan]")

    console.print("")
    console.print("[bold]Import into ATT&CK Navigator:[/bold]")
    console.print("  1. Open [cyan]https://mitre-attack.github.io/attack-navigator/[/cyan]")
    console.print("  2. Click [bold]Open Existing Layer[/bold] > [bold]Upload from local[/bold]")
    console.print(f"  3. Select [cyan]{output}[/cyan]")
