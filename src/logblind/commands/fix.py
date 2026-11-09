"""The `logblind fix` command — generates PowerShell remediation scripts."""

from pathlib import Path
from typing import Optional
from typing_extensions import Annotated

import typer

from logblind.utils.console import console, print_banner, print_error, print_success

app = typer.Typer(help="Generate PowerShell scripts to fix audit configuration gaps.")


@app.callback(invoke_without_command=True)
def fix(
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Exported audit policy CSV (offline mode).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output path for the fix script.")] = Path("logblind_fix.ps1"),
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Generate script in preview-only mode.")] = False,
    techniques: Annotated[Optional[str], typer.Option("--techniques", "-t", help="Filter ATT&CK IDs (comma-separated).")] = None,
) -> None:
    """Generate PowerShell commands to close audit gaps. Does NOT execute changes.

    This scans your audit configuration (or reads an exported CSV), detects gaps,
    then generates a ready-to-run .ps1 remediation script.
    """
    import platform

    from logblind.collectors.auditpol import AuditPolCollector, AuditPolError
    from logblind.collectors.registry import RegistryCollector
    from logblind.collectors.file_import import FileImportCollector, FileImportError
    from logblind.knowledge_base.loader import KnowledgeBaseLoader
    from logblind.analyzer.gap_detector import GapDetector
    from logblind.analyzer.coverage_scorer import CoverageScorer
    from logblind.analyzer.fix_generator import FixGenerator

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

    # Step 4: Generate fix script
    if not coverage_report.critical_gaps and coverage_report.overall_score >= 80:
        console.print("[bold green][+] No critical gaps found.[/bold green] Your audit configuration looks solid.")
        raise typer.Exit(code=0)

    generator = FixGenerator()
    script = generator.generate(coverage_report, dry_run=dry_run)

    # Write the script
    output.write_text(script, encoding="utf-8")
    print_success(f"Fix script saved to [bold cyan]{output}[/bold cyan]")

    # Summary
    console.print("")
    console.print("[bold]What to do next:[/bold]")
    console.print(f"  1. Review the script:  [cyan]Get-Content {output}[/cyan]")
    console.print(f"  2. Preview changes:    [cyan].\\{output} -WhatIf[/cyan]")
    console.print(f"  3. Apply fixes:        [cyan].\\{output}[/cyan]  (as Administrator)")
    console.print(f"  4. Verify:             [cyan]logblind scan[/cyan]")
