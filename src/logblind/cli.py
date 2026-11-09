"""Root CLI application for LogBlind."""

from typing import Optional
from typing_extensions import Annotated
import typer

from logblind import __version__
from logblind.commands import scan, fix, report, export
from logblind.utils.console import console

app = typer.Typer(
    name="logblind",
    help=(
        "🛡️ LogBlind — Windows Log Configuration Auditor for Lateral Movement Blind Spots.\n\n"
        "Maps your Windows audit policy against MITRE ATT&CK lateral movement techniques "
        "to reveal exactly what you can and cannot detect."
    ),
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

app.add_typer(scan.app, name="scan")
app.add_typer(fix.app, name="fix")
app.add_typer(report.app, name="report")
app.add_typer(export.app, name="export")


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]LogBlind[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-V", help="Show version.", callback=version_callback, is_eager=True),
    ] = None,
) -> None:
    """LogBlind — see what your logs are blind to."""
