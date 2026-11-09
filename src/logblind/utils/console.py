"""Centralized Rich console configuration for LogBlind.

All terminal output should use these console instances to ensure
consistent styling and testability.
"""

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from logblind import __version__

# Force UTF-8 output on Windows to avoid cp1252 emoji encoding errors
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    # Enable UTF-8 mode for the console
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

# Main console for standard output
console = Console(force_terminal=True)

# Error console for stderr
err_console = Console(stderr=True, force_terminal=True)


def print_error(message: str) -> None:
    """Print an error message to stderr."""
    err_console.print(f"[bold red]X Error:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]>[/bold green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]![/bold yellow] {message}")


def print_banner() -> None:
    """Print the LogBlind startup banner."""
    banner_text = Text()
    banner_text.append("LogBlind", style="bold cyan")
    banner_text.append(f" v{__version__}\n", style="dim")
    banner_text.append("Windows Lateral Movement Detection Auditor", style="italic")

    console.print(Panel(banner_text, border_style="cyan", padding=(1, 2)))
    console.print()
