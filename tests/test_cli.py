"""End-to-end tests for the LogBlind CLI."""

import re
from typer.testing import CliRunner
from logblind.cli import app

runner = CliRunner()

# Strip ANSI escape sequences for reliable assertions
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI_RE.sub("", text)


class TestCLI:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        plain = _plain(result.stdout)
        assert "LogBlind" in plain
        assert "0.2.0" in plain

    def test_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.stdout

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
