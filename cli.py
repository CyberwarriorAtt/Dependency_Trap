#!/usr/bin/env python3
"""
DependencyTrap CLI

Usage examples:
  python -m dependencytrap.cli scan-file path/to/file.py
  python -m dependencytrap.cli scan-package event-stream --version 3.3.6
  python -m dependencytrap.cli demo
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from .scanner import DependencyTrapScanner
from .solana_agent import SolanaAgentClient

app = typer.Typer(help="DependencyTrap – Open-Source Dependency Trap Code Guard")
console = Console()


@app.command()
def scan_file(
    path: Path = typer.Argument(..., exists=True, dir_okay=False),
    model: str = typer.Option("gemma4:e4b", help="Ollama model tag for Gemma 4"),
):
    """Scan a source file with Gemma 4 and log results on Solana."""
    from .gemma_analyzer import GemmaAnalyzer

    scanner = DependencyTrapScanner(gemma=GemmaAnalyzer(model=model))
    result = scanner.scan_file(path)
    scanner.pretty_print(result)


@app.command()
def scan_package(
    name: str,
    version: str = typer.Option(None, help="Optional version to check"),
    model: str = typer.Option("gemma4:e4b", help="Ollama model tag"),
):
    """Check a package name against known compromised indexes + Gemma explanation."""
    from .gemma_analyzer import GemmaAnalyzer

    scanner = DependencyTrapScanner(gemma=GemmaAnalyzer(model=model))
    result = scanner.scan_package_name(name, version)
    scanner.pretty_print(result)


@app.command()
def demo():
    """Run a full end-to-end demo (mock vulnerable files + package checks)."""
    from .gemma_analyzer import GemmaAnalyzer
    from .mocks import ensure_mock_packages

    console.print("[bold magenta]DependencyTrap End-to-End Demo[/bold magenta]\n")

    # 1. Register agent
    client = SolanaAgentClient(simulation=True)
    identity = client.register_agent()
    console.print(f"Agent registered → {identity.agent_id}\n")

    # 2. Ensure mock vulnerable samples exist
    mock_dir = ensure_mock_packages()
    console.print(f"Mock packages ready in {mock_dir}\n")

    scanner = DependencyTrapScanner(
        gemma=GemmaAnalyzer(),
        solana=client,
    )

    # 3. Scan a couple of mock files
    for sample in sorted(mock_dir.glob("*.py"))[:2]:
        console.rule(f"Scanning {sample.name}")
        result = scanner.scan_file(sample)
        scanner.pretty_print(result)
        console.print()

    # 4. Check known-bad package names
    for pkg, ver in [("event-stream", "3.3.6"), ("ctx", "0.1.4"), ("lodash", None)]:
        console.rule(f"Package check: {pkg}")
        result = scanner.scan_package_name(pkg, ver)
        scanner.pretty_print(result)
        console.print()

    console.print(
        Panel_success(
            "Demo complete. Check the onchain_txns/ folder for simulated "
            "Solana identity + validation records. "
            "Swap simulation=False + real keypair for live chain writes."
        )
    )


def Panel_success(msg: str):
    from rich.panel import Panel
    return Panel(msg, style="green")


if __name__ == "__main__":
    app()
