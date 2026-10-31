"""
Core scanning engine that ties Gemma 4 + vulnerability data + Solana logging together.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .gemma_analyzer import GemmaAnalyzer
from .vuln_data import VulnDatabase, get_default_db
from .solana_agent import SolanaAgentClient

console = Console()


class DependencyTrapScanner:
    def __init__(
        self,
        gemma: GemmaAnalyzer | None = None,
        vuln_db: VulnDatabase | None = None,
        solana: SolanaAgentClient | None = None,
    ):
        self.gemma = gemma or GemmaAnalyzer()
        self.vuln_db = vuln_db or get_default_db()
        self.solana = solana or SolanaAgentClient(simulation=True)

        # Ensure the agent is registered once
        self.solana.register_agent()

    def scan_file(self, path: Path) -> dict[str, Any]:
        """Scan a single source file with Gemma and cross-check known bad packages."""
        code = path.read_text(encoding="utf-8", errors="replace")
        analysis = self.gemma.analyze_code(code, filename=path.name)

        # Also look for import / require patterns that match known bad packages
        package_hits = self._detect_known_bad_imports(code)

        result = {
            "target": str(path),
            "type": "file",
            "gemma_analysis": analysis,
            "known_compromised_packages": package_hits,
            "overall_risk": self._combine_risk(
                analysis.get("risk_level", "none"), package_hits
            ),
        }

        # Log to Solana (simulated or real)
        self.solana.log_validation(
            package=path.name,
            version=None,
            risk_level=result["overall_risk"],
            findings_count=len(analysis.get("findings", [])) + len(package_hits),
            summary=analysis.get("summary", "")[:200],
        )
        return result

    def scan_package_name(
        self, name: str, version: str | None = None
    ) -> dict[str, Any]:
        """Check a package name against the vulnerability index + ask Gemma for context."""
        records = self.vuln_db.lookup(name, version)
        explanation = self.gemma.explain_package_risk(
            name, version, [r.summary for r in records]
        )

        risk = "critical" if any(r.severity == "critical" for r in records) else \
               "high" if records else "low"

        result = {
            "target": name,
            "version": version,
            "type": "package",
            "known_records": [
                {
                    "severity": r.severity,
                    "cve": r.cve,
                    "summary": r.summary,
                    "source": r.source,
                }
                for r in records
            ],
            "gemma_explanation": explanation.get("explanation"),
            "overall_risk": risk,
        }

        self.solana.log_validation(
            package=name,
            version=version,
            risk_level=risk,
            findings_count=len(records),
            summary=explanation.get("explanation", "")[:200],
        )
        return result

    def _detect_known_bad_imports(self, code: str) -> list[dict[str, Any]]:
        hits = []
        lower = code.lower()
        for pkg in self.vuln_db.all_packages():
            # very light heuristic – good enough for demo
            if f'"{pkg}"' in lower or f"'{pkg}'" in lower or f"import {pkg}" in lower \
               or f"from {pkg}" in lower or f"require('{pkg}')" in lower:
                records = self.vuln_db.lookup(pkg)
                if records:
                    hits.append({
                        "package": pkg,
                        "severity": records[0].severity,
                        "summary": records[0].summary,
                    })
        return hits

    def _combine_risk(self, gemma_risk: str, package_hits: list) -> str:
        order = ["none", "low", "medium", "high", "critical"]
        current = gemma_risk if gemma_risk in order else "medium"
        for hit in package_hits:
            if order.index(hit["severity"]) > order.index(current):
                current = hit["severity"]
        return current

    def pretty_print(self, result: dict[str, Any]) -> None:
        title = f"Scan: {result.get('target')}"
        risk = result.get("overall_risk", "unknown").upper()
        color = {
            "CRITICAL": "red",
            "HIGH": "dark_orange",
            "MEDIUM": "yellow",
            "LOW": "green",
            "NONE": "bright_black",
        }.get(risk, "white")

        console.print(Panel(f"[{color}]Risk Level: {risk}[/{color}]", title=title))

        if result.get("type") == "file":
            analysis = result["gemma_analysis"]
            console.print(f"[bold]Summary:[/bold] {analysis.get('summary')}")
            console.print(
                f"[bold]Junior-friendly:[/bold] {analysis.get('junior_friendly_summary')}"
            )

            table = Table(title="Findings")
            table.add_column("Severity")
            table.add_column("Title")
            table.add_column("Explanation")
            for f in analysis.get("findings", []):
                table.add_row(
                    f.get("severity", ""),
                    f.get("title", ""),
                    f.get("explanation", "")[:120] + "...",
                )
            console.print(table)

            if result.get("known_compromised_packages"):
                console.print("\n[bold red]Known compromised packages referenced:[/bold red]")
                for h in result["known_compromised_packages"]:
                    console.print(f"  • {h['package']} ({h['severity']}) – {h['summary']}")

        else:  # package
            if result.get("known_records"):
                console.print("[bold]Matches in vulnerability index:[/bold]")
                for r in result["known_records"]:
                    console.print(
                        f"  • [{r['severity']}] {r.get('cve') or 'no-CVE'} – {r['summary']}"
                    )
            console.print(f"\n[bold]Gemma explanation:[/bold]\n{result.get('gemma_explanation')}")
