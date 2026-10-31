"""
Snowflake CoCo Data layer (simulated + extensible).

In a full deployment this module connects to freely accessible open-source
security vulnerability indexes / package datasets hosted on Snowflake and uses
CoCo to build pipelines that track known compromised packages and suspicious
publishing anomalies.

For the hackathon MVP we ship a realistic local dataset that mirrors the shape
of public vulnerability feeds (OSV, GitHub Advisories, CISA KEV style) so the
rest of the agent works offline and can be swapped for real Snowflake queries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

# Sample data that would normally come from Snowflake Marketplace / CoCo pipelines
SAMPLE_COMPROMISED = [
    {
        "package": "event-stream",
        "ecosystem": "npm",
        "versions": ["3.3.6"],
        "severity": "critical",
        "cve": "CVE-2018-16469",
        "summary": "Malicious code stole cryptocurrency wallets",
        "published": "2018-11-26",
        "source": "historical-supply-chain",
    },
    {
        "package": "ua-parser-js",
        "ecosystem": "npm",
        "versions": ["0.7.29", "0.8.0", "1.0.0"],
        "severity": "critical",
        "cve": "CVE-2021-27292",
        "summary": "Compromised maintainer account injected crypto-mining and password-stealing code",
        "published": "2021-10-22",
        "source": "github-advisories",
    },
    {
        "package": "node-ipc",
        "ecosystem": "npm",
        "versions": ["9.2.2", "10.1.1", "11.0.0"],
        "severity": "critical",
        "cve": "CVE-2022-23812",
        "summary": "Protestware that wiped files based on geolocation",
        "published": "2022-03-16",
        "source": "osv",
    },
    {
        "package": "ctx",
        "ecosystem": "pypi",
        "versions": ["0.1.2", "0.1.4", "0.2.1"],
        "severity": "critical",
        "cve": None,
        "summary": "Typosquat that exfiltrated environment variables (AWS keys etc.)",
        "published": "2022-05-24",
        "source": "pypi-security",
    },
    {
        "package": "colors",
        "ecosystem": "npm",
        "versions": ["1.4.1", "1.4.2"],
        "severity": "high",
        "cve": None,
        "summary": "Maintainer sabotage – infinite loop / broken output",
        "published": "2022-01-09",
        "source": "npm-incidents",
    },
    {
        "package": "faker",
        "ecosystem": "npm",
        "versions": ["6.6.6"],
        "severity": "high",
        "cve": None,
        "summary": "Intentional breakage by maintainer",
        "published": "2022-01-05",
        "source": "npm-incidents",
    },
    {
        "package": "python-dateutil",
        "ecosystem": "pypi",
        "versions": ["2.8.1"],  # example of a version that had issues in some forks
        "severity": "medium",
        "cve": None,
        "summary": "Watch for unexpected republishing patterns on popular date libraries",
        "published": "2020-01-01",
        "source": "anomaly-detection",
    },
]


@dataclass
class VulnRecord:
    package: str
    ecosystem: str
    versions: list[str]
    severity: str
    cve: str | None
    summary: str
    published: str
    source: str

    def matches(self, name: str, version: str | None = None) -> bool:
        if self.package.lower() != name.lower():
            return False
        if version is None:
            return True
        return version in self.versions or any(version.startswith(v) for v in self.versions)


class VulnDatabase:
    """
    Local stand-in for a Snowflake CoCo-backed vulnerability index.

    In production you would replace `load()` with CoCo-generated SQL against
    Snowflake Marketplace datasets (OSV, GitHub Advisories, etc.).
    """

    def __init__(self, data: list[dict[str, Any]] | None = None):
        raw = data or SAMPLE_COMPROMISED
        self.records = [VulnRecord(**r) for r in raw]

    def lookup(self, package: str, version: str | None = None) -> list[VulnRecord]:
        return [r for r in self.records if r.matches(package, version)]

    def is_known_bad(self, package: str, version: str | None = None) -> bool:
        return len(self.lookup(package, version)) > 0

    def all_packages(self) -> list[str]:
        return sorted({r.package for r in self.records})

    def export_json(self, path: Path) -> None:
        path.write_text(json.dumps([asdict(r) for r in self.records], indent=2))

    @classmethod
    def from_snowflake_coco(cls) -> "VulnDatabase":
        """
        Placeholder for real CoCo integration.

        Example CoCo prompt a team would use:
        "Create a pipeline that keeps a daily snapshot of known compromised
         packages from OSV + GitHub Advisories and flags packages with
         anomalous publish frequency."
        """
        # Real implementation would run CoCo-generated SQL here.
        return cls()


def get_default_db() -> VulnDatabase:
    return VulnDatabase()
