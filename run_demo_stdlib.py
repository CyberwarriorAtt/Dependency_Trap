#!/usr/bin/env python3
"""
Pure-stdlib demo of DependencyTrap so judges can see the full flow
even when external packages cannot be installed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make src importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dependencytrap.vuln_data import get_default_db
from dependencytrap.solana_agent import SolanaAgentClient
from dependencytrap.mocks import ensure_mock_packages
from dependencytrap.gemma_analyzer import GemmaAnalyzer

def main():
    print("=" * 60)
    print("DependencyTrap – End-to-End Demo (stdlib mode)")
    print("=" * 60)

    # 1. Register agent on Solana (simulated)
    print("\n[1] Registering security agent on Solana Agent Registry...")
    client = SolanaAgentClient(simulation=True)
    identity = client.register_agent()
    print(f"    Agent ID : {identity.agent_id}")
    print(f"    Tx sig   : {identity.tx_signature[:40]}...")

    # 2. Load vulnerability index (Snowflake CoCo style)
    print("\n[2] Loading vulnerability index (Snowflake CoCo style data)...")
    db = get_default_db()
    print(f"    Loaded {len(db.records)} known compromised / suspicious packages")

    # 3. Generate mock vulnerable samples
    print("\n[3] Writing mock packages with subtle security flaws...")
    mock_dir = ensure_mock_packages()
    print(f"    Samples in {mock_dir}/")

    # 4. Analyze with Gemma (will use fallback if Ollama unavailable)
    print("\n[4] Analyzing mock files with Gemma 4 analyzer...")
    analyzer = GemmaAnalyzer()
    for sample in sorted(mock_dir.glob("*.py")):
        code = sample.read_text()
        result = analyzer.analyze_code(code, filename=sample.name)
        print(f"\n    --- {sample.name} ---")
        print(f"    Risk     : {result.get('risk_level')}")
        print(f"    Summary  : {result.get('summary')}")
        for f in result.get("findings", [])[:2]:
            print(f"      • [{f.get('severity')}] {f.get('title')}")
            print(f"        {f.get('explanation')[:100]}...")

        # Log validation on Solana
        client.log_validation(
            package=sample.name,
            version=None,
            risk_level=result.get("risk_level", "unknown"),
            findings_count=len(result.get("findings", [])),
            summary=result.get("summary", "")[:120],
        )

    # 5. Package-level checks
    print("\n[5] Checking known package names against index...")
    for name, ver in [("event-stream", "3.3.6"), ("ctx", "0.1.4"), ("requests", "2.32.0")]:
        hits = db.lookup(name, ver)
        status = "KNOWN BAD" if hits else "clean"
        print(f"    {name}@{ver or '*'} → {status}")
        if hits:
            client.log_validation(
                package=name,
                version=ver,
                risk_level=hits[0].severity,
                findings_count=len(hits),
                summary=hits[0].summary[:120],
            )

    print("\n" + "=" * 60)
    print("Demo complete.")
    print("Inspect onchain_txns/ for agent identity + validation records.")
    print("See README.md for how each mandatory track is satisfied.")
    print("=" * 60)

if __name__ == "__main__":
    main()
