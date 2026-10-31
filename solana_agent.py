"""
Solana Agent Identity integration.

Registers the DependencyTrap security agent on the Solana Agent Registry
(Metaplex MPL Agent Registry / 8004-style) and logs every validation result
on-chain so the audit trail of malicious packages is untamperable.

For the hackathon we provide:
1. A clear simulation that produces realistic transaction signatures and
   agent identity records (so judges can see the flow).
2. Documented real integration path using @metaplex-foundation/mpl-agent-registry
   or 8004-solana SDK once a funded keypair is available.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    console = Console()
except ImportError:
    class _Dummy:
        def print(self, *a, **k): print(*a)
    console = _Dummy()


# Simulated program IDs (real ones would come from Metaplex / 8004 docs)
AGENT_REGISTRY_PROGRAM = "AgentRegistry1111111111111111111111111111111"
VALIDATION_LOG_PROGRAM = "DepTrapLog11111111111111111111111111111111"


@dataclass
class AgentIdentity:
    agent_id: str
    name: str
    description: str
    registration_uri: str
    owner: str
    registered_at: str
    tx_signature: str
    onchain: bool = False


@dataclass
class ValidationRecord:
    record_id: str
    agent_id: str
    package: str
    version: str | None
    risk_level: str
    findings_count: int
    summary: str
    timestamp: str
    tx_signature: str
    onchain: bool = False


class SolanaAgentClient:
    """
    Client that can operate in two modes:

    - simulation=True  (default): produces deterministic-looking identities
      and tx signatures so the full demo works offline.
    - simulation=False: intended for real SDK calls (requires keypair + SOL).
    """

    def __init__(self, simulation: bool = True, keypair_path: str | None = None):
        self.simulation = simulation
        self.keypair_path = keypair_path
        self._identity: AgentIdentity | None = None
        self._log_dir = Path("onchain_txns")
        self._log_dir.mkdir(exist_ok=True)

    def register_agent(
        self,
        name: str = "DependencyTrap Security Agent",
        description: str = (
            "Autonomous open-source supply-chain guardian. "
            "Scans packages with Gemma 4, cross-checks known compromised indexes, "
            "and writes immutable validation records on Solana."
        ),
        metadata_uri: str = "https://github.com/your-org/DependencyTrap/blob/main/agent-card.json",
    ) -> AgentIdentity:
        if self._identity:
            console.print("[dim]Agent already registered in this session.[/dim]")
            return self._identity

        agent_id = self._make_agent_id(name)
        tx_sig = self._fake_tx_signature(f"register:{agent_id}:{time.time()}")

        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            description=description,
            registration_uri=metadata_uri,
            owner="SimulatedOwner111111111111111111111111111",
            registered_at=datetime.now(timezone.utc).isoformat(),
            tx_signature=tx_sig,
            onchain=not self.simulation,
        )
        self._identity = identity
        self._persist("agent_identity.json", asdict(identity))

        if self.simulation:
            console.print(
                f"[green]✓ Simulated registration of agent[/green] "
                f"[bold]{name}[/bold]\n"
                f"  Agent ID : {agent_id}\n"
                f"  Tx       : {tx_sig}\n"
                f"  [dim](Set simulation=False + funded keypair for real on-chain tx)[/dim]"
            )
        else:
            # Real path would call:
            # from mpl_agent_registry import registerIdentityV1 / mintAndSubmitAgent
            # or 8004-solana SDK registerAgent(...)
            raise NotImplementedError(
                "Real Solana registration requires a funded keypair and the "
                "Metaplex / 8004 SDK. See README for the exact steps."
            )
        return identity

    def log_validation(
        self,
        package: str,
        version: str | None,
        risk_level: str,
        findings_count: int,
        summary: str,
    ) -> ValidationRecord:
        if not self._identity:
            self.register_agent()

        record_id = str(uuid.uuid4())
        tx_sig = self._fake_tx_signature(
            f"validate:{self._identity.agent_id}:{package}:{version}:{time.time()}"
        )

        record = ValidationRecord(
            record_id=record_id,
            agent_id=self._identity.agent_id,
            package=package,
            version=version,
            risk_level=risk_level,
            findings_count=findings_count,
            summary=summary,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tx_signature=tx_sig,
            onchain=not self.simulation,
        )
        self._persist(f"validation_{record_id[:8]}.json", asdict(record))

        console.print(
            f"[cyan]⛓  Validation logged[/cyan]  package={package} "
            f"risk={risk_level}  tx={tx_sig[:20]}..."
        )
        return record

    def get_identity(self) -> AgentIdentity | None:
        return self._identity

    def _make_agent_id(self, name: str) -> str:
        h = hashlib.sha256(name.encode()).hexdigest()[:16]
        return f"DepTrap-{h}"

    def _fake_tx_signature(self, seed: str) -> str:
        """Produce a base58-looking signature for demos."""
        digest = hashlib.sha256(seed.encode()).hexdigest()
        # Make it look a bit more like a Solana signature (base58-ish length)
        return digest + hashlib.sha256((seed + "salt").encode()).hexdigest()[:32]

    def _persist(self, filename: str, data: dict[str, Any]) -> None:
        path = self._log_dir / filename
        path.write_text(json.dumps(data, indent=2))
