# DependencyTrap – Open-Source "Dependency Trap" Code Guard

> Autonomous supply-chain security agent powered by **open-weight AI (Gemma 4)**.

**Hacktoberfest 2026 · Challenge 2 · Multan**  
**Tracks used:** Google Gemma 4 Core · Snowflake CoCo Data · Solana Agent Identity · GitHub Copilot Acceleration

---

## What it does

DependencyTrap is an autonomous security agent that:

1. Uses **Gemma 4** (open-weight) as a focused developer assistant to summarize code and explain vulnerabilities in plain language a junior developer can understand.
2. Cross-checks packages against a vulnerability index shaped like the public datasets you would pull from **Snowflake** (via CoCo pipelines).
3. Registers itself on the **Solana Agent Registry** and writes every validation result on-chain, creating an untamperable audit log of malicious / suspicious packages.
4. Ships with realistic mock packages that contain subtle security flaws (generated in the style of the Copilot acceleration track) plus a full demo command.

---

## Quick Start (demo in < 2 minutes)

```bash
# 1. Clone & enter
git clone <your-repo-url> DependencyTrap
cd DependencyTrap

# 2. Create venv & install
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. (Recommended) Pull Gemma 4 via Ollama
ollama pull gemma4:e4b             # ~9-10 GB, good laptop default
# or: ollama pull gemma4:e2b       # lighter

# 4. Run the full demo
python -m dependencytrap.cli demo
```

The demo will:
- Register the security agent (simulated Solana identity + tx signature)
- Generate mock vulnerable files
- Scan them with Gemma 4
- Check known compromised packages
- Write validation records into `onchain_txns/`

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Source / Pkg   │────▶│  Gemma 4 Analyzer │────▶│  Risk + Findings   │
└─────────────────┘     │  (Ollama)         │     └─────────┬──────────┘
                        └──────────────────┘               │
                                                           ▼
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│ Snowflake CoCo  │────▶│  Vuln Database   │────▶│  Cross-check hits  │
│ style datasets  │     │  (local MVP)     │     └─────────┬──────────┘
└─────────────────┘     └──────────────────┘               │
                                                           ▼
                                               ┌────────────────────┐
                                               │ Solana Agent       │
                                               │ Registry + Log     │
                                               │ (sim or real)      │
                                               └────────────────────┘
```

---

## Mandatory Track Integration

### 1. Google Gemma 4 Core
- Model: `gemma4:e4b` (or any Gemma 4 tag) via Ollama
- Role: focused developer assistant
- Prompting: asks for JSON with summary, risk level, findings, and a **junior-friendly explanation**
- File: `src/dependencytrap/gemma_analyzer.py`

If Ollama is not available the analyzer falls back to a deterministic pattern-based analysis so the rest of the demo still works for judges.

### 2. Snowflake CoCo Data
- Local dataset in `src/dependencytrap/vuln_data.py` mirrors the shape of public vulnerability feeds (OSV / GitHub Advisories / historical supply-chain incidents).
- Designed so a CoCo pipeline can replace the static list with live Snowflake Marketplace data.
- Example CoCo-style prompt documented in the module docstring:
  > "Create a pipeline that keeps a daily snapshot of known compromised packages from OSV + GitHub Advisories and flags packages with anomalous publish frequency."

### 3. Solana Agent Identity
- Agent is registered on startup (`SolanaAgentClient.register_agent`).
- Every scan produces a `ValidationRecord` that is persisted and given a transaction signature.
- Simulation mode is on by default so the demo works offline.
- Real path (documented below) uses Metaplex MPL Agent Registry / 8004-solana SDK.

Look at the files written to `onchain_txns/` after a run for the identity + validation JSON.

### 4. GitHub Copilot Acceleration
The mock packages in `src/dependencytrap/mocks.py` were created following the spirit of the track:

> Natural-language prompts such as  
> "write a small logger that also records the environment for debugging"  
> "make a config loader that can evaluate simple expressions"  
> produce code that looks almost legitimate but hides eval, shell=True, hardcoded secrets, and environment exfiltration.

These samples are then fed to the scanner + Gemma so we can verify the engine actually surfaces the issues. See the "How Copilot helped" section below for the exact prompts used during development.

---

## How Copilot helped (required README section)

While building the package-parsing and mock-generation pieces we used GitHub Copilot in natural language:

1. **Unfamiliar packaging APIs**  
   Prompt: "Show me a robust way to parse both requirements.txt and pyproject.toml dependency lists in pure Python without heavy dependencies."  
   Copilot produced a clean starting point using `packaging` + `toml` that we adapted into the (future) manifest scanner.

2. **Generating subtle flawed scripts**  
   Prompts like the ones listed above produced the four mock files under `mock_packages/`. We then asked Copilot to "write pytest cases that assert each of these dangerous patterns is present" so we could verify the scanner catches them.

3. **Test suite scaffolding**  
   Copilot generated the initial `tests/` layout and parametrized cases for known-bad package names, which we kept and extended.

---

## Real Solana registration (optional next step)

When you have a funded keypair:

```bash
# Install real SDKs
pip install solana solders
# or use the JS/TS Metaplex route:
# npm install @metaplex-foundation/mpl-agent-registry @metaplex-foundation/umi-bundle-defaults
```

Then set `simulation=False` and point `SolanaAgentClient` at your keypair.  
Follow the official docs:
- https://www.metaplex.com/docs/agents/register-agent
- https://solana.com/agent-registry

The agent registration URI can point at the `agent-card.json` in this repo.

---

## Project layout

```
DependencyTrap/
├── LICENSE                 # MIT (visible open-source license)
├── README.md
├── requirements.txt
├── pyproject.toml
├── src/dependencytrap/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py              # Typer CLI
│   ├── gemma_analyzer.py   # Gemma 4 core
│   ├── vuln_data.py        # Snowflake CoCo style data
│   ├── solana_agent.py     # Agent Registry + validation log
│   ├── scanner.py          # Orchestration
│   └── mocks.py            # Copilot-style vulnerable samples
├── mock_packages/          # Generated on first demo run
├── onchain_txns/           # Simulated (or real) Solana records
└── tests/
```

---

## License

MIT – see [LICENSE](LICENSE).

---

## Why open-weight AI matters here

A closed API cannot be audited, cannot be run air-gapped, and cannot be fine-tuned on your own historical incident data.  
By using **Gemma 4** as the reasoning core we keep the entire decision path inspectable, offline-capable, and under the control of the open-source community that actually maintains the packages being protected.
