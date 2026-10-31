# DependencyTrap – Open-Source "Dependency Trap" Code Guard

> Autonomous supply-chain security agent powered by **open-weight AI (Gemma 4)**.

**Hacktoberfest 2026 · Challenge 2 · Multan**  
**Tracks used:** Google Gemma 4 Core · Snowflake CoCo Data · Solana Agent Identity · GitHub Copilot Acceleration  

**Author:** [CyberwarriorAtt](https://github.com/CyberwarriorAtt)  
**Repository:** https://github.com/CyberwarriorAtt/Dependency_Trap

---

## What it does

DependencyTrap is an autonomous security agent that:

1. Uses **Gemma 4** (open-weight) as a focused developer assistant to summarize code and explain vulnerabilities in plain language a junior developer can understand.
2. Cross-checks packages against a vulnerability index shaped like the public datasets you would pull from **Snowflake** (via CoCo pipelines).
3. Registers itself on the **Solana Agent Registry** and writes every validation result on-chain, creating an untamperable audit log of malicious / suspicious packages.
4. Ships with realistic mock packages that contain subtle security flaws (generated in the style of the Copilot acceleration track).

---

## Quick Start (Demo in under 2 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/CyberwarriorAtt/Dependency_Trap.git
cd Dependency_Trap

# 2. Run the demo (no extra installation required for basic demo)
python run_demo_stdlib.py
```

The demo will:
- Register the security agent (simulated Solana identity + transaction signature)
- Analyze mock vulnerable files using Gemma 4 (or fallback analysis)
- Check known compromised packages
- Save validation records as JSON files

---

## Main Files

| File | Purpose |
|------|---------|
| `gemma_analyzer.py` | Gemma 4 Core – analyzes code and explains vulnerabilities |
| `vuln_data.py` | Snowflake CoCo style vulnerability database |
| `solana_agent.py` | Solana Agent Identity registration + validation logging |
| `scanner.py` | Main scanning engine |
| `cli.py` | Command-line interface |
| `mocks.py` | Generates mock packages with security flaws |
| `run_demo_stdlib.py` | Full end-to-end demo script |
| `agent-card.json` | Agent metadata for Solana registration |

---

## Mandatory Track Integration

### 1. Google Gemma 4 Core
- Uses open-weight **Gemma 4** model (via Ollama when available)
- Acts as a developer assistant that explains risks in junior-friendly language
- Falls back to pattern-based analysis if Ollama is not installed

### 2. Snowflake CoCo Data
- Contains a local vulnerability index based on real historical supply-chain attacks
- Designed so it can be replaced with live data from Snowflake using CoCo pipelines
- Includes known compromised packages such as `event-stream`, `ua-parser-js`, `node-ipc`, `ctx`, etc.

### 3. Solana Agent Identity
- Registers the security agent on startup
- Logs every validation result with a transaction signature
- Works in simulation mode by default (fully offline)
- Real on-chain integration path is documented in the code

### 4. GitHub Copilot Acceleration
Mock vulnerable files were created using natural language prompts such as:
- “write a small logger that also records the environment for debugging”
- “make a config loader that can evaluate simple expressions”

These samples contain subtle issues (eval, hardcoded secrets, shell injection, environment exfiltration) and are used to test the scanner.

---

## How Copilot Helped

While building this project we used GitHub Copilot with natural language prompts:

1. **Package parsing**  
   Prompt: “Show me a robust way to parse both requirements.txt and pyproject.toml dependency lists in pure Python”  
   Copilot helped generate clean starting code.

2. **Creating subtle vulnerable samples**  
   Prompts produced the mock files (`auth_helper.py`, `config_loader.py`, `innocent_logger.py`, `task_runner.py`).

3. **Test ideas**  
   Copilot suggested parametrized test cases for known-bad packages.

---

## Example Demo Output

```
[1] Registering security agent on Solana Agent Registry...
    Agent ID : DepTrap-996539577fde5824

[2] Loading vulnerability index...
    Loaded 7 known compromised packages

[3] Analyzing mock files with Gemma 4...
    config_loader.py     → CRITICAL (dangerous eval)
    auth_helper.py       → HIGH (hardcoded password)
    innocent_logger.py   → HIGH (environment exfiltration)
    task_runner.py       → HIGH (shell injection)

[4] Package checks:
    event-stream@3.3.6   → KNOWN BAD
    ctx@0.1.4            → KNOWN BAD
```

---

## License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.

---

## Why Open-Weight AI Matters

A closed API cannot be audited, cannot run air-gapped, and cannot be fine-tuned on private incident data.  
By using **Gemma 4** as the core reasoning engine, the entire decision path stays inspectable, offline-capable, and under the control of the open-source community.
