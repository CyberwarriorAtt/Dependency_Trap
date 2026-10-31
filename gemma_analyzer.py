"""
Gemma 4 Core – Vulnerability explanation engine.

Uses an open-weight Gemma 4 model (via Ollama) as a focused developer assistant
to summarize code and explain vulnerabilities in plain language for junior developers.
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    import ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False

try:
    from rich.console import Console
    console = Console()
except ImportError:
    class _Dummy:
        def print(self, *a, **k): print(*a)
    console = _Dummy()

DEFAULT_MODEL = os.getenv("GEMMA_MODEL", "gemma4:e4b")


class GemmaAnalyzer:
    """Wrapper around Gemma 4 for code security analysis."""

    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model
        if HAS_OLLAMA:
            self._check_model()
        else:
            console.print("[dim]ollama package not installed – using simulated Gemma responses[/dim]")

    def _check_model(self) -> None:
        try:
            models = ollama.list()
            names = [m.model for m in models.models]
            if not any(self.model in n for n in names):
                console.print(
                    f"[yellow]Model '{self.model}' not found locally. "
                    f"Run: ollama pull {self.model}[/yellow]"
                )
        except Exception as e:
            console.print(f"[yellow]Ollama not reachable: {e}[/yellow]")
            console.print("[dim]Falling back to simulated responses for demo.[/dim]")

    def analyze_code(
        self,
        code: str,
        filename: str = "unknown.py",
        context: str | None = None,
    ) -> dict[str, Any]:
        if not HAS_OLLAMA:
            return self._simulate_analysis(code, filename)

        system_prompt = (
            "You are a helpful senior security engineer mentoring a junior developer. "
            "Analyze the provided code for security vulnerabilities, supply-chain risks, "
            "hardcoded secrets, insecure patterns, and dependency traps. "
            "Respond ONLY with valid JSON in this exact schema:\n"
            "{\n"
            '  "summary": "one-sentence overview",\n'
            '  "risk_level": "critical|high|medium|low|none",\n'
            '  "findings": [\n'
            "    {\n"
            '      "title": "short title",\n'
            '      "severity": "critical|high|medium|low",\n'
            '      "explanation": "plain-language explanation for a junior developer",\n'
            '      "recommendation": "what to do instead",\n'
            '      "line_hint": "optional approximate location"\n'
            "    }\n"
            "  ],\n"
            '  "junior_friendly_summary": "2-3 sentences a junior can understand"\n'
            "}"
        )

        user_content = f"Filename: {filename}\n\n```\n{code}\n```"
        if context:
            user_content = f"Additional context: {context}\n\n" + user_content

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                options={"temperature": 0.2},
                format="json",
            )
            content = response.message.content
            return json.loads(content)
        except Exception as e:
            console.print(f"[yellow]Gemma call failed ({e}). Using simulated analysis.[/yellow]")
            return self._simulate_analysis(code, filename)

    def explain_package_risk(
        self,
        package_name: str,
        version: str | None = None,
        known_issues: list[str] | None = None,
    ) -> dict[str, Any]:
        if not HAS_OLLAMA:
            return {
                "package": package_name,
                "version": version,
                "explanation": (
                    f"Package '{package_name}' appears in known compromised or "
                    "suspicious publishing patterns. Prefer pinned, well-maintained "
                    "alternatives and review the source before installing."
                ),
            }

        prompt = (
            f"Explain to a junior developer why the package '{package_name}'"
            f"{f' version {version}' if version else ''} might be a supply-chain risk. "
            f"Known issues: {known_issues or 'none listed'}. "
            "Keep it under 150 words and practical."
        )
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.3},
            )
            return {
                "package": package_name,
                "version": version,
                "explanation": response.message.content,
            }
        except Exception:
            return {
                "package": package_name,
                "version": version,
                "explanation": (
                    f"Package '{package_name}' appears in known compromised or "
                    "suspicious publishing patterns. Prefer pinned, well-maintained "
                    "alternatives and review the source before installing."
                ),
            }

    def _simulate_analysis(self, code: str, filename: str) -> dict[str, Any]:
        findings = []
        lower = code.lower()

        if "eval(" in lower or "exec(" in lower:
            findings.append({
                "title": "Dangerous dynamic execution",
                "severity": "critical",
                "explanation": "Using eval() or exec() lets attackers run arbitrary code if they control the input. This is one of the most common ways supply-chain malware gains a foothold.",
                "recommendation": "Never evaluate untrusted strings. Use safe parsers or allow-lists instead.",
                "line_hint": "search for eval/exec",
            })
        if "password" in lower and ("=" in code or ":" in code):
            findings.append({
                "title": "Possible hardcoded secret",
                "severity": "high",
                "explanation": "Hardcoding passwords or API keys in source is a classic mistake. Once the code is published or leaked, attackers can reuse those credentials.",
                "recommendation": "Move secrets to environment variables or a secrets manager. Never commit them.",
                "line_hint": "lines containing 'password'",
            })
        if "subprocess" in lower and "shell=true" in lower:
            findings.append({
                "title": "Shell injection risk",
                "severity": "high",
                "explanation": "Calling subprocess with shell=True and unsanitized input can let an attacker run any command on the machine.",
                "recommendation": "Prefer shell=False and pass arguments as a list. Validate or escape any user-controlled parts.",
                "line_hint": "subprocess calls",
            })
        if "os.environ" in lower and ("urllib" in lower or "requests" in lower or "http" in lower):
            findings.append({
                "title": "Potential environment exfiltration",
                "severity": "high",
                "explanation": "Reading os.environ and sending data over the network can leak secrets (API keys, cloud credentials) to an attacker-controlled endpoint.",
                "recommendation": "Never send the full environment. Explicitly allow-list only the non-sensitive values you need.",
                "line_hint": "environment + network",
            })
        if not findings:
            findings.append({
                "title": "No obvious critical issues detected in fallback mode",
                "severity": "low",
                "explanation": "Static pattern matching found nothing immediately dangerous. A full Gemma analysis would dig deeper into logic and dependency usage.",
                "recommendation": "Still run the real model and review third-party dependencies.",
                "line_hint": None,
            })

        risk = "critical" if any(f["severity"] == "critical" for f in findings) else \
               "high" if any(f["severity"] == "high" for f in findings) else "medium"

        return {
            "summary": f"Analysis of {filename} completed (simulated Gemma path).",
            "risk_level": risk,
            "findings": findings,
            "junior_friendly_summary": (
                "I looked for the most common dangerous patterns (eval, hardcoded secrets, "
                "shell injection, env exfiltration). Treat any 'high' or 'critical' finding "
                "seriously and ask a senior for a second look."
            ),
        }
