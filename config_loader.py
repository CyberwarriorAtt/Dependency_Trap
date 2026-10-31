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
