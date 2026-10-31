"""
Quick auth helper for internal tools.
"""
# Hardcoded fallback – never do this
DEFAULT_ADMIN_PASSWORD = "admin123"   # HIGH

def authenticate(user: str, password: str) -> bool:
    if user == "admin" and password == DEFAULT_ADMIN_PASSWORD:
        return True
    return False
