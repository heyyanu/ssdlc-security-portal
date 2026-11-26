"""
Shared security utilities:
  - HTTP security headers
  - Audit logging
  - Input validation helpers
  - Account lockout
  - Role-based access control decorator
"""
import re
from datetime import datetime, timezone, timedelta
from functools import wraps

import bleach
from flask import request, abort, current_app
from flask_login import current_user

from app.extensions import db


# ── Sanitisation ─────────────────────────────────────────────────────────────

def sanitize(text: str) -> str:
    """Strip unsafe HTML tags from user input."""
    if not text:
        return ""
    allowed = current_app.config.get("ALLOWED_TAGS", [])
    return bleach.clean(str(text), tags=allowed, strip=True)


# ── Password validation ───────────────────────────────────────────────────────

def validate_password(value: str) -> tuple[bool, str]:
    """Return (ok, error_message)."""
    min_len = current_app.config.get("MIN_PASSWORD_LENGTH", 12)
    checks = [
        (len(value) >= min_len,              f"Password must be at least {min_len} characters."),
        (bool(re.search(r"[A-Z]", value)),   "Must contain an uppercase letter."),
        (bool(re.search(r"[a-z]", value)),   "Must contain a lowercase letter."),
        (bool(re.search(r"\d", value)),      "Must contain a digit."),
        (bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', value)),
         "Must contain a special character."),
    ]
    for ok, msg in checks:
        if not ok:
            return False, msg
    return True, ""


# ── Audit logging ─────────────────────────────────────────────────────────────

def audit_log(action: str, resource: str = "", details: str = "") -> None:
    """Write an immutable audit entry to the database."""
    from app.models.audit import AuditLog
    uid = current_user.id if (current_user and current_user.is_authenticated) else None
    ip  = (request.remote_addr or "system") if request else "system"
    entry = AuditLog(
        user_id    = uid,
        action     = str(action)[:100],
        resource   = str(resource)[:100],
        details    = str(details)[:500],
        ip_address = ip,
    )
    db.session.add(entry)
    db.session.commit()


# ── Account lockout ───────────────────────────────────────────────────────────

def handle_failed_login(user) -> None:
    """Increment failure counter and lock account when threshold is reached."""
    threshold = current_app.config.get("LOGIN_MAX_ATTEMPTS", 5)
    minutes   = current_app.config.get("LOCKOUT_MINUTES", 15)
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= threshold:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        audit_log("ACCOUNT_LOCKED", "auth", f"user={user.username}")
    db.session.commit()


def reset_failed_logins(user) -> None:
    user.failed_logins = 0
    user.locked_until  = None
    user.last_login    = datetime.now(timezone.utc)
    db.session.commit()


# ── RBAC decorator ────────────────────────────────────────────────────────────

def roles_required(*roles):
    """Abort 403 if logged-in user's role is not in *roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                audit_log("UNAUTHORISED_ACCESS", request.path, f"user={current_user.username}")
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Security headers ──────────────────────────────────────────────────────────

def add_security_headers(response):
    h = response.headers
    h["X-Content-Type-Options"]  = "nosniff"
    h["X-Frame-Options"]         = "DENY"
    h["X-XSS-Protection"]        = "1; mode=block"
    h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
    h["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'nonce-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    h.pop("Server", None)        # remove fingerprint
    return response
