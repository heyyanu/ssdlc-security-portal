"""Application configuration classes."""
import os, secrets


class Config:
    # ── Core ─────────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    WTF_CSRF_ENABLED      = True
    WTF_CSRF_TIME_LIMIT   = 3600

    # ── Database ──────────────────────────────────────────────────────────────
    _base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL") or
        f"sqlite:///{os.path.join(_base, 'instance', 'ssdlc.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Session ───────────────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    SESSION_COOKIE_SECURE    = False   # True in production (HTTPS)
    PERMANENT_SESSION_LIFETIME = 1800  # 30 min

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT     = "300 per day;60 per hour"

    # ── App-specific ──────────────────────────────────────────────────────────
    MIN_PASSWORD_LENGTH = 12
    LOGIN_MAX_ATTEMPTS  = 5
    LOCKOUT_MINUTES     = 15
    ALLOWED_TAGS = ["b", "i", "u", "em", "strong", "p", "br", "ul", "li", "ol"]


class DevelopmentConfig(Config):
    DEBUG   = True
    TESTING = False


class TestingConfig(Config):
    TESTING            = True
    DEBUG              = False
    WTF_CSRF_ENABLED   = False
    RATELIMIT_ENABLED  = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class StagingConfig(Config):
    """Staging runs over the current HTTP-only EC2 endpoint.

    Keep cookies non-Secure only for this staging environment. Enable HTTPS
    and use ProductionConfig before exposing a production environment.
    """
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "staging": StagingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
