"""User model with bcrypt password hashing and account-lockout support."""
from datetime import datetime, timezone
import bcrypt
from flask_login import UserMixin
from app.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer,     primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default="analyst")
    is_active     = db.Column(db.Boolean,     default=True,   nullable=False)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    last_login    = db.Column(db.DateTime)
    failed_logins = db.Column(db.Integer,     default=0, nullable=False)
    locked_until  = db.Column(db.DateTime)

    # Relationships
    projects  = db.relationship("Project",        back_populates="owner",    lazy="dynamic")
    audit_logs = db.relationship("AuditLog",       back_populates="user",     lazy="dynamic")
    findings  = db.relationship("SecurityFinding", back_populates="reporter", lazy="dynamic")

    ROLES = ["admin", "manager", "analyst"]

    # ── Password ──────────────────────────────────────────────────────────────

    def set_password(self, plaintext: str) -> None:
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(plaintext.encode(), salt).decode()

    def check_password(self, plaintext: str) -> bool:
        try:
            return bcrypt.checkpw(plaintext.encode(), self.password_hash.encode())
        except Exception:
            return False

    # ── Lockout ───────────────────────────────────────────────────────────────

    def is_locked(self) -> bool:
        if self.locked_until:
            lu = self.locked_until
            if lu.tzinfo is None:
                lu = lu.replace(tzinfo=timezone.utc)
            return lu > datetime.now(timezone.utc)
        return False

    def __repr__(self):
        return f"<User {self.username!r} role={self.role}>"
