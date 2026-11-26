"""Immutable audit log entry."""
from datetime import datetime, timezone
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer,   primary_key=True)
    user_id    = db.Column(db.Integer,   db.ForeignKey("users.id"), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    resource   = db.Column(db.String(100))
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp  = db.Column(db.DateTime,
                           default=lambda: datetime.now(timezone.utc), index=True)

    user = db.relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} @ {self.timestamp}>"
