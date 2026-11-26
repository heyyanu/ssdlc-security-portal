"""Security Finding model."""
from datetime import datetime, timezone
from app.extensions import db


class SecurityFinding(db.Model):
    __tablename__ = "security_findings"

    id           = db.Column(db.Integer,     primary_key=True)
    project_id   = db.Column(db.Integer,     db.ForeignKey("projects.id"),  nullable=False)
    reporter_id  = db.Column(db.Integer,     db.ForeignKey("users.id"),     nullable=False)
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text)
    severity     = db.Column(db.String(20),  nullable=False, default="Medium")
    cwe_id       = db.Column(db.String(20))
    cvss_score   = db.Column(db.Float)
    remediation  = db.Column(db.Text)
    status       = db.Column(db.String(30),  default="Open")
    created_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at   = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc))

    project  = db.relationship("Project",  back_populates="findings")
    reporter = db.relationship("User",     back_populates="findings")

    SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
    STATUSES   = ["Open", "In Progress", "Resolved", "Accepted Risk", "False Positive"]

    SEV_COLOR = {
        "Critical":      "danger",
        "High":          "warning",
        "Medium":        "primary",
        "Low":           "success",
        "Informational": "secondary",
    }

    @property
    def severity_color(self):
        return self.SEV_COLOR.get(self.severity, "secondary")

    def __repr__(self):
        return f"<Finding {self.title!r} [{self.severity}]>"
