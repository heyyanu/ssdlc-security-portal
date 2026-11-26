"""Threat Model (STRIDE) model."""
from datetime import datetime, timezone
from app.extensions import db


class ThreatModel(db.Model):
    __tablename__ = "threat_models"

    id             = db.Column(db.Integer,     primary_key=True)
    project_id     = db.Column(db.Integer,     db.ForeignKey("projects.id"), nullable=False)
    threat_name    = db.Column(db.String(200), nullable=False)
    stride_cat     = db.Column(db.String(40),  nullable=False)
    description    = db.Column(db.Text)
    countermeasure = db.Column(db.Text)
    priority       = db.Column(db.String(20),  default="Medium")
    status         = db.Column(db.String(30),  default="Open")
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc),
                               onupdate=lambda: datetime.now(timezone.utc))

    project = db.relationship("Project", back_populates="threat_models")

    STRIDE = [
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    ]
    PRIORITIES = ["Critical", "High", "Medium", "Low"]
    STATUSES   = ["Open", "Mitigated", "Accepted", "Closed"]

    # Colour map for badges
    STRIDE_COLOR = {
        "Spoofing":               "danger",
        "Tampering":              "warning",
        "Repudiation":            "secondary",
        "Information Disclosure": "info",
        "Denial of Service":      "dark",
        "Elevation of Privilege": "primary",
    }

    @property
    def stride_color(self):
        return self.STRIDE_COLOR.get(self.stride_cat, "secondary")

    def __repr__(self):
        return f"<Threat {self.threat_name!r}>"
