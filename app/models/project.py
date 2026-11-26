"""Project model."""
from datetime import datetime, timezone
from app.extensions import db


class Project(db.Model):
    __tablename__ = "projects"

    id          = db.Column(db.Integer,     primary_key=True)
    name        = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    phase       = db.Column(db.String(50),  nullable=False, default="Requirements")
    status      = db.Column(db.String(30),  nullable=False, default="Active")
    created_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))
    owner_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    owner            = db.relationship("User",            back_populates="projects")
    risk_assessments = db.relationship("RiskAssessment",  back_populates="project",
                                       cascade="all, delete-orphan", lazy="dynamic")
    threat_models    = db.relationship("ThreatModel",     back_populates="project",
                                       cascade="all, delete-orphan", lazy="dynamic")
    findings         = db.relationship("SecurityFinding", back_populates="project",
                                       cascade="all, delete-orphan", lazy="dynamic")

    PHASES   = ["Requirements", "Design", "Implementation", "Testing", "Deployment", "Maintenance"]
    STATUSES = ["Active", "On Hold", "Completed", "Archived"]

    def __repr__(self):
        return f"<Project {self.name!r}>"
