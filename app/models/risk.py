"""Risk Assessment model with automatic risk-score calculation."""
from datetime import datetime, timezone
from app.extensions import db


class RiskAssessment(db.Model):
    __tablename__ = "risk_assessments"

    id          = db.Column(db.Integer,      primary_key=True)
    project_id  = db.Column(db.Integer,      db.ForeignKey("projects.id"), nullable=False)
    title       = db.Column(db.String(200),  nullable=False)
    description = db.Column(db.Text)
    likelihood  = db.Column(db.Integer,      nullable=False)   # 1-5
    impact      = db.Column(db.Integer,      nullable=False)   # 1-5
    mitigation  = db.Column(db.Text)
    status      = db.Column(db.String(30),   default="Open")
    created_at  = db.Column(db.DateTime,     default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime,     default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))

    project = db.relationship("Project", back_populates="risk_assessments")

    STATUSES = ["Open", "Mitigated", "Accepted", "Closed"]

    @property
    def risk_score(self) -> int:
        return (self.likelihood or 0) * (self.impact or 0)

    @property
    def risk_level(self) -> str:
        s = self.risk_score
        if s >= 20: return "Critical"
        if s >= 12: return "High"
        if s >= 6:  return "Medium"
        return "Low"

    @property
    def risk_color(self) -> str:
        return {"Critical": "danger", "High": "warning",
                "Medium": "primary", "Low": "success"}.get(self.risk_level, "secondary")

    def __repr__(self):
        return f"<Risk {self.title!r} score={self.risk_score}>"
