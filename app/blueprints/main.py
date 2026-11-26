"""Main blueprint – dashboard."""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

from app.models.project import Project
from app.models.finding import SecurityFinding
from app.models.risk    import RiskAssessment
from app.models.threat  import ThreatModel
from app.models.audit   import AuditLog

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if current_user.is_authenticated
                    else url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    total_projects = Project.query.count()
    open_findings  = SecurityFinding.query.filter_by(status="Open").count()
    open_risks     = RiskAssessment.query.filter_by(status="Open").count()
    open_threats   = ThreatModel.query.filter_by(status="Open").count()

    # Severity breakdown for open findings
    sev_counts = {
        s: SecurityFinding.query.filter_by(severity=s, status="Open").count()
        for s in SecurityFinding.SEVERITIES
    }

    # Recent projects (scoped by role)
    pq = Project.query
    if current_user.role not in ("admin", "manager"):
        pq = pq.filter_by(owner_id=current_user.id)
    recent_projects = pq.order_by(Project.updated_at.desc()).limit(6).all()

    # Critical open findings
    critical = (SecurityFinding.query
                .filter_by(severity="Critical", status="Open")
                .order_by(SecurityFinding.created_at.desc())
                .limit(5).all())

    # Audit tail (admin only)
    recent_audit = []
    if current_user.role == "admin":
        recent_audit = (AuditLog.query
                        .order_by(AuditLog.timestamp.desc())
                        .limit(8).all())

    return render_template(
        "main/dashboard.html",
        total_projects  = total_projects,
        open_findings   = open_findings,
        open_risks      = open_risks,
        open_threats    = open_threats,
        sev_counts      = sev_counts,
        recent_projects = recent_projects,
        critical        = critical,
        recent_audit    = recent_audit,
        severities      = SecurityFinding.SEVERITIES,
    )
