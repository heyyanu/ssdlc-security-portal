"""Security Findings blueprint."""
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.project import Project
from app.models.finding import SecurityFinding
from app.forms   import FindingForm
from app.security import audit_log, sanitize

findings_bp = Blueprint("findings", __name__, url_prefix="/projects/<int:pid>/findings")


def _check(pid: int) -> Project:
    p = db.session.get(Project, pid) or abort(404)
    if current_user.role not in ("admin", "manager") and p.owner_id != current_user.id:
        abort(403)
    return p


@findings_bp.route("/")
@login_required
def list_findings(pid):
    p        = _check(pid)
    findings = (SecurityFinding.query
                .filter_by(project_id=pid)
                .order_by(SecurityFinding.created_at.desc())
                .all())
    sev_summary = {s: sum(1 for f in findings if f.severity == s)
                   for s in SecurityFinding.SEVERITIES}
    return render_template("findings/list.html",
                           project=p, findings=findings, sev_summary=sev_summary,
                           severities=SecurityFinding.SEVERITIES)


@findings_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_finding(pid):
    p    = _check(pid)
    form = FindingForm()
    if form.validate_on_submit():
        f = SecurityFinding(
            project_id  = pid,
            reporter_id = current_user.id,
            title       = sanitize(form.title.data),
            description = sanitize(form.description.data or ""),
            severity    = form.severity.data,
            cwe_id      = form.cwe_id.data or None,
            cvss_score  = form.cvss_score.data,
            remediation = sanitize(form.remediation.data or ""),
            status      = form.status.data,
        )
        db.session.add(f)
        db.session.commit()
        audit_log("FINDING_CREATED", "finding", f"id={f.id} sev={f.severity}")
        flash("Security finding recorded.", "success")
        return redirect(url_for("findings.list_findings", pid=pid))
    return render_template("findings/form.html", form=form, project=p, title="New Finding")


@findings_bp.route("/<int:fid>")
@login_required
def finding_detail(pid, fid):
    p = _check(pid)
    f = SecurityFinding.query.filter_by(id=fid, project_id=pid).first_or_404()
    return render_template("findings/detail.html", project=p, finding=f)


@findings_bp.route("/<int:fid>/edit", methods=["GET", "POST"])
@login_required
def edit_finding(pid, fid):
    p    = _check(pid)
    f    = SecurityFinding.query.filter_by(id=fid, project_id=pid).first_or_404()
    form = FindingForm(obj=f)
    if form.validate_on_submit():
        f.title       = sanitize(form.title.data)
        f.description = sanitize(form.description.data or "")
        f.severity    = form.severity.data
        f.cwe_id      = form.cwe_id.data or None
        f.cvss_score  = form.cvss_score.data
        f.remediation = sanitize(form.remediation.data or "")
        f.status      = form.status.data
        db.session.commit()
        audit_log("FINDING_UPDATED", "finding", f"id={fid}")
        flash("Finding updated.", "success")
        return redirect(url_for("findings.finding_detail", pid=pid, fid=fid))
    return render_template("findings/form.html", form=form, project=p, title="Edit Finding")


@findings_bp.route("/<int:fid>/delete", methods=["POST"])
@login_required
def delete_finding(pid, fid):
    _check(pid)
    f = SecurityFinding.query.filter_by(id=fid, project_id=pid).first_or_404()
    db.session.delete(f)
    db.session.commit()
    audit_log("FINDING_DELETED", "finding", f"id={fid}")
    flash("Finding deleted.", "success")
    return redirect(url_for("findings.list_findings", pid=pid))
