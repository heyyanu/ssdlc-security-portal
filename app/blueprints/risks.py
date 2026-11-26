"""Risk Assessment blueprint."""
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.project import Project
from app.models.risk    import RiskAssessment
from app.forms   import RiskForm
from app.security import audit_log, sanitize

risks_bp = Blueprint("risks", __name__, url_prefix="/projects/<int:pid>/risks")


def _check(pid: int) -> Project:
    p = db.session.get(Project, pid) or abort(404)
    if current_user.role not in ("admin", "manager") and p.owner_id != current_user.id:
        abort(403)
    return p


@risks_bp.route("/")
@login_required
def list_risks(pid):
    p = _check(pid)
    risks = RiskAssessment.query.filter_by(project_id=pid).order_by(
        RiskAssessment.created_at.desc()).all()
    return render_template("risks/list.html", project=p, risks=risks)


@risks_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_risk(pid):
    p = _check(pid)
    form = RiskForm()
    if form.validate_on_submit():
        r = RiskAssessment(
            project_id  = pid,
            title       = sanitize(form.title.data),
            description = sanitize(form.description.data or ""),
            likelihood  = form.likelihood.data,
            impact      = form.impact.data,
            mitigation  = sanitize(form.mitigation.data or ""),
            status      = form.status.data,
        )
        db.session.add(r)
        db.session.commit()
        audit_log("RISK_CREATED", "risk", f"id={r.id}")
        flash("Risk assessment added.", "success")
        return redirect(url_for("risks.list_risks", pid=pid))
    return render_template("risks/form.html", form=form, project=p, title="New Risk")


@risks_bp.route("/<int:rid>/edit", methods=["GET", "POST"])
@login_required
def edit_risk(pid, rid):
    p = _check(pid)
    r = RiskAssessment.query.filter_by(id=rid, project_id=pid).first_or_404()
    form = RiskForm(obj=r)
    if form.validate_on_submit():
        r.title       = sanitize(form.title.data)
        r.description = sanitize(form.description.data or "")
        r.likelihood  = form.likelihood.data
        r.impact      = form.impact.data
        r.mitigation  = sanitize(form.mitigation.data or "")
        r.status      = form.status.data
        db.session.commit()
        audit_log("RISK_UPDATED", "risk", f"id={rid}")
        flash("Risk updated.", "success")
        return redirect(url_for("risks.list_risks", pid=pid))
    return render_template("risks/form.html", form=form, project=p, title="Edit Risk")


@risks_bp.route("/<int:rid>/delete", methods=["POST"])
@login_required
def delete_risk(pid, rid):
    _check(pid)
    r = RiskAssessment.query.filter_by(id=rid, project_id=pid).first_or_404()
    db.session.delete(r)
    db.session.commit()
    audit_log("RISK_DELETED", "risk", f"id={rid}")
    flash("Risk deleted.", "success")
    return redirect(url_for("risks.list_risks", pid=pid))
