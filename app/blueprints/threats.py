"""Threat Model blueprint."""
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.project import Project
from app.models.threat  import ThreatModel
from app.forms   import ThreatForm
from app.security import audit_log, sanitize

threats_bp = Blueprint("threats", __name__, url_prefix="/projects/<int:pid>/threats")


def _check(pid: int) -> Project:
    p = db.session.get(Project, pid) or abort(404)
    if current_user.role not in ("admin", "manager") and p.owner_id != current_user.id:
        abort(403)
    return p


@threats_bp.route("/")
@login_required
def list_threats(pid):
    p = _check(pid)
    threats = ThreatModel.query.filter_by(project_id=pid).order_by(
        ThreatModel.created_at.desc()).all()
    # Group by STRIDE category
    grouped = {}
    for t in threats:
        grouped.setdefault(t.stride_cat, []).append(t)
    return render_template("threats/list.html", project=p,
                           threats=threats, grouped=grouped,
                           stride_list=ThreatModel.STRIDE)


@threats_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_threat(pid):
    p = _check(pid)
    form = ThreatForm()
    if form.validate_on_submit():
        t = ThreatModel(
            project_id     = pid,
            threat_name    = sanitize(form.threat_name.data),
            stride_cat     = form.stride_cat.data,
            description    = sanitize(form.description.data or ""),
            countermeasure = sanitize(form.countermeasure.data or ""),
            priority       = form.priority.data,
            status         = form.status.data,
        )
        db.session.add(t)
        db.session.commit()
        audit_log("THREAT_CREATED", "threat", f"id={t.id}")
        flash("Threat entry added.", "success")
        return redirect(url_for("threats.list_threats", pid=pid))
    return render_template("threats/form.html", form=form, project=p, title="New Threat")


@threats_bp.route("/<int:tid>/edit", methods=["GET", "POST"])
@login_required
def edit_threat(pid, tid):
    p = _check(pid)
    t = ThreatModel.query.filter_by(id=tid, project_id=pid).first_or_404()
    form = ThreatForm(obj=t)
    if form.validate_on_submit():
        t.threat_name    = sanitize(form.threat_name.data)
        t.stride_cat     = form.stride_cat.data
        t.description    = sanitize(form.description.data or "")
        t.countermeasure = sanitize(form.countermeasure.data or "")
        t.priority       = form.priority.data
        t.status         = form.status.data
        db.session.commit()
        audit_log("THREAT_UPDATED", "threat", f"id={tid}")
        flash("Threat updated.", "success")
        return redirect(url_for("threats.list_threats", pid=pid))
    return render_template("threats/form.html", form=form, project=p, title="Edit Threat")


@threats_bp.route("/<int:tid>/delete", methods=["POST"])
@login_required
def delete_threat(pid, tid):
    _check(pid)
    t = ThreatModel.query.filter_by(id=tid, project_id=pid).first_or_404()
    db.session.delete(t)
    db.session.commit()
    audit_log("THREAT_DELETED", "threat", f"id={tid}")
    flash("Threat deleted.", "success")
    return redirect(url_for("threats.list_threats", pid=pid))
