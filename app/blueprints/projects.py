"""Projects blueprint – full CRUD with ownership enforcement."""
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.project import Project
from app.forms import ProjectForm
from app.security import audit_log, sanitize

projects_bp = Blueprint("projects", __name__, url_prefix="/projects")


def _get_project(pid: int) -> Project:
    p = db.session.get(Project, pid) or abort(404)
    if current_user.role not in ("admin", "manager") and p.owner_id != current_user.id:
        abort(403)
    return p


@projects_bp.route("/")
@login_required
def list_projects():
    if current_user.role in ("admin", "manager"):
        projects = Project.query.order_by(Project.updated_at.desc()).all()
    else:
        projects = (Project.query
                    .filter_by(owner_id=current_user.id)
                    .order_by(Project.updated_at.desc()).all())
    return render_template("projects/list.html", projects=projects)


@projects_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_project():
    form = ProjectForm()
    if form.validate_on_submit():
        p = Project(
            name        = sanitize(form.name.data),
            description = sanitize(form.description.data or ""),
            phase       = form.phase.data,
            status      = form.status.data,
            owner_id    = current_user.id,
        )
        db.session.add(p)
        db.session.commit()
        audit_log("PROJECT_CREATED", "project", f"id={p.id}")
        flash(f'Project "{p.name}" created.', "success")
        return redirect(url_for("projects.project_detail", pid=p.id))
    return render_template("projects/form.html", form=form, title="New Project", project=None)


@projects_bp.route("/<int:pid>")
@login_required
def project_detail(pid):
    p = _get_project(pid)
    return render_template("projects/detail.html", project=p)


@projects_bp.route("/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def edit_project(pid):
    p    = _get_project(pid)
    form = ProjectForm(obj=p)
    if form.validate_on_submit():
        p.name        = sanitize(form.name.data)
        p.description = sanitize(form.description.data or "")
        p.phase       = form.phase.data
        p.status      = form.status.data
        db.session.commit()
        audit_log("PROJECT_UPDATED", "project", f"id={p.id}")
        flash("Project updated.", "success")
        return redirect(url_for("projects.project_detail", pid=p.id))
    return render_template("projects/form.html", form=form, title="Edit Project", project=p)


@projects_bp.route("/<int:pid>/delete", methods=["POST"])
@login_required
def delete_project(pid):
    p = _get_project(pid)
    name = p.name
    db.session.delete(p)
    db.session.commit()
    audit_log("PROJECT_DELETED", "project", f"name={name}")
    flash(f'Project "{name}" deleted.', "success")
    return redirect(url_for("projects.list_projects"))
