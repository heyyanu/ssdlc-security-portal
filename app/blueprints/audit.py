"""Audit Log blueprint – admin-only."""
from flask import Blueprint, render_template, request
from flask_login import login_required

from app.models.audit import AuditLog
from app.models.user  import User
from app.security     import roles_required

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
@login_required
@roles_required("admin")
def audit_log_view():
    page     = request.args.get("page",   1,  type=int)
    action_f = request.args.get("action", "").strip()
    user_f   = request.args.get("user",   "").strip()

    q = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if action_f:
        q = q.filter(AuditLog.action.ilike(f"%{action_f}%"))
    if user_f:
        ids = [u.id for u in User.query.filter(User.username.ilike(f"%{user_f}%")).all()]
        q = q.filter(AuditLog.user_id.in_(ids))

    logs = q.paginate(page=page, per_page=30, error_out=False)
    return render_template("audit/log.html", logs=logs,
                           action_f=action_f, user_f=user_f)
