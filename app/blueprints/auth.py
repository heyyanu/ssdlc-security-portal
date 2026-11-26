"""Authentication blueprint – login, register, logout, change-password."""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, limiter
from app.models.user import User
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm
from app.security import (audit_log, validate_password,
                           handle_failed_login, reset_failed_logins)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        user     = User.query.filter_by(username=username).first()

        # Generic message – don't reveal whether user exists
        if not user or not user.check_password(form.password.data):
            if user:
                handle_failed_login(user)
            audit_log("LOGIN_FAILED", "auth", f"username={username}")
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active:
            flash("Your account is disabled. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form)

        if user.is_locked():
            audit_log("LOGIN_LOCKED", "auth", f"user={username}")
            flash("Account temporarily locked due to too many failed attempts. "
                  "Try again in 15 minutes.", "danger")
            return render_template("auth/login.html", form=form)

        login_user(user, remember=form.remember.data)
        reset_failed_logins(user)
        audit_log("LOGIN_SUCCESS", "auth", f"user={user.username}")

        # Open-redirect guard
        nxt = request.args.get("next", "")
        if nxt and nxt.startswith("/") and not nxt.startswith("//"):
            return redirect(nxt)
        return redirect(url_for("main.dashboard"))

    return render_template("auth/login.html", form=form)


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email    = form.email.data.strip().lower()

        ok, msg = validate_password(form.password.data)
        if not ok:
            flash(msg, "danger")
            return render_template("auth/register.html", form=form)

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html", form=form)
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(username=username, email=email, role="analyst")
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        audit_log("USER_REGISTERED", "auth", f"user={user.id}")
        flash("Account created! Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    audit_log("LOGOUT", "auth", f"user={current_user.username}")
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# ── Change password ───────────────────────────────────────────────────────────

@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            audit_log("PWD_CHANGE_FAIL", "auth")
            flash("Current password is incorrect.", "danger")
            return render_template("auth/change_password.html", form=form)

        ok, msg = validate_password(form.password.data)
        if not ok:
            flash(msg, "danger")
            return render_template("auth/change_password.html", form=form)

        current_user.set_password(form.password.data)
        db.session.commit()
        audit_log("PWD_CHANGED", "auth")
        flash("Password updated successfully.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("auth/change_password.html", form=form)
