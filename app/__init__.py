"""
SSDLC Portal – Application Factory
Secure Software Development Lifecycle management system.
"""
import os
from flask import Flask, jsonify, render_template
from sqlalchemy import text

from app.extensions import db, login_manager, csrf, limiter
from app.security import add_security_headers


def create_app(config_name: str = "default") -> Flask:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, "templates"),
        static_folder="static",
        instance_path=os.path.join(project_root, "instance"),
        instance_relative_config=True,
    )

    # ── Load config ──────────────────────────────────────────────────────────
    from app.config import config
    app.config.from_object(config[config_name])
    os.makedirs(app.instance_path, exist_ok=True)

    # ── Extensions ───────────────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ── User loader ───────────────────────────────────────────────────────────
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ── Blueprints ────────────────────────────────────────────────────────────
    from app.blueprints.auth     import auth_bp
    from app.blueprints.main     import main_bp
    from app.blueprints.projects import projects_bp
    from app.blueprints.risks    import risks_bp
    from app.blueprints.threats  import threats_bp
    from app.blueprints.findings import findings_bp
    from app.blueprints.audit    import audit_bp

    for bp in (main_bp, auth_bp, projects_bp, risks_bp,
               threats_bp, findings_bp, audit_bp):
        app.register_blueprint(bp)

    # ── Security headers on every response ───────────────────────────────────
    app.after_request(add_security_headers)

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(e):        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):       return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(e):          return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):          return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def rate_limited(e):       return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def server_error(e):       return render_template("errors/500.html"), 500

    # ── Liveness/readiness endpoint ───────────────────────────────────────────
    # This endpoint is intentionally unauthenticated for Docker/Jenkins checks.
    @app.get("/health")
    def health():
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify(status="healthy"), 200
        except Exception:
            db.session.rollback()
            app.logger.exception("Application health check failed")
            return jsonify(status="unhealthy"), 503

    # ── Initialise the database schema ────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app
