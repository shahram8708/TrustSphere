"""Application factory for TrustSphere."""

from datetime import datetime

from flask import Flask, g, render_template
from flask_login import current_user

from app.config import config
from app.extensions import cache, csrf, db, limiter, login_manager, mail, migrate


def create_app(config_name="development"):
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="../templates", static_folder="static")
    app.config.from_object(config.get(config_name, config["default"]))

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    # Ensure rate limiter storage is reachable. If Redis is configured but
    # not reachable, fall back to in-process memory storage so the app
    # continues to serve requests instead of raising connection errors.
    try:
        storage_uri = app.config.get("RATELIMIT_STORAGE_URI")
        if storage_uri and storage_uri.startswith("redis"):
            try:
                import redis as _redis

                client = _redis.from_url(storage_uri)
                client.ping()
            except Exception as exc:  # pragma: no cover - runtime network issue
                app.logger.warning(
                    "Rate limiter Redis unavailable (%s); falling back to memory storage.",
                    exc,
                )
                app.config["RATELIMIT_STORAGE_URI"] = "memory://"
    except Exception:  # pragma: no cover - defensive guard
        pass

    limiter.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    cache.init_app(app)

    from app.tasks.celery_app import celery as celery_instance, make_celery

    make_celery(app)
    app.extensions["celery"] = celery_instance

    from app.models import AdminUser, Alert, Institution, User
    from app.routes import admin_bp, api_bp, auth_bp, portal_bp, public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(portal_bp, url_prefix="/portal")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    @login_manager.user_loader
    def load_user(user_id):
        admin_user = AdminUser.query.get(user_id)
        if admin_user:
            return admin_user
        return User.query.get(user_id)

    @app.context_processor
    def inject_platform_context():
        open_alerts_count = 0
        institution_name = "TrustSphere"
        recent_open_alerts = []
        all_institutions = []

        if getattr(current_user, "is_authenticated", False):
            query = Alert.query.filter(Alert.status == "open")
            if getattr(current_user, "institution_id", None):
                query = query.filter(Alert.institution_id == current_user.institution_id)
                if current_user.institution:
                    institution_name = current_user.institution.name
            elif getattr(current_user, "is_super_admin", False):
                all_institutions = Institution.query.order_by(Institution.name.asc()).all()
            open_alerts_count = query.count()
            recent_open_alerts = (
                query.order_by(
                    Alert.ml_priority_score.desc(),
                    Alert.created_at.desc(),
                )
                .limit(5)
                .all()
            )

        return {
            "current_year": datetime.utcnow().year,
            "platform_version": app.config.get("PLATFORM_VERSION", "1.0.0"),
            "platform_name": app.config.get("PLATFORM_NAME", "TrustSphere"),
            "open_alerts_count": open_alerts_count,
            "institution_name": institution_name,
            "recent_open_alerts": recent_open_alerts,
            "all_institutions": all_institutions,
            "form_errors_exist": lambda form: any(form.errors.values()) if form else False,
        }

    @app.before_request
    def load_request_institution():
        g.institution = None
        if getattr(current_user, "is_authenticated", False):
            institution_id = getattr(current_user, "institution_id", None)
            if institution_id:
                g.institution = Institution.query.get(institution_id)

    @app.errorhandler(400)
    def bad_request(error):
        return (
            render_template(
                "errors/403.html",
                error_code=400,
                error_title="Bad Request",
                error_message="The request could not be understood by the server.",
            ),
            400,
        )

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    return app
