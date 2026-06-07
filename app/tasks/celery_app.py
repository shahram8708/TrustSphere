"""Celery application instance and Flask integration."""

from __future__ import annotations

import os
import sys

from celery import Celery


celery = Celery(__name__)


def _redis_is_available(flask_app):
    redis_url = flask_app.config.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        import redis

        client = redis.Redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return True
    except Exception as exc:
        flask_app.config["CELERY_TASK_ALWAYS_EAGER"] = True
        print(
            "[TrustSphere] Redis unavailable, Celery running in eager synchronous mode",
            file=sys.stdout,
        )
        print(f"[TrustSphere] Redis check failed: {exc}", file=sys.stderr)
        return False


def make_celery(flask_app):
    """Configure the shared Celery instance for a Flask application."""
    _redis_is_available(flask_app)

    celery.conf.update(
        broker_url=flask_app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=flask_app.config.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        task_always_eager=flask_app.config.get("CELERY_TASK_ALWAYS_EAGER", False),
        task_eager_propagates=True,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="Asia/Kolkata",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        result_expires=3600,
    )

    class ContextTask(celery.Task):
        """Run Celery task bodies inside the Flask application context."""

        abstract = True

        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    flask_app.extensions["celery"] = celery

    from app.tasks import alert_notify, behavioural_update, data_cleanup, device_analysis
    from app.tasks import email_tasks, kyc_processing, pam_analysis, report_build, risk_update
    from app.tasks import scheduled_jobs

    task_modules = (
        email_tasks,
        risk_update,
        alert_notify,
        report_build,
        behavioural_update,
        device_analysis,
        kyc_processing,
        pam_analysis,
        data_cleanup,
        scheduled_jobs,
    )
    for module in task_modules:
        getattr(module, "__name__", None)

    return celery


# If this module is imported directly by a Celery worker, try to automatically
# initialize the shared Celery instance with the Flask application so that
# tasks run inside a Flask application context. This is safe to attempt and
# falls back gracefully on any error.
try:
    if os.environ.get("CELERY_APP_INIT", "1").strip().lower() in {"1", "true", "yes"}:
        try:
            from app import create_app

            cfg = (
                os.environ.get("FLASK_CONFIG")
                or os.environ.get("TRUSTSPHERE_CONFIG")
                or os.environ.get("FLASK_ENV")
                or "default"
            )
            flask_app = create_app(cfg)
            make_celery(flask_app)
        except Exception as exc:
            print(
                "[TrustSphere] Celery auto-init skipped due to error:", exc,
                file=sys.stderr,
            )
except Exception:
    # Protect against unexpected failures during module import.
    pass
