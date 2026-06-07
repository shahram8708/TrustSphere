"""Shared helpers for TrustSphere Celery task modules."""

from __future__ import annotations

from contextlib import nullcontext
import sys

from flask import current_app, has_app_context

from app.extensions import db


def flask_task_context():
    """Return a Flask app context when one is already available."""
    if has_app_context():
        return current_app._get_current_object().app_context()
    return nullcontext()


def log_task_error(task_name, exc):
    """Write task errors to stderr with a consistent prefix."""
    print(f"[TrustSphere Task] {task_name} failed: {exc}", file=sys.stderr)


def rollback_session():
    """Rollback SQLAlchemy session without hiding the original error."""
    try:
        db.session.rollback()
    except Exception as rollback_exc:
        print(f"[TrustSphere Task] rollback failed: {rollback_exc}", file=sys.stderr)
