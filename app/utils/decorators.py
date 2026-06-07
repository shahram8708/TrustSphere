"""Route decorators for TrustSphere access control and API protection."""

from __future__ import annotations

import hashlib
import time
from functools import wraps

from flask import abort, flash, g, redirect, request, url_for
from flask_login import current_user, logout_user

from app.models import AdminUser, Institution, User
from app.utils.response import error_response


_rate_limit_store = {}


def admin_required(view_func):
    """Require an authenticated AdminUser account."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not getattr(current_user, "is_authenticated", False):
            flash("Please log in to access the admin portal.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        if not isinstance(current_user._get_current_object(), AdminUser):
            abort(403)
        if current_user.is_locked:
            logout_user()
            flash(
                "Your account is temporarily locked due to too many failed login attempts.",
                "error",
            )
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return wrapped


def super_admin_required(view_func):
    """Require the platform super admin role."""

    @admin_required
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user.role != "super_admin":
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


def institution_required(view_func):
    """Require an active institution context unless the user is a super admin."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        institution = getattr(g, "institution", None)
        if getattr(current_user, "is_super_admin", False) and institution is None:
            return view_func(*args, **kwargs)
        if institution is None:
            abort(403, description="Institution not found or inactive.")
        if not institution.is_active:
            flash("Institution not found or inactive.", "error")
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return wrapped


def api_key_required(view_func):
    """Authenticate API callers with the X API Key header."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        raw_key = request.headers.get("X-API-Key", "")
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest() if raw_key else ""
        institution = Institution.query.filter_by(api_key_hash=key_hash).first()
        if institution and institution.is_active:
            g.api_institution = institution
            return view_func(*args, **kwargs)

        portal_user = current_user._get_current_object() if getattr(current_user, "is_authenticated", False) else None
        if isinstance(portal_user, User) and portal_user.institution and portal_user.institution.is_active:
            g.api_institution = portal_user.institution
            g.api_portal_user = portal_user
            return view_func(*args, **kwargs)

        return error_response("Invalid or inactive API key", 401)

    return wrapped


def role_required(*roles):
    """Require the current admin user to have one of the listed roles."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not getattr(current_user, "is_authenticated", False):
                flash("Please log in to access the admin portal.", "warning")
                return redirect(url_for("auth.login", next=request.url))
            if current_user.role not in roles:
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def rate_limit_user(limit=10, per=60):
    """Apply a simple in memory per user rate limit to a route."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            now = time.time()
            endpoint = request.endpoint or view_func.__name__
            user_id = getattr(current_user, "id", "anonymous")
            key = f"ratelimit:{user_id}:{endpoint}"

            for store_key in list(_rate_limit_store.keys()):
                _rate_limit_store[store_key] = [
                    item for item in _rate_limit_store[store_key] if now - item < per
                ]
                if not _rate_limit_store[store_key]:
                    _rate_limit_store.pop(store_key, None)

            attempts = _rate_limit_store.setdefault(key, [])
            if len(attempts) >= limit:
                abort(429, description="Too many requests. Please try again later.")
            attempts.append(now)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def read_only_forbidden(view_func):
    """Block write actions for read only users."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if getattr(current_user, "role", None) == "read_only":
            flash("Read-only accounts cannot perform this action.", "error")
            return redirect(request.referrer or url_for("admin.dashboard"))
        return view_func(*args, **kwargs)

    return wrapped
