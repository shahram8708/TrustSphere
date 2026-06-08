"""Audit logging service for security relevant actions."""

from __future__ import annotations

import json
import sys

from flask import request

from app.extensions import db
from app.utils.ip_intel import get_client_ip


class AuditLogger:
    """Write audit events without disrupting request handling."""

    @classmethod
    def log(
        cls,
        actor_type,
        actor_id,
        action,
        actor_email=None,
        institution_id=None,
        target_type=None,
        target_id=None,
        details=None,
        ip_address=None,
        user_agent=None,
        commit=True,
    ):
        try:
            from app.models import AuditLog

            details_value = json.dumps(details, sort_keys=True) if isinstance(details, dict) else details
            entry = AuditLog(
                actor_type=actor_type,
                actor_id=actor_id,
                actor_email=actor_email,
                action=action,
                institution_id=institution_id,
                target_type=target_type,
                target_id=target_id,
                details=details_value,
                ip_address=ip_address,
                user_agent=(user_agent or "")[:500],
            )
            db.session.add(entry)
            if commit:
                db.session.commit()
            return True
        except Exception as exc:
            try:
                db.session.rollback()
            except Exception as rollback_exc:
                print(f"[AuditLogger] Rollback failed: {rollback_exc}", file=sys.stderr)
            print(f"[AuditLogger] Failed to write audit entry: {exc}", file=sys.stderr)
            return False

    @classmethod
    def log_from_request(cls, actor, action, target_type=None, target_id=None, details=None, commit=True):
        if actor == "system":
            return cls.log(
                actor_type="system",
                actor_id=None,
                actor_email=None,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details,
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("User-Agent", ""),
                commit=commit,
            )

        actor_type = "admin" if getattr(actor, "email", None) else "customer"
        return cls.log(
            actor_type=actor_type,
            actor_id=getattr(actor, "id", None),
            actor_email=getattr(actor, "email", None),
            action=action,
            institution_id=getattr(actor, "institution_id", None),
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent", ""),
            commit=commit,
        )

    @classmethod
    def log_login_success(cls, admin_user, request_obj, ip_city=None, ip_country=None):
        details = None
        if ip_city or ip_country:
            if ip_city and ip_country:
                location = f"{ip_city}, {ip_country}"
            elif ip_city:
                location = f"{ip_city}"
            else:
                location = f"{ip_country}"
            details = {"location": location}

        return cls.log(
            actor_type="admin",
            actor_id=admin_user.id,
            actor_email=admin_user.email,
            institution_id=admin_user.institution_id,
            action="login.success",
            details=details,
            ip_address=get_client_ip(request_obj),
            user_agent=request_obj.headers.get("User-Agent", ""),
        )

    @classmethod
    def log_login_failure(cls, email, request_obj, reason="Invalid credentials"):
        masked = ((email or "")[:3] + "***") if email else "***"
        return cls.log(
            actor_type="system",
            actor_id=None,
            actor_email=None,
            action="login.fail",
            details={"email_attempted": masked, "reason": reason},
            ip_address=get_client_ip(request_obj),
            user_agent=request_obj.headers.get("User-Agent", ""),
        )

    @classmethod
    def log_logout(cls, admin_user, request_obj):
        return cls.log(
            actor_type="admin",
            actor_id=admin_user.id,
            actor_email=admin_user.email,
            institution_id=admin_user.institution_id,
            action="logout",
            ip_address=get_client_ip(request_obj),
            user_agent=request_obj.headers.get("User-Agent", ""),
        )

    @classmethod
    def log_password_reset_request(cls, email, request_obj):
        masked = ((email or "")[:3] + "***") if email else "***"
        return cls.log(
            actor_type="system",
            actor_id=None,
            actor_email=None,
            action="password_reset.request",
            details={"email_attempted": masked},
            ip_address=get_client_ip(request_obj),
            user_agent=request_obj.headers.get("User-Agent", ""),
        )

    @classmethod
    def log_password_reset_complete(cls, target_type, target_id, request_obj):
        return cls.log(
            actor_type="system",
            actor_id=None,
            actor_email=None,
            action="password_reset.complete",
            target_type=target_type,
            target_id=target_id,
            ip_address=get_client_ip(request_obj),
            user_agent=request_obj.headers.get("User-Agent", ""),
        )
