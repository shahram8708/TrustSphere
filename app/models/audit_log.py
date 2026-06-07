"""Immutable audit log model."""

from datetime import datetime
import json
import sys

from sqlalchemy import inspect

from app.extensions import db


class AuditLog(db.Model):
    """Append only audit trail for security relevant actions."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    institution_id = db.Column(db.String(36), nullable=True, index=True)
    actor_type = db.Column(db.String(20), nullable=False)
    actor_id = db.Column(db.String(36), nullable=True)
    actor_email = db.Column(db.String(200), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def __setattr__(self, key, value):
        """Prevent changes to persistent audit rows."""
        if not key.startswith("_"):
            try:
                state = inspect(self)
                if state.persistent:
                    raise RuntimeError("AuditLog records are immutable")
            except RuntimeError:
                raise
            except Exception:
                state = None
        super().__setattr__(key, value)

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
    ):
        """Create and commit an audit log entry without disrupting caller flow."""
        try:
            details_value = json.dumps(details, sort_keys=True) if isinstance(details, dict) else details
            entry = cls(
                actor_type=actor_type,
                actor_id=actor_id,
                actor_email=actor_email,
                action=action,
                institution_id=institution_id,
                target_type=target_type,
                target_id=target_id,
                details=details_value,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.session.add(entry)
            db.session.commit()
            return entry
        except Exception as exc:
            db.session.rollback()
            print(f"[AuditLog] Failed to write audit entry: {exc}", file=sys.stderr)
            return None

    def get_details_dict(self):
        """Return parsed audit details."""
        if not self.details:
            return {}
        try:
            value = json.loads(self.details)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def to_dict(self):
        """Return all audit log fields."""
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.get_details_dict(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<AuditLog #{self.id} {self.action} by {self.actor_type}>"
