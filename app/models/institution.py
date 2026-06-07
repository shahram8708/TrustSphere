"""Institution model for tenant isolation."""

from datetime import datetime
import hashlib
import json
import secrets
import uuid

from app.extensions import db


class Institution(db.Model):
    """Bank or financial institution using TrustSphere."""

    __tablename__ = "institutions"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(100), unique=True, nullable=False)
    api_key_hash = db.Column(db.String(64), nullable=True)
    plan_tier = db.Column(db.String(20), nullable=False, default="starter")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    config_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    users = db.relationship("User", back_populates="institution", lazy="select")
    admin_users = db.relationship("AdminUser", back_populates="institution", lazy="select")
    alerts = db.relationship("Alert", back_populates="institution", lazy="select")
    sessions = db.relationship("SessionRecord", back_populates="institution", lazy="select")
    policies = db.relationship("RiskPolicy", back_populates="institution", lazy="select")
    onboarding_applications = db.relationship(
        "OnboardingApplication",
        back_populates="institution",
        lazy="select",
    )
    privileged_sessions = db.relationship(
        "PrivilegedSession",
        back_populates="institution",
        lazy="select",
    )
    audit_logs = db.relationship(
        "AuditLog",
        primaryjoin="Institution.id == foreign(AuditLog.institution_id)",
        lazy="select",
        viewonly=True,
    )

    @classmethod
    def generate_api_key(cls):
        """Generate a raw API key and its SHA256 hash."""
        raw_key = secrets.token_hex(32)
        hash_string = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return raw_key, hash_string

    def get_config(self):
        """Return parsed institution configuration."""
        if not self.config_json:
            return {}
        try:
            value = json.loads(self.config_json)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def set_config(self, config_dict):
        """Store institution configuration as JSON."""
        self.config_json = json.dumps(config_dict or {}, sort_keys=True)

    def get_plan_display(self):
        """Return the human readable plan tier."""
        return {
            "starter": "Starter",
            "growth": "Growth",
            "enterprise": "Enterprise",
        }.get(self.plan_tier, self.plan_tier.title())

    def to_dict(self):
        """Return public institution fields."""
        return {
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "plan_tier": self.plan_tier,
            "plan_display": self.get_plan_display(),
            "is_active": self.is_active,
            "config": self.get_config(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f"<Institution {self.name}>"
