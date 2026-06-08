"""Administrative user model for SOC access."""

from datetime import datetime, timedelta
import uuid

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


ROLE_PERMISSIONS = {
    "super_admin": ["*"],
    "security_analyst": [
        "view_alerts",
        "manage_alerts",
        "view_users",
        "view_sessions",
        "force_stepup",
        "view_audit_log",
    ],
    "compliance_officer": [
        "view_alerts",
        "view_reports",
        "view_audit_log",
        "review_onboarding",
        "manage_policy",
    ],
    "read_only": [
        "view_alerts",
        "view_users",
        "view_sessions",
        "view_reports",
        "view_audit_log",
    ],
    "it_admin": [
        "view_alerts",
        "manage_users",
        "manage_admin_users",
        "manage_policy",
        "view_sessions",
        "manage_integrations",
    ],
}


class AdminUser(UserMixin, db.Model):
    """TrustSphere administrator, analyst, or auditor."""

    __tablename__ = "admin_users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=True,
        index=True,
    )
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="security_analyst")
    _is_active = db.Column("is_active", db.Boolean, default=True, nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(256), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    login_ip_last = db.Column(db.String(45), nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    post_lock_verification_required = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    institution = db.relationship("Institution", back_populates="admin_users")
    assigned_alerts = db.relationship(
        "Alert",
        foreign_keys="Alert.assigned_to",
        back_populates="assigned_analyst",
        lazy="select",
    )
    created_policies = db.relationship(
        "RiskPolicy",
        foreign_keys="RiskPolicy.created_by",
        back_populates="creator",
        lazy="select",
    )
    reviewed_applications = db.relationship(
        "OnboardingApplication",
        foreign_keys="OnboardingApplication.reviewer_id",
        back_populates="reviewer",
        lazy="select",
    )

    def get_id(self):
        """Return Flask Login identifier."""
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return bool(self._is_active)

    @is_active.setter
    def is_active(self, value):
        self._is_active = bool(value)

    @property
    def is_anonymous(self):
        return False

    @property
    def is_locked(self):
        """Return true when the account lock window is active."""
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    @property
    def is_super_admin(self):
        """Return true for platform super administrators."""
        return self.role == "super_admin"

    def set_password(self, password):
        """Hash and store a password."""
        try:
            from passlib.hash import argon2

            self.password_hash = f"argon2${argon2.hash(password)}"
        except Exception:
            self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        """Verify a password against the stored hash."""
        if not self.password_hash:
            return False
        if self.password_hash.startswith("argon2$"):
            try:
                from passlib.hash import argon2

                return argon2.verify(password, self.password_hash.removeprefix("argon2$"))
            except Exception:
                return False
        return check_password_hash(self.password_hash, password)

    def lock_account(self, minutes=15):
        """Lock the account for a period of time."""
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        # Require verification after the lock period expires
        try:
            self.post_lock_verification_required = True
        except Exception:
            # Best-effort: if DB schema not migrated, avoid raising
            pass

    def unlock_account(self):
        """Unlock the account and clear failures."""
        self.locked_until = None
        self.failed_login_count = 0
        try:
            self.post_lock_verification_required = False
        except Exception:
            pass

    def increment_failed_login(self):
        """Track a failed login and lock after repeated failures."""
        self.failed_login_count = (self.failed_login_count or 0) + 1
        if self.failed_login_count >= 5:
            self.lock_account(15)

    def get_role_display(self):
        """Return human readable role."""
        return {
            "super_admin": "Super Admin",
            "security_analyst": "Security Analyst",
            "compliance_officer": "Compliance Officer",
            "read_only": "Read Only",
            "it_admin": "IT Admin",
        }.get(self.role, (self.role or "").replace("_", " ").title())

    def get_role_badge_color(self):
        """Return Bootstrap color class for role."""
        return {
            "super_admin": "danger",
            "security_analyst": "primary",
            "compliance_officer": "info",
            "read_only": "secondary",
            "it_admin": "warning",
        }.get(self.role, "secondary")

    def has_permission(self, permission):
        """Return true if the user's role grants a permission."""
        permissions = ROLE_PERMISSIONS.get(self.role, [])
        return "*" in permissions or permission in permissions

    def to_dict(self):
        """Return non sensitive admin fields."""
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "email": self.email,
            "role": self.role,
            "role_display": self.get_role_display(),
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "login_ip_last": self.login_ip_last,
            "failed_login_count": self.failed_login_count,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<AdminUser {self.email} role={self.role}>"
