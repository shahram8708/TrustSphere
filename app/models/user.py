"""End customer and employee identity model."""

from datetime import datetime, timedelta
import uuid

from flask_login import UserMixin
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class User(db.Model, UserMixin):
    """Bank customer or employee monitored by TrustSphere."""

    __tablename__ = "users"
    __table_args__ = (
        db.Index("ix_users_institution_email", "institution_id", "email"),
    )

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    external_user_id = db.Column(db.String(100), nullable=True)
    user_type = db.Column(db.String(20), nullable=False, default="customer")
    display_name = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(200), nullable=True, index=True)
    phone = db.Column(db.String(32), nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    risk_score_current = db.Column(db.Integer, default=25, nullable=False)
    risk_score_updated_at = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    post_lock_verification_required = db.Column(db.Boolean, default=False, nullable=False)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    config_json = db.Column(db.Text, nullable=True)
    behavioural_profile_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "behavioural_profiles.id",
            use_alter=True,
            name="fk_users_behavioural_profile_id",
        ),
        nullable=True,
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active_at = db.Column(db.DateTime, nullable=True)

    institution = db.relationship("Institution", back_populates="users")
    devices = db.relationship("Device", back_populates="user", lazy="select")
    sessions = db.relationship("SessionRecord", back_populates="user", lazy="select")
    alerts = db.relationship("Alert", back_populates="user", lazy="select")
    privileged_sessions = db.relationship(
        "PrivilegedSession",
        back_populates="employee",
        lazy="select",
    )
    behavioural_profiles = db.relationship(
        "BehaviouralProfile",
        foreign_keys="BehaviouralProfile.user_id",
        back_populates="user",
        lazy="select",
    )
    behavioural_profile = db.relationship(
        "BehaviouralProfile",
        foreign_keys=[behavioural_profile_id],
        uselist=False,
        post_update=True,
    )

    def get_id(self):
        """Return the Flask Login identifier."""
        return str(self.id)

    def set_password(self, password):
        """Hash and store a password for the end user."""
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

    @property
    def is_active(self):
        """Return true when the customer account is allowed to sign in."""
        return not bool(self.is_suspended)

    @property
    def is_locked(self):
        """Return true when the account lock window is active."""
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def lock_account(self, minutes=15):
        """Lock the account for a period of time and require verification after expiry."""
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.post_lock_verification_required = True

    def unlock_account(self):
        """Unlock the account and clear failures and post-lock verification requirement."""
        self.locked_until = None
        self.failed_login_count = 0
        self.post_lock_verification_required = False

    def increment_failed_login(self):
        """Track a failed login and lock after repeated failures."""
        self.failed_login_count = (self.failed_login_count or 0) + 1
        if self.failed_login_count >= 2:
            self.lock_account(1)

    def get_risk_category(self):
        """Return the risk category for the current risk score."""
        score = self.risk_score_current or 0
        if score <= 30:
            return "Low"
        if score <= 60:
            return "Medium"
        if score <= 80:
            return "High"
        return "Critical"

    def get_risk_color(self):
        """Return a Bootstrap color class for the current risk score."""
        category = self.get_risk_category()
        return {
            "Low": "success",
            "Medium": "warning",
            "High": "danger",
            "Critical": "danger",
        }[category]

    def get_masked_id(self):
        """Return a privacy preserving identifier."""
        return f"{self.id[:8]}***" if self.id else "***"

    def get_user_type_badge(self):
        """Return a Bootstrap badge for the user type."""
        styles = {
            "customer": "bg-primary",
            "employee": "bg-info text-dark",
            "admin": "bg-warning text-dark",
        }
        label = (self.user_type or "customer").replace("_", " ").title()
        badge_class = styles.get(self.user_type, "bg-secondary")
        return Markup(f'<span class="badge {badge_class}">{label}</span>')

    def to_dict(self):
        """Return non sensitive user fields."""
        return {
            "id": self.id,
            "masked_id": self.get_masked_id(),
            "institution_id": self.institution_id,
            "user_type": self.user_type,
            "display_name": self.display_name,
            "risk_score_current": self.risk_score_current,
            "risk_category": self.get_risk_category(),
            "is_suspended": self.is_suspended,
            "behavioural_profile_id": self.behavioural_profile_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_active_at": self.last_active_at.isoformat() if self.last_active_at else None,
        }

    def __repr__(self):
        return f"<User {self.id[:8]} type={self.user_type} risk={self.risk_score_current}>"
