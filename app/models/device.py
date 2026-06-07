"""Device intelligence model."""

from datetime import datetime
import uuid

from app.extensions import db


class Device(db.Model):
    """Registered or observed device fingerprint."""

    __tablename__ = "devices"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    device_fingerprint_hash = db.Column(db.String(64), nullable=False, index=True)
    device_name = db.Column(db.String(100), default="Unknown Device")
    device_type = db.Column(db.String(30), default="desktop")
    os_family = db.Column(db.String(50), nullable=True)
    browser_family = db.Column(db.String(50), nullable=True)
    trust_level = db.Column(db.String(20), default="new", index=True)
    is_rooted = db.Column(db.Boolean, default=False)
    is_emulator = db.Column(db.Boolean, default=False)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_removed = db.Column(db.Boolean, default=False)

    user = db.relationship("User", back_populates="devices")
    sessions = db.relationship("SessionRecord", back_populates="device", lazy="select")

    def get_trust_badge_color(self):
        """Return Bootstrap color class for device trust."""
        return {
            "trusted": "success",
            "known": "info",
            "new": "warning",
            "suspicious": "danger",
        }.get(self.trust_level, "secondary")

    def get_trust_score(self):
        """Return a device risk contribution score."""
        score = {
            "trusted": 5,
            "known": 20,
            "new": 60,
            "suspicious": 90,
        }.get(self.trust_level, 60)
        if self.is_rooted:
            score += 15
        if self.is_emulator:
            score += 10
        return min(score, 100)

    def get_device_icon(self):
        """Return a Bootstrap Icons class for the device."""
        return {
            "mobile": "bi-phone",
            "desktop": "bi-laptop",
            "tablet": "bi-tablet",
        }.get(self.device_type, "bi-device-hdd")

    def to_dict(self):
        """Return all device fields."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "institution_id": self.institution_id,
            "device_fingerprint_hash": self.device_fingerprint_hash,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "os_family": self.os_family,
            "browser_family": self.browser_family,
            "trust_level": self.trust_level,
            "trust_score": self.get_trust_score(),
            "is_rooted": self.is_rooted,
            "is_emulator": self.is_emulator,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "is_removed": self.is_removed,
        }

    def __repr__(self):
        return f"<Device {self.device_name} trust={self.trust_level}>"
