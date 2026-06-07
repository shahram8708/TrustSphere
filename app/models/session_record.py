"""Session record model for user activity monitoring."""

from datetime import datetime
import uuid

from app.extensions import db


class SessionRecord(db.Model):
    """Individual digital banking session."""

    __tablename__ = "session_records"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    device_id = db.Column(db.String(36), db.ForeignKey("devices.id"), nullable=True)
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    ip_address = db.Column(db.String(45), nullable=True)
    ip_country = db.Column(db.String(2), nullable=True)
    ip_city = db.Column(db.String(100), nullable=True)
    channel = db.Column(db.String(30), default="web_browser")
    session_token_hash = db.Column(db.String(64), nullable=True)
    risk_score_initial = db.Column(db.Integer, default=25)
    risk_score_peak = db.Column(db.Integer, default=25, index=True)
    risk_score_final = db.Column(db.Integer, default=25)
    stepup_triggered = db.Column(db.Boolean, default=False)
    stepup_outcome = db.Column(db.String(20), default="none")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ended_at = db.Column(db.DateTime, nullable=True)
    is_flagged = db.Column(db.Boolean, default=False, index=True)

    institution = db.relationship("Institution", back_populates="sessions")
    user = db.relationship("User", back_populates="sessions")
    device = db.relationship("Device", back_populates="sessions")
    risk_events = db.relationship("RiskEvent", back_populates="session", lazy="select")
    alerts = db.relationship("Alert", back_populates="session", lazy="select")

    @property
    def is_active(self):
        """Return true when the session is still open."""
        return self.ended_at is None

    @property
    def duration_minutes(self):
        """Return session duration in minutes."""
        if not self.started_at:
            return 0
        end_time = self.ended_at or datetime.utcnow()
        try:
            return round((end_time - self.started_at).total_seconds() / 60, 1)
        except TypeError:
            return 0

    def get_risk_category(self):
        """Return risk category for peak session risk."""
        score = self.risk_score_peak or 0
        if score <= 30:
            return "Low"
        if score <= 60:
            return "Medium"
        if score <= 80:
            return "High"
        return "Critical"

    def get_channel_icon(self):
        """Return a Bootstrap Icons class for the channel."""
        return {
            "mobile_app": "bi-phone",
            "web_browser": "bi-globe2",
            "api": "bi-code-slash",
            "atm": "bi-bank",
        }.get(self.channel, "bi-activity")

    def to_dict(self):
        """Return all session fields."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "institution_id": self.institution_id,
            "ip_address": self.ip_address,
            "ip_country": self.ip_country,
            "ip_city": self.ip_city,
            "channel": self.channel,
            "session_token_hash": self.session_token_hash,
            "risk_score_initial": self.risk_score_initial,
            "risk_score_peak": self.risk_score_peak,
            "risk_score_final": self.risk_score_final,
            "risk_category": self.get_risk_category(),
            "stepup_triggered": self.stepup_triggered,
            "stepup_outcome": self.stepup_outcome,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "is_flagged": self.is_flagged,
            "is_active": self.is_active,
            "duration_minutes": self.duration_minutes,
        }

    def __repr__(self):
        return f"<SessionRecord {self.id[:8]} risk_peak={self.risk_score_peak} active={self.is_active}>"
