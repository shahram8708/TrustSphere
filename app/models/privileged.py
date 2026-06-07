"""Privileged access monitoring model."""

from datetime import datetime
import json
import uuid

from app.extensions import db


class PrivilegedSession(db.Model):
    """Employee privileged access session."""

    __tablename__ = "privileged_sessions"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    employee_user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    role = db.Column(db.String(50), nullable=True)
    privilege_level = db.Column(db.String(20), default="standard")
    system_accessed = db.Column(db.String(100), nullable=True)
    actions_count = db.Column(db.Integer, default=0)
    data_records_accessed = db.Column(db.Integer, default=0)
    export_volume_kb = db.Column(db.Integer, default=0)
    anomaly_flags = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, default=0, index=True)
    alert_generated = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ended_at = db.Column(db.DateTime, nullable=True)

    employee = db.relationship(
        "User",
        foreign_keys=[employee_user_id],
        back_populates="privileged_sessions",
    )
    institution = db.relationship("Institution", back_populates="privileged_sessions")

    @property
    def duration_hours(self):
        """Return duration in hours."""
        if not self.started_at:
            return 0
        end_time = self.ended_at or datetime.utcnow()
        try:
            return round((end_time - self.started_at).total_seconds() / 3600, 2)
        except TypeError:
            return 0

    @property
    def is_active(self):
        """Return true when the privileged session is still open."""
        return self.ended_at is None

    def get_anomaly_flags_dict(self):
        """Return parsed anomaly flags."""
        if not self.anomaly_flags:
            return {}
        try:
            value = json.loads(self.anomaly_flags)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def get_anomaly_count(self):
        """Return count of active anomaly flags."""
        return len(self.get_anomaly_flags_dict())

    def get_risk_category(self):
        """Return risk category for privileged access score."""
        score = self.risk_score or 0
        if score <= 30:
            return "Low"
        if score <= 60:
            return "Medium"
        if score <= 80:
            return "High"
        return "Critical"

    def to_dict(self):
        """Return all privileged session fields."""
        return {
            "id": self.id,
            "employee_user_id": self.employee_user_id,
            "institution_id": self.institution_id,
            "role": self.role,
            "privilege_level": self.privilege_level,
            "system_accessed": self.system_accessed,
            "actions_count": self.actions_count,
            "data_records_accessed": self.data_records_accessed,
            "export_volume_kb": self.export_volume_kb,
            "anomaly_flags": self.get_anomaly_flags_dict(),
            "risk_score": self.risk_score,
            "risk_category": self.get_risk_category(),
            "alert_generated": self.alert_generated,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_hours": self.duration_hours,
            "is_active": self.is_active,
        }

    def __repr__(self):
        return f"<PrivilegedSession employee={self.employee_user_id[:8]} risk={self.risk_score}>"
