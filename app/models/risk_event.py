"""Risk signal evaluation events."""

from datetime import datetime
import json
import uuid

from app.extensions import db


class RiskEvent(db.Model):
    """Risk engine evaluation event within a session."""

    __tablename__ = "risk_events"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(
        db.String(36),
        db.ForeignKey("session_records.id"),
        nullable=False,
        index=True,
    )
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    risk_score_before = db.Column(db.Integer, nullable=False)
    risk_score_after = db.Column(db.Integer, nullable=False)
    contributing_factors = db.Column(db.Text, nullable=True)
    cre_response_action = db.Column(db.String(20), nullable=False, index=True)
    event_metadata = db.Column(db.Text, nullable=True)
    evaluated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    processing_ms = db.Column(db.Integer, nullable=True)

    session = db.relationship("SessionRecord", back_populates="risk_events")

    @property
    def risk_delta(self):
        """Return risk movement caused by this event."""
        return (self.risk_score_after or 0) - (self.risk_score_before or 0)

    def get_contributing_factors_dict(self):
        """Return parsed contributing factors."""
        return self._load_json_dict(self.contributing_factors)

    def get_event_metadata_dict(self):
        """Return parsed event metadata."""
        return self._load_json_dict(self.event_metadata)

    @staticmethod
    def _load_json_dict(raw_value):
        if not raw_value:
            return {}
        try:
            value = json.loads(raw_value)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def get_action_badge_color(self):
        """Return Bootstrap color class for the CRE action."""
        return {
            "allow": "success",
            "monitor": "info",
            "stepup": "warning",
            "block": "danger",
        }.get(self.cre_response_action, "secondary")

    def to_dict(self):
        """Return all risk event fields."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "institution_id": self.institution_id,
            "event_type": self.event_type,
            "risk_score_before": self.risk_score_before,
            "risk_score_after": self.risk_score_after,
            "risk_delta": self.risk_delta,
            "contributing_factors": self.get_contributing_factors_dict(),
            "cre_response_action": self.cre_response_action,
            "event_metadata": self.get_event_metadata_dict(),
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
            "processing_ms": self.processing_ms,
        }

    def __repr__(self):
        return (
            f"<RiskEvent {self.event_type} {self.risk_score_before}->{self.risk_score_after} "
            f"action={self.cre_response_action}>"
        )
