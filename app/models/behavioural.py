"""Behavioural biometric profile model."""

from datetime import datetime
import json
import math
import uuid

from app.extensions import db


class BehaviouralProfile(db.Model):
    """Stored behavioural baseline for a user."""

    __tablename__ = "behavioural_profiles"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, unique=True)
    profile_version = db.Column(db.Integer, default=1)
    typing_rhythm_vector = db.Column(db.Text, nullable=True)
    mouse_pattern_vector = db.Column(db.Text, nullable=True)
    touch_pattern_vector = db.Column(db.Text, nullable=True)
    interaction_timing_vector = db.Column(db.Text, nullable=True)
    training_sessions_count = db.Column(db.Integer, default=0)
    confidence_level = db.Column(db.String(20), default="low")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="behavioural_profiles",
    )

    VECTOR_DEFAULT_LENGTHS = {
        "typing_rhythm_vector": 50,
        "mouse_pattern_vector": 40,
        "touch_pattern_vector": 40,
        "interaction_timing_vector": 30,
    }

    def get_vector(self, field_name):
        """Return a vector field as a list of floats."""
        if field_name not in self.VECTOR_DEFAULT_LENGTHS:
            raise ValueError(f"Unknown behavioural vector field: {field_name}")
        raw_value = getattr(self, field_name, None)
        if not raw_value:
            return [0.0] * self.VECTOR_DEFAULT_LENGTHS[field_name]
        try:
            values = json.loads(raw_value)
        except (TypeError, json.JSONDecodeError):
            return [0.0] * self.VECTOR_DEFAULT_LENGTHS[field_name]
        if not isinstance(values, list):
            return [0.0] * self.VECTOR_DEFAULT_LENGTHS[field_name]
        return [float(value) for value in values]

    def set_vector(self, field_name, vector_list):
        """Store a vector field as JSON."""
        if field_name not in self.VECTOR_DEFAULT_LENGTHS:
            raise ValueError(f"Unknown behavioural vector field: {field_name}")
        values = [float(value) for value in vector_list]
        setattr(self, field_name, json.dumps(values))

    def compute_similarity_score(self, current_vector_list):
        """Return behavioural deviation score from the stored typing baseline."""
        if self.confidence_level == "low" or not self.typing_rhythm_vector:
            return 30
        baseline = self.get_vector("typing_rhythm_vector")
        current = [float(value) for value in current_vector_list]
        if not baseline or not current:
            return 30
        length = min(len(baseline), len(current))
        baseline = baseline[:length]
        current = current[:length]
        dot_product = sum(left * right for left, right in zip(baseline, current))
        baseline_norm = math.sqrt(sum(value * value for value in baseline))
        current_norm = math.sqrt(sum(value * value for value in current))
        if baseline_norm == 0 or current_norm == 0:
            return 30
        similarity = dot_product / (baseline_norm * current_norm)
        similarity = max(min(similarity, 1), -1)
        deviation = (1 - similarity) * 50
        return round(max(min(deviation, 100), 0), 2)

    def update_profile(self, new_vector_list, alpha=0.1):
        """Update typing rhythm baseline using an exponential moving average."""
        current = [float(value) for value in new_vector_list]
        old = self.get_vector("typing_rhythm_vector")
        length = min(len(old), len(current))
        if length == 0:
            self.set_vector("typing_rhythm_vector", current)
        else:
            blended = [
                alpha * current[index] + (1 - alpha) * old[index]
                for index in range(length)
            ]
            self.set_vector("typing_rhythm_vector", blended)
        self.training_sessions_count = (self.training_sessions_count or 0) + 1
        if self.training_sessions_count < 5:
            self.confidence_level = "low"
        elif self.training_sessions_count <= 20:
            self.confidence_level = "medium"
        else:
            self.confidence_level = "high"
        self.updated_at = datetime.utcnow()

    def _stored_vector_length(self, field_name):
        raw_value = getattr(self, field_name, None)
        if not raw_value:
            return 0
        try:
            values = json.loads(raw_value)
        except (TypeError, json.JSONDecodeError):
            return 0
        return len(values) if isinstance(values, list) else 0

    def to_dict(self):
        """Return profile metadata without full vector values."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "profile_version": self.profile_version,
            "typing_rhythm_vector_length": self._stored_vector_length("typing_rhythm_vector"),
            "mouse_pattern_vector_length": self._stored_vector_length("mouse_pattern_vector"),
            "touch_pattern_vector_length": self._stored_vector_length("touch_pattern_vector"),
            "interaction_timing_vector_length": self._stored_vector_length("interaction_timing_vector"),
            "training_sessions_count": self.training_sessions_count,
            "confidence_level": self.confidence_level,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return (
            f"<BehaviouralProfile user={self.user_id[:8]} "
            f"confidence={self.confidence_level} sessions={self.training_sessions_count}>"
        )
