"""Risk policy model."""

from datetime import datetime
import json
import uuid

from app.extensions import db


class RiskPolicy(db.Model):
    """Configurable risk policy for an institution."""

    __tablename__ = "risk_policies"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    policy_name = db.Column(db.String(100), nullable=False)
    threshold_low = db.Column(db.Integer, default=30)
    threshold_medium = db.Column(db.Integer, default=60)
    threshold_high = db.Column(db.Integer, default=80)
    stepup_rules = db.Column(db.Text, nullable=True)
    channel_policies = db.Column(db.Text, nullable=True)
    ml_weight_config = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=False, index=True)
    created_by = db.Column(db.String(36), db.ForeignKey("admin_users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activated_at = db.Column(db.DateTime, nullable=True)

    institution = db.relationship("Institution", back_populates="policies")
    creator = db.relationship(
        "AdminUser",
        foreign_keys=[created_by],
        back_populates="created_policies",
    )

    def _parse_json(self, raw_value, fallback):
        if not raw_value:
            return fallback
        try:
            value = json.loads(raw_value)
            return value if isinstance(value, type(fallback)) else fallback
        except (TypeError, json.JSONDecodeError):
            return fallback

    def get_stepup_rules_list(self):
        """Return parsed step up rules."""
        return self._parse_json(self.stepup_rules, [])

    def get_stepup_method(self, risk_score, channel="web_browser"):
        """Return the matching verification method for a risk score."""
        for rule in self.get_stepup_rules_list():
            risk_min = int(rule.get("risk_min", 0))
            risk_max = int(rule.get("risk_max", 100))
            rule_channel = rule.get("channel", "all")
            if risk_min <= risk_score <= risk_max and rule_channel in {"all", channel}:
                return rule.get("verification_method", "otp")
        return "otp"

    def get_risk_category_for_score(self, score):
        """Map a score to a risk category using policy thresholds."""
        if score <= self.threshold_low:
            return "Low"
        if score <= self.threshold_medium:
            return "Medium"
        if score <= self.threshold_high:
            return "High"
        return "Critical"

    def validate_thresholds(self):
        """Return true when thresholds are strictly ascending."""
        return self.threshold_low < self.threshold_medium < self.threshold_high < 100

    def to_dict(self):
        """Return all policy fields with parsed JSON."""
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "policy_name": self.policy_name,
            "threshold_low": self.threshold_low,
            "threshold_medium": self.threshold_medium,
            "threshold_high": self.threshold_high,
            "stepup_rules": self.get_stepup_rules_list(),
            "channel_policies": self._parse_json(self.channel_policies, {}),
            "ml_weight_config": self._parse_json(self.ml_weight_config, {}),
            "is_active": self.is_active,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "thresholds_valid": self.validate_thresholds(),
        }

    def __repr__(self):
        return f"<RiskPolicy {self.policy_name} active={self.is_active}>"
