"""KYC onboarding application model."""

from datetime import datetime
import json
import uuid

from app.extensions import db


class OnboardingApplication(db.Model):
    """KYC onboarding record with composite risk assessment."""

    __tablename__ = "onboarding_applications"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(
        db.String(36),
        db.ForeignKey("institutions.id"),
        nullable=False,
        index=True,
    )
    application_ref = db.Column(db.String(50), unique=True, nullable=False)
    applicant_name = db.Column(db.String(200), nullable=True)
    document_type = db.Column(db.String(30), nullable=False)
    document_number_hash = db.Column(db.String(64), nullable=False)
    liveness_score = db.Column(db.Float, default=0.0)
    document_authenticity_score = db.Column(db.Float, default=0.0)
    onboarding_behaviour_score = db.Column(db.Float, default=0.0)
    watchlist_match = db.Column(db.Boolean, default=False)
    watchlist_match_detail = db.Column(db.Text, nullable=True)
    synthetic_identity_risk = db.Column(db.Float, default=0.0)
    composite_risk_score = db.Column(db.Integer, default=0)
    decision = db.Column(db.String(20), default="pending")
    reviewer_id = db.Column(db.String(36), db.ForeignKey("admin_users.id"), nullable=True)
    reviewer_notes = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    decided_at = db.Column(db.DateTime, nullable=True)

    institution = db.relationship("Institution", back_populates="onboarding_applications")
    reviewer = db.relationship(
        "AdminUser",
        foreign_keys=[reviewer_id],
        back_populates="reviewed_applications",
    )

    def compute_composite_score(self):
        """Compute and store onboarding risk score and decision."""
        score = (
            (1 - min(max(self.document_authenticity_score or 0, 0), 1)) * 35
            + (1 - min(max(self.liveness_score or 0, 0), 1)) * 30
            + (1 - min(max(self.onboarding_behaviour_score or 0, 0), 1)) * 20
            + (15 if self.watchlist_match else 0)
        )
        score += min(max(self.synthetic_identity_risk or 0, 0), 1) * 15
        self.composite_risk_score = int(round(min(score, 100)))
        if self.composite_risk_score < 40:
            self.decision = "approve"
        elif self.composite_risk_score <= 70:
            self.decision = "manual_review"
        else:
            self.decision = "reject"
        return self.composite_risk_score

    def get_decision_badge_color(self):
        """Return Bootstrap color class for the decision."""
        return {
            "approve": "success",
            "manual_review": "warning",
            "pending": "warning",
            "reject": "danger",
        }.get(self.decision, "secondary")

    def get_risk_flags_list(self):
        """Return active onboarding risk flags."""
        flags = []
        if self.synthetic_identity_risk and self.synthetic_identity_risk >= 0.5:
            flags.append("Synthetic Identity Risk")
        if self.liveness_score is not None and self.liveness_score < 0.5:
            flags.append("Liveness Check Failed")
        if self.document_authenticity_score is not None and self.document_authenticity_score < 0.7:
            flags.append("Document Authenticity Risk")
        if self.onboarding_behaviour_score is not None and self.onboarding_behaviour_score < 0.5:
            flags.append("Bot Like Onboarding Behaviour")
        if self.watchlist_match:
            flags.append("Watchlist Match")
        return flags

    def get_watchlist_match_detail_dict(self):
        """Return parsed watchlist details."""
        if not self.watchlist_match_detail:
            return {}
        try:
            value = json.loads(self.watchlist_match_detail)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def to_dict(self):
        """Return all onboarding application fields."""
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "application_ref": self.application_ref,
            "applicant_name": self.applicant_name,
            "document_type": self.document_type,
            "document_number_hash": self.document_number_hash,
            "liveness_score": self.liveness_score,
            "document_authenticity_score": self.document_authenticity_score,
            "onboarding_behaviour_score": self.onboarding_behaviour_score,
            "watchlist_match": self.watchlist_match,
            "watchlist_match_detail": self.get_watchlist_match_detail_dict(),
            "synthetic_identity_risk": self.synthetic_identity_risk,
            "composite_risk_score": self.composite_risk_score,
            "decision": self.decision,
            "reviewer_id": self.reviewer_id,
            "reviewer_notes": self.reviewer_notes,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "risk_flags": self.get_risk_flags_list(),
        }

    def __repr__(self):
        return (
            f"<OnboardingApplication {self.application_ref} "
            f"decision={self.decision} risk={self.composite_risk_score}>"
        )
