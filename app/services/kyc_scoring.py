"""KYC onboarding fraud risk scoring."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
import sys

from app.extensions import db
from app.services.audit import AuditLogger


class KYCOnboardingScorer:
    """Evaluate onboarding applications with deterministic demo signals."""

    DEMO_WATCHLIST_HASHES = {
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in ("FRAUD001", "FRAUD002", "FRAUD003", "SYNTH001", "SYNTH002")
    }
    DOCUMENT_FORMATS = {
        "pan": r"^[A-Z]{5}[0-9]{4}[A-Z]$",
        "aadhaar": r"^\d{12}$",
        "passport": r"^[A-Z]\d{7}$",
        "driving_licence": r"^[A-Z]{2}\d{2}\s?\d{11}$",
    }

    @classmethod
    def score_application(cls, application):
        """Score and persist a KYC onboarding application."""
        try:
            application.document_authenticity_score = cls.simulate_document_authenticity_check(
                application.document_type,
                application.document_number_hash,
            )
            application.liveness_score = cls.simulate_liveness_check(application.id)
            if application.onboarding_behaviour_score is None:
                application.onboarding_behaviour_score = 0.85

            is_match, match_detail = cls.check_watchlist(application.document_number_hash)
            application.watchlist_match = is_match
            application.watchlist_match_detail = json.dumps(match_detail, sort_keys=True) if match_detail else None
            application.synthetic_identity_risk = cls.compute_synthetic_identity_risk(application)
            application.compute_composite_score()

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="onboarding.decision",
                institution_id=application.institution_id,
                target_type="onboarding_application",
                target_id=application.id,
                details={
                    "application_ref": application.application_ref,
                    "decision": application.decision,
                    "composite_risk_score": application.composite_risk_score,
                },
                commit=False,
            )
            db.session.add(application)
            db.session.commit()
            return application
        except Exception as exc:
            db.session.rollback()
            print(f"[KYCOnboardingScorer] Application scoring failed: {exc}", file=sys.stderr)
            return application

    @classmethod
    def simulate_document_authenticity_check(cls, document_type, document_number_hash):
        """Return a deterministic document authenticity score."""
        try:
            document_hash = str(document_number_hash or "")
            if len(document_hash) < 8:
                document_hash = hashlib.sha256(document_hash.encode("utf-8")).hexdigest()
            if document_hash.startswith(("00", "ff")):
                return 0.25
            value = int(document_hash[:8], 16) % 100
            if value <= 10:
                return round(0.10 + (value / 10) * 0.30, 2)
            if value <= 20:
                return round(0.50 + ((value - 11) / 9) * 0.10, 2)
            return round(0.75 + ((value - 21) / 78) * 0.24, 2)
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Document check failed: {exc}", file=sys.stderr)
            return 0.75

    @classmethod
    def simulate_liveness_check(cls, application_id):
        """Return a deterministic liveness score."""
        try:
            digest = hashlib.sha256(str(application_id or "").encode("utf-8")).hexdigest()
            value = int(digest[:8], 16) % 100
            if value <= 5:
                return 0.15
            if value <= 15:
                return 0.45
            return round(0.82 + (value % 18) / 100.0, 2)
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Liveness check failed: {exc}", file=sys.stderr)
            return 0.82

    @classmethod
    def check_watchlist(cls, document_number_hash):
        """Check the deterministic demo watchlist."""
        try:
            if document_number_hash in cls.DEMO_WATCHLIST_HASHES:
                return True, {
                    "list_name": "OFAC Sanctions",
                    "match_type": "exact",
                    "matched_at": datetime.utcnow().isoformat(),
                    "risk_level": "high",
                }
            return False, {}
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Watchlist check failed: {exc}", file=sys.stderr)
            return False, {}

    @classmethod
    def compute_synthetic_identity_risk(cls, application):
        """Compute simple additive synthetic identity risk."""
        try:
            risk = 0.0
            if application.watchlist_match:
                risk += 0.4
            if (application.document_authenticity_score or 0) < 0.5:
                risk += 0.3
            if (application.liveness_score or 0) < 0.5:
                risk += 0.2
            if (application.onboarding_behaviour_score or 0) < 0.3:
                risk += 0.2
            return round(min(risk, 1.0), 2)
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Synthetic risk failed: {exc}", file=sys.stderr)
            return 0.0

    @classmethod
    def generate_risk_factor_report(cls, application):
        """Return display friendly factor details for an onboarding application."""
        try:
            factors = [
                cls._score_factor(
                    "Document Authenticity",
                    application.document_authenticity_score,
                    0.35,
                    True,
                    "Measures whether the submitted identity document appears genuine.",
                ),
                cls._score_factor(
                    "Liveness",
                    application.liveness_score,
                    0.30,
                    True,
                    "Measures whether the applicant appears to be present and live.",
                ),
                cls._score_factor(
                    "Onboarding Behaviour",
                    application.onboarding_behaviour_score,
                    0.20,
                    True,
                    "Measures whether the signup interaction pattern appears human and consistent.",
                ),
                cls._score_factor(
                    "Watchlist",
                    1.0 if application.watchlist_match else 0.0,
                    0.15,
                    False,
                    "Checks the document hash against the configured sanctions demo list.",
                ),
                cls._score_factor(
                    "Synthetic Identity",
                    application.synthetic_identity_risk,
                    0.15,
                    False,
                    "Combines weak document, liveness, behaviour, and watchlist signals.",
                ),
            ]
            return factors
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Risk factor report failed: {exc}", file=sys.stderr)
            return []

    @classmethod
    def validate_document_format(cls, document_type, document_number_plain):
        """Validate document number format for supported document types."""
        try:
            pattern = cls.DOCUMENT_FORMATS.get(document_type)
            if not pattern:
                return False, "Unsupported document type."
            value = str(document_number_plain or "").strip().upper()
            if re.fullmatch(pattern, value):
                return True, ""
            return False, "Document number format is invalid."
        except Exception as exc:
            print(f"[KYCOnboardingScorer] Document format validation failed: {exc}", file=sys.stderr)
            return False, "Document number could not be validated."

    @staticmethod
    def _score_factor(factor, score, weight, higher_is_better, explanation):
        value = float(score or 0)
        if higher_is_better:
            risk_value = 1.0 - max(0.0, min(1.0, value))
            verdict = "Pass" if value >= 0.75 else "Warning" if value >= 0.5 else "Fail"
        else:
            risk_value = max(0.0, min(1.0, value))
            verdict = "Pass" if value < 0.3 else "Warning" if value < 0.7 else "Fail"
        return {
            "factor": factor,
            "score": round(value, 2),
            "weight": weight,
            "contribution": round(risk_value * weight * 100, 2),
            "verdict": verdict,
            "explanation": explanation,
        }
