"""Step up verification challenge orchestration."""

from __future__ import annotations

from datetime import datetime, timedelta
import secrets
import sys


class StepUpOrchestrator:
    """Select and verify adaptive authentication challenges."""

    _challenges = {}

    METHOD_DESCRIPTIONS = {
        "push_notification": "A verification request has been sent to your registered mobile device.",
        "biometric": "Please authenticate using your device biometric.",
        "otp": "A verification code has been sent to your registered email address.",
        "video_kyc": "A video verification call will be initiated. Please keep your government ID ready.",
        "agent_call": "A TrustSphere security agent will call you on your registered number within 5 minutes.",
    }

    @classmethod
    def select_verification_method(cls, risk_score, channel, institution_id):
        """Return the policy selected verification method for a risk score."""
        try:
            risk_score = int(risk_score)
            channel = channel or "web_browser"

            from app.models import RiskPolicy

            policy = RiskPolicy.query.filter_by(
                institution_id=institution_id,
                is_active=True,
            ).first()
            if policy and policy.get_stepup_rules_list():
                method = policy.get_stepup_method(risk_score, channel)
                if method in {None, "", "none"}:
                    return None
                if method:
                    return method

            if risk_score <= 30:
                return None
            if risk_score <= 60:
                return "push_notification"
            if risk_score <= 80:
                return "otp"
            if risk_score <= 90:
                return "video_kyc"
            return "agent_call"
        except Exception as exc:
            print(f"[StepUpOrchestrator] Method selection failed: {exc}", file=sys.stderr)
            return "otp"

    @classmethod
    def create_challenge(cls, user_id, method, session_id, institution_id):
        """Create and store a verification challenge."""
        try:
            if method in {None, "", "none"}:
                return None
            challenge_id = secrets.token_urlsafe(16)
            timeout_seconds = 300 if method in {"video_kyc", "agent_call"} else 120
            expires_at = datetime.utcnow() + timedelta(seconds=timeout_seconds)
            otp_code = None

            if method == "otp":
                otp_code = str(secrets.randbelow(900000) + 100000)
                print(f"[DEMO SMS] OTP for user {user_id}: {otp_code}")
            elif method == "push_notification":
                otp_code = str(secrets.randbelow(9000) + 1000)

            cls._challenges[challenge_id] = {
                "user_id": user_id,
                "institution_id": institution_id,
                "method": method,
                "otp_code": otp_code,
                "created_at": datetime.utcnow(),
                "session_id": session_id,
                "expires_at": expires_at,
                "attempts": 0,
                "verified": False,
            }

            return {
                "challenge_id": challenge_id,
                "method": method,
                "instructions": cls.METHOD_DESCRIPTIONS.get(method, "Please complete verification."),
                "expires_at": expires_at.isoformat(),
                "timeout_seconds": timeout_seconds,
                "otp_code": otp_code,
            }
        except Exception as exc:
            print(f"[StepUpOrchestrator] Challenge creation failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def verify_challenge(cls, challenge_id, user_input, user_id):
        """Validate a challenge response."""
        try:
            challenge = cls._challenges.get(challenge_id)
            if not challenge:
                return False, "Invalid or expired challenge.", None
            if challenge.get("user_id") != user_id:
                return False, "Challenge user mismatch.", None
            if datetime.utcnow() >= challenge.get("expires_at"):
                return False, "Challenge has expired. Please try again.", None
            if challenge.get("verified") is True:
                return False, "Challenge already used.", None

            challenge["attempts"] = int(challenge.get("attempts") or 0) + 1
            if challenge["attempts"] > 3:
                cls._challenges.pop(challenge_id, None)
                return False, "Too many attempts. Challenge invalidated.", None

            method = challenge.get("method")
            verified = False
            if method == "otp":
                verified = str(user_input or "").strip() == str(challenge.get("otp_code") or "")
            elif method in {"push_notification", "biometric", "video_kyc", "agent_call"}:
                verified = True

            if verified:
                challenge["verified"] = True
                return True, "Verification successful.", 15
            return False, "Verification failed. Incorrect code.", None
        except Exception as exc:
            print(f"[StepUpOrchestrator] Challenge verification failed: {exc}", file=sys.stderr)
            return False, "Verification could not be completed.", None

    @classmethod
    def cleanup_expired_challenges(cls):
        """Remove expired challenges and return the number removed."""
        try:
            now = datetime.utcnow()
            expired_ids = [
                challenge_id
                for challenge_id, challenge in cls._challenges.items()
                if challenge.get("expires_at") and now >= challenge["expires_at"]
            ]
            for challenge_id in expired_ids:
                cls._challenges.pop(challenge_id, None)
            return len(expired_ids)
        except Exception as exc:
            print(f"[StepUpOrchestrator] Challenge cleanup failed: {exc}", file=sys.stderr)
            return 0

    @classmethod
    def get_challenge_status(cls, challenge_id):
        """Return the current status of a challenge."""
        try:
            challenge = cls._challenges.get(challenge_id)
            if not challenge:
                return {
                    "exists": False,
                    "verified": False,
                    "expired": False,
                    "attempts": 0,
                    "method": None,
                    "session_id": None,
                }
            expired = datetime.utcnow() >= challenge.get("expires_at")
            return {
                "exists": True,
                "verified": bool(challenge.get("verified")),
                "expired": expired,
                "attempts": int(challenge.get("attempts") or 0),
                "method": challenge.get("method"),
                "session_id": challenge.get("session_id"),
            }
        except Exception as exc:
            print(f"[StepUpOrchestrator] Challenge status failed: {exc}", file=sys.stderr)
            return {
                "exists": False,
                "verified": False,
                "expired": False,
                "attempts": 0,
                "method": None,
                "session_id": None,
            }
