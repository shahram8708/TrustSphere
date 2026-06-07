"""Behavioural biometric feature extraction and profile maintenance."""

from __future__ import annotations

from collections import Counter
import math
import statistics
import sys

from app.extensions import db


class BehaviouralBiometricsService:
    """Process passive interaction signals and maintain user baselines."""

    FEATURE_NAMES = (
        "mean_iki",
        "std_iki",
        "dwell_time_letters",
        "dwell_time_numbers",
        "error_rate",
        "scroll_velocity_mean",
        "scroll_velocity_var",
        "click_iat",
        "field_nav_entropy",
        "touch_pressure_mean",
    )

    DEFAULT_VECTOR = [150.0, 30.0, 80.0, 90.0, 0.05, 2.5, 1.0, 800.0, 1.5, 0.5]

    @classmethod
    def process_sdk_payload(cls, user_id, sdk_payload_dict=None):
        """Convert SDK telemetry into a normalized ten feature vector."""
        try:
            if sdk_payload_dict is None and isinstance(user_id, dict):
                payload = user_id
            else:
                payload = sdk_payload_dict or {}
            typing_events = cls._list(payload.get("typing_events"))
            scroll_events = cls._list(payload.get("scroll_events"))
            mouse_events = cls._list(payload.get("mouse_events"))
            form_events = cls._list(payload.get("form_events"))
            touch_events = cls._list(payload.get("touch_events"))

            iki_values = cls._numbers(event.get("iki_ms") for event in typing_events)
            dwell_letters = cls._numbers(
                event.get("dwell_ms")
                for event in typing_events
                if event.get("key_type") == "letter"
            )
            dwell_numbers = cls._numbers(
                event.get("dwell_ms")
                for event in typing_events
                if event.get("key_type") == "number"
            )
            scroll_values = cls._numbers(event.get("velocity_pxms") for event in scroll_events)
            click_values = cls._numbers(event.get("click_iat_ms") for event in mouse_events)
            pressure_values = cls._numbers(event.get("pressure") for event in touch_events)

            typing_count = len(typing_events)
            backspaces = sum(1 for event in typing_events if event.get("key_type") == "backspace")
            error_rate = backspaces / typing_count if typing_count else 0.05

            vector = [
                cls._mean(iki_values, 150.0),
                cls._stdev(iki_values, 30.0),
                cls._mean(dwell_letters, 80.0),
                cls._mean(dwell_numbers, 90.0),
                float(error_rate),
                cls._mean(scroll_values, 2.5),
                cls._variance(scroll_values, 1.0),
                cls._mean(click_values, 800.0),
                cls._field_nav_entropy(form_events),
                cls._mean(pressure_values, 0.5),
            ]
            return cls._normalize(vector)
        except Exception as exc:
            print(f"[BehaviouralBiometricsService] Payload processing failed: {exc}", file=sys.stderr)
            return cls._normalize(cls.DEFAULT_VECTOR)

    @classmethod
    def compute_deviation_score(cls, user_id, current_vector):
        """Compare a current vector against the active behavioural profile."""
        try:
            from app.models import BehaviouralProfile

            profile = BehaviouralProfile.query.filter_by(user_id=user_id, is_active=True).first()
            if not profile or profile.confidence_level == "low":
                return 30
            baseline = profile.get_vector("typing_rhythm_vector")
            current = [float(value) for value in (current_vector or [])]
            if not baseline or not current:
                return 30

            length = min(len(baseline), len(current))
            baseline = baseline[:length]
            current = current[:length]
            dot_product = sum(left * right for left, right in zip(baseline, current))
            norm1 = math.sqrt(sum(value * value for value in baseline))
            norm2 = math.sqrt(sum(value * value for value in current))
            if norm1 == 0 or norm2 == 0:
                return 30

            similarity = dot_product / (norm1 * norm2)
            similarity = max(min(similarity, 1), -1)
            deviation = int((1 - similarity) * 50)
            deviation = max(0, min(100, deviation))
            if profile.confidence_level == "medium":
                deviation = int(deviation * 0.8)
            return max(0, min(100, deviation))
        except Exception as exc:
            print(f"[BehaviouralBiometricsService] Deviation scoring failed: {exc}", file=sys.stderr)
            return 30

    @classmethod
    def update_profile_after_session(cls, user_id, session_vector=None, session_was_clean=None):
        """Update the active behavioural profile after a verified clean session."""
        try:
            if session_was_clean is None and isinstance(session_vector, str):
                from app.models import SessionRecord

                session = SessionRecord.query.filter_by(id=session_vector, user_id=user_id).first()
                if not session:
                    return False
                dirty_outcomes = {"failed", "timeout"}
                session_was_clean = (
                    not bool(session.is_flagged)
                    and (session.stepup_outcome or "none") not in dirty_outcomes
                )
                session_vector = cls.DEFAULT_VECTOR
            elif session_was_clean is None:
                session_was_clean = True

            if not session_was_clean:
                return False

            from app.models import BehaviouralProfile, User

            profile = BehaviouralProfile.query.filter_by(user_id=user_id, is_active=True).first()
            if not profile:
                profile = BehaviouralProfile(
                    user_id=user_id,
                    confidence_level="low",
                    training_sessions_count=0,
                    is_active=True,
                )
                cls._initialise_profile_vectors(profile)
                db.session.add(profile)
                db.session.flush()
                user = User.query.get(user_id)
                if user:
                    user.behavioural_profile_id = profile.id
                    db.session.add(user)

            profile.update_profile(session_vector or cls.DEFAULT_VECTOR)
            db.session.add(profile)
            db.session.commit()
            return True
        except Exception as exc:
            db.session.rollback()
            print(f"[BehaviouralBiometricsService] Profile update failed: {exc}", file=sys.stderr)
            return False

    @classmethod
    def create_initial_profile(cls, user_id):
        """Create a low confidence behavioural profile for a user."""
        try:
            from app.models import BehaviouralProfile, User

            profile = BehaviouralProfile(
                user_id=user_id,
                confidence_level="low",
                training_sessions_count=0,
                is_active=True,
            )
            cls._initialise_profile_vectors(profile)
            db.session.add(profile)
            db.session.flush()
            user = User.query.get(user_id)
            if user:
                user.behavioural_profile_id = profile.id
                db.session.add(user)
            db.session.commit()
            return profile
        except Exception as exc:
            db.session.rollback()
            print(f"[BehaviouralBiometricsService] Initial profile creation failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def get_profile_summary(cls, user_id):
        """Return profile metadata for a user."""
        try:
            from app.models import BehaviouralProfile

            profile = BehaviouralProfile.query.filter_by(user_id=user_id, is_active=True).first()
            if not profile:
                return {
                    "has_profile": False,
                    "confidence_level": None,
                    "training_sessions": 0,
                    "profile_version": None,
                    "last_updated": None,
                }
            return {
                "has_profile": True,
                "confidence_level": profile.confidence_level,
                "training_sessions": profile.training_sessions_count or 0,
                "profile_version": profile.profile_version,
                "last_updated": profile.updated_at.isoformat() if profile.updated_at else None,
            }
        except Exception as exc:
            print(f"[BehaviouralBiometricsService] Profile summary failed: {exc}", file=sys.stderr)
            return {
                "has_profile": False,
                "confidence_level": None,
                "training_sessions": 0,
                "profile_version": None,
                "last_updated": None,
            }

    @classmethod
    def _initialise_profile_vectors(cls, profile):
        zeros = [0.0] * 10
        for field_name in profile.VECTOR_DEFAULT_LENGTHS:
            profile.set_vector(field_name, zeros)

    @staticmethod
    def _list(value):
        return value if isinstance(value, list) else []

    @staticmethod
    def _numbers(values):
        numbers = []
        for value in values:
            try:
                numbers.append(float(value))
            except (TypeError, ValueError):
                continue
        return numbers

    @staticmethod
    def _mean(values, default):
        return float(statistics.mean(values)) if values else float(default)

    @staticmethod
    def _stdev(values, default):
        if len(values) < 2:
            return float(default)
        return float(statistics.stdev(values))

    @staticmethod
    def _variance(values, default):
        if len(values) < 2:
            return float(default)
        return float(statistics.variance(values))

    @staticmethod
    def _field_nav_entropy(form_events):
        try:
            sequence = []
            for event in form_events:
                order = event.get("field_order")
                if isinstance(order, list):
                    sequence.extend(str(item) for item in order if item is not None)
                elif order is not None:
                    sequence.append(str(order))
            if len(sequence) < 2:
                return 1.5
            transitions = Counter(zip(sequence, sequence[1:]))
            total = sum(transitions.values())
            if total == 0:
                return 1.5
            entropy = 0.0
            for count in transitions.values():
                probability = count / total
                entropy -= probability * math.log2(probability)
            return float(entropy)
        except Exception:
            return 1.5

    @staticmethod
    def _normalize(vector):
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return [float(value) for value in vector]
        return [float(value) / norm for value in vector]
