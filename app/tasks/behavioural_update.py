"""Behavioural biometric profile maintenance tasks."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
import json

from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return None
    raise self.retry(exc=exc, countdown=countdown)


def _load_json_dict(raw_value):
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
        return value if isinstance(value, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _average_vectors(vectors):
    clean_vectors = []
    for vector in vectors:
        if isinstance(vector, list) and vector:
            try:
                clean_vectors.append([float(value) for value in vector])
            except (TypeError, ValueError):
                continue
    if not clean_vectors:
        return []
    length = min(len(vector) for vector in clean_vectors)
    return [
        sum(vector[index] for vector in clean_vectors) / len(clean_vectors)
        for index in range(length)
    ]


@celery.task(
    bind=True,
    name="trustsphere.tasks.behavioural.update_profile",
    max_retries=3,
    default_retry_delay=60,
)
def update_behavioural_profile_task(self, user_id, session_id, session_vector):
    """Update a user's behavioural profile after a clean verified session."""
    try:
        with flask_task_context():
            from app.models import Alert, SessionRecord, User
            from app.services.audit import AuditLogger
            from app.services.behavioural import BehaviouralBiometricsService

            user = User.query.get(user_id)
            session = SessionRecord.query.get(session_id) if session_id else None
            if not user or not session or session.user_id != user.id:
                return False

            high_alert_count = Alert.query.filter(
                Alert.session_id == session.id,
                Alert.status.in_(["open", "investigating"]),
                Alert.severity.in_(["high", "critical"]),
            ).count()
            session_was_clean = (
                not session.is_flagged
                and high_alert_count == 0
                and session.stepup_outcome not in {"failed", "timeout"}
                and int(session.risk_score_peak or 0) <= 60
            )
            updated = BehaviouralBiometricsService.update_profile_after_session(
                user.id,
                session_vector,
                session_was_clean,
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=user.id,
                action="behavioural.profile_update",
                institution_id=user.institution_id,
                target_type="behavioural_profile",
                target_id=user.behavioural_profile_id,
                details={"session_id": session.id, "session_was_clean": session_was_clean, "updated": updated},
            )
            return bool(updated)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "behavioural.update_profile", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "behavioural.update_profile", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.behavioural.rebuild_all",
    max_retries=1,
    default_retry_delay=60,
)
def rebuild_all_profiles_task(self, institution_id=None):
    """Rebuild behavioural profiles from recent clean behavioural vectors."""
    try:
        with flask_task_context():
            from app.models import BehaviouralProfile, RiskEvent, SessionRecord, User
            from app.services.audit import AuditLogger
            from app.services.behavioural import BehaviouralBiometricsService

            cutoff = datetime.utcnow() - timedelta(days=90)
            query = RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id).filter(
                RiskEvent.evaluated_at >= cutoff,
                RiskEvent.cre_response_action.in_(["allow", "monitor"]),
                SessionRecord.is_flagged.is_(False),
            )
            if institution_id:
                query = query.filter(RiskEvent.institution_id == institution_id)
            events = query.order_by(RiskEvent.evaluated_at.desc()).limit(10000).all()

            vectors_by_user = defaultdict(list)
            for event in events:
                metadata = _load_json_dict(event.event_metadata)
                vector = metadata.get("behavioural_vector")
                if vector:
                    vectors_by_user[event.session.user_id].append(vector)

            rebuilt = 0
            for user_id, vectors in vectors_by_user.items():
                averaged = _average_vectors(vectors)
                if not averaged:
                    continue
                user = User.query.get(user_id)
                if not user:
                    continue
                profile = BehaviouralProfile.query.filter_by(user_id=user.id, is_active=True).first()
                if not profile:
                    profile = BehaviouralBiometricsService.create_initial_profile(user.id)
                if not profile:
                    continue
                profile.set_vector("typing_rhythm_vector", averaged)
                profile.training_sessions_count = max(profile.training_sessions_count or 0, len(vectors))
                if profile.training_sessions_count < 5:
                    profile.confidence_level = "low"
                elif profile.training_sessions_count <= 20:
                    profile.confidence_level = "medium"
                else:
                    profile.confidence_level = "high"
                profile.profile_version = int(profile.profile_version or 1) + 1
                profile.updated_at = datetime.utcnow()
                user.behavioural_profile_id = profile.id
                db.session.add(profile)
                db.session.add(user)
                rebuilt += 1

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="behavioural.rebuild_all",
                institution_id=institution_id,
                details={"profiles_rebuilt": rebuilt},
                commit=False,
            )
            db.session.commit()
            return {"rebuilt": rebuilt}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "behavioural.rebuild_all", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "behavioural.rebuild_all", exc)
