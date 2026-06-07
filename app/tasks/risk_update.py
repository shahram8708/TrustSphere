"""Risk score background update tasks."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
import statistics

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


@celery.task(
    bind=True,
    name="trustsphere.tasks.risk.async_score_update",
    max_retries=3,
    default_retry_delay=60,
)
def async_risk_score_update_task(self, user_id, new_score, event_id=None):
    """Persist an asynchronous user risk score update."""
    try:
        with flask_task_context():
            from app.models import User
            from app.services.alert_manager import AlertManager
            from app.services.audit import AuditLogger
            from app.tasks.email_tasks import send_alert_notification_email_task

            user = User.query.get(user_id)
            if not user:
                return False

            old_score = int(user.risk_score_current or 0)
            new_score = max(0, min(100, int(new_score or 0)))
            user.risk_score_current = new_score
            user.risk_score_updated_at = datetime.utcnow()
            db.session.add(user)
            db.session.commit()

            new_alert = None
            if new_score >= 81 and old_score < 81:
                new_alert = AlertManager.create_alert(
                    institution_id=user.institution_id,
                    user_id=user_id,
                    alert_type="suspicious_behaviour",
                    severity="critical",
                    title=f"User risk score escalated to Critical ({new_score})",
                    description=(
                        f"Risk score crossed into Critical range from {old_score}. "
                        "Immediate review recommended."
                    ),
                )
                if new_alert:
                    send_alert_notification_email_task.delay(new_alert.id)

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="risk.score_updated",
                institution_id=user.institution_id,
                target_type="user",
                target_id=user.id,
                details={
                    "old": old_score,
                    "new": new_score,
                    "delta": new_score - old_score,
                    "event_id": event_id,
                    "alert_id": new_alert.id if new_alert else None,
                },
            )
            return {"old": old_score, "new": new_score}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "risk.async_score_update", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "risk.async_score_update", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.risk.batch_recalculate",
    max_retries=1,
    default_retry_delay=60,
)
def batch_recalculate_risk_scores_task(self, institution_id=None):
    """Recalculate user risk scores from recent session history."""
    try:
        with flask_task_context():
            from app.models import SessionRecord, User
            from app.services.audit import AuditLogger

            query = User.query.filter(User.is_suspended.is_(False))
            if institution_id:
                query = query.filter(User.institution_id == institution_id)
            users = query.all()
            now = datetime.utcnow()
            updated_count = 0
            skipped_count = 0

            for user in users:
                sessions = (
                    SessionRecord.query.filter_by(user_id=user.id, institution_id=user.institution_id)
                    .order_by(SessionRecord.started_at.desc())
                    .limit(10)
                    .all()
                )
                current_score = int(user.risk_score_current or 0)
                computed_score = current_score

                if sessions:
                    weighted_scores = []
                    weights = []
                    for session in sessions:
                        weight = 2 if session.started_at and session.started_at >= now - timedelta(days=7) else 1
                        weighted_scores.append(int(session.risk_score_peak or current_score) * weight)
                        weights.append(weight)
                    computed_score = int(round(sum(weighted_scores) / max(sum(weights), 1)))
                    last_session_at = sessions[0].started_at
                else:
                    last_session_at = user.last_active_at

                if last_session_at and last_session_at < now - timedelta(days=14):
                    inactive_days = max((now - last_session_at).days, 14)
                    decay_periods = max(inactive_days // 14, 1)
                    computed_score = max(15, computed_score - int(decay_periods) * 5)

                user.risk_score_updated_at = now
                if abs(computed_score - current_score) > 5:
                    user.risk_score_current = max(0, min(100, computed_score))
                    updated_count += 1
                else:
                    skipped_count += 1
                db.session.add(user)

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="risk.batch_recalculated",
                institution_id=institution_id,
                details={"users_updated": updated_count, "institution_id": institution_id},
                commit=False,
            )
            db.session.commit()
            return {"updated": updated_count, "skipped": skipped_count}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "risk.batch_recalculate", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "risk.batch_recalculate", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.risk.session_baseline_refresh",
    max_retries=1,
    default_retry_delay=60,
)
def recalculate_all_session_baselines_task(self):
    """Refresh per user session baselines for anomaly detection."""
    try:
        with flask_task_context():
            from app.models import Institution, SessionRecord, User
            from app.services.audit import AuditLogger

            cutoff = datetime.utcnow() - timedelta(days=90)
            refreshed = 0
            for institution in Institution.query.filter_by(is_active=True).all():
                sessions = (
                    SessionRecord.query.filter(
                        SessionRecord.institution_id == institution.id,
                        SessionRecord.started_at >= cutoff,
                    )
                    .order_by(SessionRecord.started_at.asc())
                    .all()
                )
                by_user = defaultdict(list)
                for session in sessions:
                    by_user[session.user_id].append(session)

                for user_id, user_sessions in by_user.items():
                    user = User.query.get(user_id)
                    if not user:
                        continue
                    hours = [item.started_at.hour for item in user_sessions if item.started_at]
                    countries = [item.ip_country for item in user_sessions if item.ip_country]
                    cities = [item.ip_city for item in user_sessions if item.ip_city]
                    durations = [item.duration_minutes for item in user_sessions if item.duration_minutes]
                    stats = {
                        "typical_login_hour_mean": round(statistics.mean(hours), 2) if hours else None,
                        "typical_login_hour_stdev": round(statistics.stdev(hours), 2) if len(hours) > 1 else 0.0,
                        "typical_country": Counter(countries).most_common(1)[0][0] if countries else None,
                        "typical_city": Counter(cities).most_common(1)[0][0] if cities else None,
                        "typical_session_duration_minutes": round(statistics.mean(durations), 2) if durations else 0.0,
                        "sample_size": len(user_sessions),
                        "refreshed_at": datetime.utcnow().isoformat(),
                    }
                    config = _load_json_dict(user.config_json)
                    config["baseline_stats"] = stats
                    user.config_json = json.dumps(config, sort_keys=True)
                    db.session.add(user)

                AuditLogger.log(
                    actor_type="system",
                    actor_id=None,
                    action="risk.session_baseline_refreshed",
                    institution_id=institution.id,
                    details={"users_refreshed": len(by_user)},
                    commit=False,
                )
                refreshed += 1

            db.session.commit()
            return {"institutions_refreshed": refreshed}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "risk.session_baseline_refresh", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "risk.session_baseline_refresh", exc)
