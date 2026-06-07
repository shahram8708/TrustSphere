"""Data cleanup and maintenance Celery tasks."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return None
    raise self.retry(exc=exc, countdown=countdown)


@celery.task(
    bind=True,
    name="trustsphere.tasks.cleanup.purge_old_sessions",
    max_retries=1,
    default_retry_delay=60,
)
def purge_old_sessions_task(self, retention_days=90):
    """Delete old session records and their risk events."""
    try:
        with flask_task_context():
            from app.models import Alert, RiskEvent, SessionRecord
            from app.services.audit import AuditLogger

            cutoff = datetime.utcnow() - timedelta(days=int(retention_days or 90))
            old_sessions = (
                SessionRecord.query.filter(SessionRecord.started_at < cutoff)
                .order_by(SessionRecord.started_at.asc())
                .limit(1000)
                .all()
            )
            session_ids = [session.id for session in old_sessions]
            deleted_events = 0
            deleted_sessions = 0
            cleared_alert_links = 0
            if session_ids:
                cleared_alert_links = Alert.query.filter(Alert.session_id.in_(session_ids)).update(
                    {Alert.session_id: None},
                    synchronize_session=False,
                )
                deleted_events = RiskEvent.query.filter(RiskEvent.session_id.in_(session_ids)).delete(
                    synchronize_session=False
                )
                deleted_sessions = SessionRecord.query.filter(SessionRecord.id.in_(session_ids)).delete(
                    synchronize_session=False
                )
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="cleanup.sessions_purged",
                details={
                    "count": deleted_sessions,
                    "cutoff": cutoff.isoformat(),
                    "cleared_alert_links": cleared_alert_links,
                },
                commit=False,
            )
            db.session.commit()
            return {
                "deleted_sessions": deleted_sessions,
                "deleted_events": deleted_events,
                "cleared_alert_links": cleared_alert_links,
            }
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.purge_old_sessions", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.purge_old_sessions", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.cleanup.archive_audit_logs",
    max_retries=1,
    default_retry_delay=60,
)
def purge_old_audit_logs_task(self, retention_days=365):
    """Archive and delete old audit log rows in demo mode."""
    try:
        with flask_task_context():
            from app.models import AuditLog
            from app.services.audit import AuditLogger

            cutoff = datetime.utcnow() - timedelta(days=int(retention_days or 365))
            old_entries = (
                AuditLog.query.filter(AuditLog.created_at < cutoff)
                .order_by(AuditLog.created_at.asc())
                .limit(5000)
                .all()
            )
            archived_json = json.dumps([entry.to_dict() for entry in old_entries], default=str)
            print(
                f"[TrustSphere Audit Archive] {len(old_entries)} entries archived. "
                "In production, write to secure long term storage."
            )
            if old_entries:
                print(f"[TrustSphere Audit Archive Sample] {archived_json[:1000]}")
            for entry in old_entries:
                db.session.delete(entry)
            db.session.commit()
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="cleanup.audit_archived",
                details={"count": len(old_entries), "cutoff": cutoff.isoformat()},
            )
            return {"archived": len(old_entries)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.archive_audit_logs", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.archive_audit_logs", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.cleanup.expired_challenges",
    max_retries=1,
    default_retry_delay=60,
)
def cleanup_expired_challenges_task(self):
    """Remove expired in memory step up challenges."""
    try:
        with flask_task_context():
            from app.services.stepup_orchestrator import StepUpOrchestrator

            count = StepUpOrchestrator.cleanup_expired_challenges()
            if count > 0:
                print(f"[TrustSphere] Cleaned up {count} expired step up challenges")
            return {"cleaned": count}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.expired_challenges", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.expired_challenges", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.cleanup.stale_reports",
    max_retries=1,
    default_retry_delay=60,
)
def cleanup_stale_reports_task(self, max_age_hours=24):
    """Remove old entries from the in memory report cache."""
    try:
        with flask_task_context():
            from app.tasks.report_cache import _report_cache

            cutoff = datetime.utcnow() - timedelta(hours=int(max_age_hours or 24))
            stale_keys = []
            for key, entry in list(_report_cache.items()):
                created_at = entry.get("created_at")
                if isinstance(created_at, str):
                    try:
                        created_at = datetime.fromisoformat(created_at)
                    except ValueError:
                        created_at = None
                if created_at and created_at < cutoff:
                    stale_keys.append(key)
            for key in stale_keys:
                _report_cache.pop(key, None)
            print(f"[TrustSphere] Removed {len(stale_keys)} stale reports", file=sys.stderr)
            return {"removed": len(stale_keys)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.stale_reports", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "cleanup.stale_reports", exc)
