"""Alert lifecycle and notification Celery tasks."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return None
    raise self.retry(exc=exc, countdown=countdown)


def _least_loaded_analyst(AdminUser, Alert, institution_id, roles=None):
    roles = roles or ["security_analyst", "compliance_officer", "super_admin"]
    query = AdminUser.query.filter(
        AdminUser.role.in_(roles),
        AdminUser._is_active.is_(True),
    )
    query = query.filter(or_(AdminUser.institution_id == institution_id, AdminUser.role == "super_admin"))
    analysts = query.all()
    if not analysts:
        return None
    return min(
        analysts,
        key=lambda analyst: Alert.query.filter_by(assigned_to=analyst.id, status="open").count(),
    )


@celery.task(
    bind=True,
    name="trustsphere.tasks.alert.created",
    max_retries=3,
    default_retry_delay=60,
)
def alert_created_task(self, alert_id):
    """Finalize a new alert by assigning and notifying an analyst."""
    try:
        with flask_task_context():
            from app.models import AdminUser, Alert
            from app.services.audit import AuditLogger
            from app.tasks.email_tasks import send_alert_notification_email_task

            alert = Alert.query.get(alert_id)
            if not alert:
                return False
            if not alert.assigned_to and alert.severity in {"high", "critical"}:
                analyst = _least_loaded_analyst(AdminUser, Alert, alert.institution_id)
                if analyst:
                    alert.assigned_to = analyst.id
                    alert.status = "investigating"
                    db.session.add(alert)
                    db.session.commit()

            if alert.assigned_to:
                send_alert_notification_email_task.delay(alert.id)

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="alert.created_task_processed",
                institution_id=alert.institution_id,
                target_type="alert",
                target_id=alert.id,
                details={"assigned_to": alert.assigned_to},
            )
            return True
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "alert.created", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "alert.created", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.alert.escalate",
    max_retries=3,
    default_retry_delay=60,
)
def escalate_alert_task(self, alert_id, escalated_by_id=None):
    """Escalate an alert to a senior reviewer."""
    try:
        with flask_task_context():
            from app.models import AdminUser, Alert
            from app.services.audit import AuditLogger
            from app.tasks.email_tasks import send_escalation_notification_task

            alert = Alert.query.get(alert_id)
            if not alert:
                return False
            target = _least_loaded_analyst(
                AdminUser,
                Alert,
                alert.institution_id,
                roles=["compliance_officer", "super_admin"],
            )
            if not target:
                return False

            previous_status = alert.status
            alert.status = "investigating"
            alert.assigned_to = target.id
            db.session.add(alert)
            AuditLogger.log(
                actor_type="system",
                actor_id=escalated_by_id,
                action="alert.escalated_async",
                institution_id=alert.institution_id,
                target_type="alert",
                target_id=alert.id,
                details={"previous_status": previous_status, "assigned_to": target.id},
                commit=False,
            )
            db.session.commit()
            send_escalation_notification_task.delay(alert.id, target.id)
            return {"assigned_to": target.id}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "alert.escalate", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "alert.escalate", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.alert.block_user_session",
    max_retries=3,
    default_retry_delay=60,
)
def block_user_session_task(self, user_id, session_id=None, reason=None):
    """Suspend a user and terminate an active session after analyst action."""
    try:
        with flask_task_context():
            from app.models import SessionRecord, User
            from app.services.audit import AuditLogger

            user = User.query.get(user_id)
            if not user:
                return False
            user.is_suspended = True
            session = SessionRecord.query.get(session_id) if session_id else None
            if session and session.user_id == user.id:
                session.is_flagged = True
                if session.ended_at is None:
                    session.ended_at = datetime.utcnow()
                db.session.add(session)
            db.session.add(user)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="user.session_blocked",
                institution_id=user.institution_id,
                target_type="user",
                target_id=user.id,
                details={"session_id": session_id, "reason": reason},
                commit=False,
            )
            db.session.commit()
            return True
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "alert.block_user_session", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "alert.block_user_session", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.alert.auto_prioritise",
    max_retries=1,
    default_retry_delay=60,
)
def auto_prioritise_alerts_task(self, institution_id=None):
    """Refresh machine priority scores for open alerts."""
    try:
        with flask_task_context():
            from app.services.alert_manager import AlertManager

            updated = AlertManager.auto_prioritise_alerts(institution_id)
            return {"updated": updated, "institution_id": institution_id}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "alert.auto_prioritise", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "alert.auto_prioritise", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.alert.escalation_reminder",
    max_retries=1,
    default_retry_delay=60,
)
def alert_escalation_reminder_task(self):
    """Remind senior reviewers about unresolved high severity alerts."""
    try:
        with flask_task_context():
            from flask import url_for

            from app.models import AdminUser, Alert
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            cutoff = datetime.utcnow() - timedelta(hours=4)
            alerts = Alert.query.filter(
                Alert.status.in_(["open", "investigating"]),
                Alert.severity.in_(["high", "critical"]),
                Alert.created_at <= cutoff,
            ).all()
            sent = 0
            for alert in alerts:
                recipient = None
                if alert.assigned_to:
                    recipient = AdminUser.query.get(alert.assigned_to)
                if not recipient:
                    recipient = _least_loaded_analyst(
                        AdminUser,
                        Alert,
                        alert.institution_id,
                        roles=["compliance_officer", "super_admin"],
                    )
                if not recipient:
                    continue
                body = NotificationService.build_email_html(
                    title="Alert Escalation Reminder",
                    body_paragraphs=[
                        f"Alert: {alert.title}",
                        f"Severity: {alert.severity.upper()}",
                        f"Status: {alert.status}",
                    ],
                    cta_text="Open Alert",
                    cta_url=url_for("admin.alert_detail", alert_id=alert.id, _external=True),
                    footer_note="Generated by TrustSphere scheduled escalation monitoring.",
                )
                ok, _message = NotificationService.send_email(
                    recipient.email,
                    f"TrustSphere Alert Reminder: {alert.title}",
                    body,
                )
                if ok:
                    sent += 1
                    AuditLogger.log(
                        actor_type="system",
                        actor_id=None,
                        action="alert.escalation_reminder_sent",
                        institution_id=alert.institution_id,
                        target_type="alert",
                        target_id=alert.id,
                        details={"recipient": recipient.id},
                        commit=False,
                    )
            db.session.commit()
            return {"reminders_sent": sent}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "alert.escalation_reminder", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "alert.escalation_reminder", exc)
