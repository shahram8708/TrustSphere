"""Privileged access monitoring background tasks."""

from __future__ import annotations

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


@celery.task(
    bind=True,
    name="trustsphere.tasks.pam.anomaly_alert",
    max_retries=2,
    default_retry_delay=60,
)
def pam_anomaly_alert_task(self, priv_session_id, anomaly_type, details_dict):
    """Create an alert for a privileged access anomaly."""
    try:
        with flask_task_context():
            from app.models import PrivilegedSession
            from app.services.alert_manager import AlertManager
            from app.services.audit import AuditLogger
            from app.tasks.email_tasks import send_alert_notification_email_task

            priv_session = PrivilegedSession.query.get(priv_session_id)
            if not priv_session:
                return False
            severity = {
                "large_data_export": "critical",
                "unauthorized_system_access": "critical",
                "bulk_record_access": "high",
                "high_action_velocity": "medium",
                "off_hours_access": "medium",
            }.get(anomaly_type, "medium")
            new_alert = AlertManager.create_alert(
                institution_id=priv_session.institution_id,
                user_id=priv_session.employee_user_id,
                alert_type="insider_anomaly",
                severity=severity,
                title=f"Privileged Access Anomaly: {anomaly_type.replace('_', ' ').title()}",
                description=(
                    f"Employee {priv_session.employee_user_id[:8]}*** triggered anomaly in "
                    f"{priv_session.system_accessed}. Details: {json.dumps(details_dict or {}, sort_keys=True)}"
                ),
                auto_action="investigate",
            )
            if new_alert:
                send_alert_notification_email_task.delay(new_alert.id)
            AuditLogger.log(
                actor_type="system",
                actor_id=priv_session.employee_user_id,
                action="pam.anomaly_detected",
                institution_id=priv_session.institution_id,
                target_type="privileged_session",
                target_id=priv_session_id,
                details={"anomaly_type": anomaly_type, "severity": severity, "alert_id": new_alert.id if new_alert else None},
            )
            return {"alert_id": new_alert.id if new_alert else None, "severity": severity}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "pam.anomaly_alert", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "pam.anomaly_alert", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.pam.generate_report",
    max_retries=1,
    default_retry_delay=60,
)
def generate_pam_report_task(self, priv_session_id):
    """Generate a final privileged session risk summary."""
    try:
        with flask_task_context():
            from flask import url_for

            from app.models import AdminUser, PrivilegedSession
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService
            from app.services.pam_monitor import PrivilegedAccessMonitor

            priv_session = PrivilegedSession.query.get(priv_session_id)
            if not priv_session:
                return False
            risk_score = PrivilegedAccessMonitor.compute_risk_score(priv_session, commit=False)
            summary = PrivilegedAccessMonitor.get_employee_risk_summary(
                priv_session.employee_user_id,
                priv_session.institution_id,
            )
            if int(risk_score or 0) >= 70:
                reviewer = AdminUser.query.filter(
                    AdminUser.institution_id == priv_session.institution_id,
                    AdminUser.role.in_(["compliance_officer", "super_admin"]),
                    AdminUser._is_active.is_(True),
                ).first()
                if reviewer:
                    body = NotificationService.build_email_html(
                        title="High Risk Privileged Session",
                        body_paragraphs=[
                            f"Session risk score: {risk_score}",
                            f"Anomaly count: {priv_session.get_anomaly_count()}",
                            f"System accessed: {priv_session.system_accessed}",
                        ],
                        cta_text="Open PAM Detail",
                        cta_url=url_for("admin.privileged_detail", session_id=priv_session.id, _external=True),
                        footer_note="Generated by TrustSphere privileged access monitoring.",
                    )
                    NotificationService.send_email(
                        reviewer.email,
                        "TrustSphere High Risk Privileged Session",
                        body,
                    )
            AuditLogger.log(
                actor_type="system",
                actor_id=priv_session.employee_user_id,
                action="pam.session_report_generated",
                institution_id=priv_session.institution_id,
                target_type="privileged_session",
                target_id=priv_session.id,
                details={"risk_score": risk_score, "anomaly_count": priv_session.get_anomaly_count(), "summary": summary},
                commit=False,
            )
            db.session.add(priv_session)
            db.session.commit()
            return {"risk_score": risk_score, "summary": summary}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "pam.generate_report", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "pam.generate_report", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.pam.session_timeout",
    max_retries=1,
    default_retry_delay=60,
)
def pam_session_timeout_task(self, priv_session_id):
    """Terminate a privileged session that exceeded maximum duration."""
    try:
        with flask_task_context():
            from app.models import PrivilegedSession
            from app.services.alert_manager import AlertManager
            from app.services.audit import AuditLogger

            priv_session = PrivilegedSession.query.get(priv_session_id)
            if not priv_session:
                return False
            if priv_session.ended_at is not None:
                return False
            priv_session.ended_at = datetime.utcnow()
            db.session.add(priv_session)
            db.session.commit()
            generate_pam_report_task.delay(priv_session_id)
            AlertManager.create_alert(
                institution_id=priv_session.institution_id,
                user_id=priv_session.employee_user_id,
                alert_type="insider_anomaly",
                severity="medium",
                title="Privileged Session Forcibly Terminated",
                description=f"Session {priv_session_id[:8]} exceeded 8 hours and was automatically terminated.",
                auto_action="terminate_session",
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=priv_session.employee_user_id,
                action="pam.session_timeout_terminated",
                institution_id=priv_session.institution_id,
                target_type="privileged_session",
                target_id=priv_session.id,
            )
            return True
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "pam.session_timeout", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "pam.session_timeout", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.pam.check_active_sessions",
    max_retries=1,
    default_retry_delay=60,
)
def check_active_pam_sessions_task(self):
    """Check active privileged sessions for timeout violations."""
    try:
        with flask_task_context():
            from app.models import PrivilegedSession

            cutoff = datetime.utcnow() - timedelta(hours=8)
            sessions = PrivilegedSession.query.filter(
                PrivilegedSession.ended_at.is_(None),
                PrivilegedSession.started_at < cutoff,
            ).all()
            for priv_session in sessions:
                pam_session_timeout_task.delay(priv_session.id)
            return {"terminated": len(sessions)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "pam.check_active_sessions", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "pam.check_active_sessions", exc)
