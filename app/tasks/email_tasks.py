"""Email and outbound notification Celery tasks."""

from __future__ import annotations

from smtplib import SMTPException
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return False
    raise self.retry(exc=exc, countdown=countdown)


def _ensure_sent(ok, message):
    if not ok:
        raise SMTPException(message or "Email delivery failed")


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.password_reset",
    max_retries=3,
    default_retry_delay=60,
)
def send_password_reset_email_task(self, admin_user_id, reset_token):
    """Send a password reset email to an active admin user."""
    try:
        with flask_task_context():
            from app.models import AdminUser
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            admin_user = AdminUser.query.get(admin_user_id)
            if not admin_user:
                print(
                    f"[TrustSphere Task] password reset skipped, admin user not found: {admin_user_id}",
                    file=sys.stderr,
                )
                return False
            if not admin_user.is_active:
                return False

            ok, message = NotificationService.send_password_reset_email(admin_user_id, reset_token)
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=admin_user_id,
                action="email.password_reset_sent",
                institution_id=admin_user.institution_id,
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.password_reset", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.password_reset", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.password_reset", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.verification",
    max_retries=3,
    default_retry_delay=60,
)
def send_verification_email_task(self, admin_user_id, verify_token):
    """Send an email verification message to an admin user."""
    try:
        with flask_task_context():
            from app.models import AdminUser
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            admin_user = AdminUser.query.get(admin_user_id)
            if not admin_user:
                print(
                    f"[TrustSphere Task] verification skipped, admin user not found: {admin_user_id}",
                    file=sys.stderr,
                )
                return False

            ok, message = NotificationService.send_email_verification(admin_user_id, verify_token)
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=admin_user_id,
                action="email.verification_sent",
                institution_id=admin_user.institution_id,
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.verification", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.verification", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.verification", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.alert_notification",
    max_retries=3,
    default_retry_delay=60,
)
def send_alert_notification_email_task(self, alert_id):
    """Notify the assigned analyst about an alert."""
    try:
        with flask_task_context():
            from app.models import AdminUser, Alert
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            alert = Alert.query.get(alert_id)
            if not alert:
                return False
            analyst = AdminUser.query.get(alert.assigned_to) if alert.assigned_to else None
            if not analyst:
                return False

            ok, message = NotificationService.send_alert_notification_email(alert_id)
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.alert_notification_sent",
                institution_id=alert.institution_id,
                target_type="alert",
                target_id=alert.id,
                details={"assigned_to": analyst.id},
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.alert_notification", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.alert_notification", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.alert_notification", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.demo_request",
    max_retries=2,
    default_retry_delay=60,
)
def send_demo_request_notification_task(self, contact_data_dict):
    """Send an internal demo request notification."""
    try:
        with flask_task_context():
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            ok, message = NotificationService.send_demo_request_notification(contact_data_dict or {})
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.demo_request_received",
                details={"company": (contact_data_dict or {}).get("company_name") or (contact_data_dict or {}).get("company", "Unknown")},
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.demo_request", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.demo_request", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.demo_request", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.contact_form",
    max_retries=2,
    default_retry_delay=60,
)
def send_contact_form_notification_task(self, contact_data_dict):
    """Send an internal notification for a public contact form submission."""
    try:
        with flask_task_context():
            from flask import current_app

            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            data = contact_data_dict or {}
            paragraphs = [
                f"Name: {data.get('full_name') or data.get('name') or 'Unknown'}",
                f"Email: {data.get('email') or 'Unknown'}",
                f"Bank: {data.get('bank_name') or data.get('bank') or 'Unknown'}",
                f"Message: {data.get('message') or ''}",
            ]
            body = NotificationService.build_email_html(
                title="New Contact Form Submission",
                body_paragraphs=paragraphs,
                footer_note="Generated by the public TrustSphere website.",
            )
            to_email = current_app.config.get("DEFAULT_ADMIN_EMAIL", "admin@trustsphere.com")
            ok, message = NotificationService.send_email(
                to_email,
                "TrustSphere New Contact Form Submission",
                body,
            )
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.contact_form_received",
                details={"bank": data.get("bank_name") or data.get("bank", "Unknown")},
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.contact_form", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.contact_form", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.contact_form", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.kyc_decision",
    max_retries=3,
    default_retry_delay=60,
)
def send_kyc_decision_notification_task(self, application_id):
    """Record a KYC decision notification in demo mode."""
    try:
        with flask_task_context():
            from app.models import OnboardingApplication
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            application = OnboardingApplication.query.get(application_id)
            if not application:
                return False

            decision_labels = {
                "approve": "approved",
                "manual_review": "sent for manual review",
                "reject": "rejected",
                "pending": "left pending",
            }
            next_steps = {
                "approve": "Your bank will continue with account activation.",
                "manual_review": "A reviewer will complete checks before a final decision.",
                "reject": "You may contact the bank support team for the appeal process.",
                "pending": "Your bank will update you after processing is complete.",
            }
            decision_display = decision_labels.get(application.decision, application.decision)
            NotificationService.build_email_html(
                title="KYC Application Decision",
                body_paragraphs=[
                    f"Your application {application.application_ref} has been {decision_display}.",
                    next_steps.get(application.decision, next_steps["pending"]),
                ],
                footer_note="In production this would be sent to the applicant email address.",
            )
            print(
                f"[DEMO KYC] Decision notification for {application.application_ref}: {application.decision}"
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.kyc_decision_sent",
                institution_id=application.institution_id,
                target_type="onboarding_application",
                target_id=application.id,
                details={"decision": application.decision},
            )
            return True
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.kyc_decision", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.kyc_decision", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.stepup_challenge",
    max_retries=2,
    default_retry_delay=60,
)
def send_stepup_challenge_notification_task(self, user_id, method, challenge_data_dict):
    """Send a step up challenge notification."""
    try:
        with flask_task_context():
            from app.models import User
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            user = User.query.get(user_id)
            institution_id = user.institution_id if user else None
            ok, message = NotificationService.send_stepup_notification(user_id, method, challenge_data_dict or {})
            _ensure_sent(ok, message)
            details = {"method": method}
            if method == "otp":
                details["otp_demo_code"] = (challenge_data_dict or {}).get("otp_code")
            AuditLogger.log(
                actor_type="system",
                actor_id=user_id,
                action="notification.stepup_sent",
                institution_id=institution_id,
                target_type="user",
                target_id=user_id,
                details=details,
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.stepup_challenge", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.stepup_challenge", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.stepup_challenge", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.account_recovery",
    max_retries=3,
    default_retry_delay=60,
)
def send_account_recovery_status_task(self, user_id, status, institution_id):
    """Send a demo account recovery status notification."""
    try:
        with flask_task_context():
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            ok, message = NotificationService.send_account_recovery_status_email(user_id, status, institution_id)
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=user_id,
                action="email.recovery_status_sent",
                institution_id=institution_id,
                target_type="user",
                target_id=user_id,
                details={"status": status},
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.account_recovery", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.account_recovery", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.account_recovery", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.weekly_digest",
    max_retries=1,
    default_retry_delay=60,
)
def send_weekly_security_digest_task(self, institution_id):
    """Send the weekly security digest for one institution."""
    try:
        with flask_task_context():
            from app.models import AdminUser
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            recipients = AdminUser.query.filter(
                AdminUser.institution_id == institution_id,
                AdminUser.role.in_(["compliance_officer", "super_admin"]),
                AdminUser._is_active.is_(True),
            ).all()
            sent_count = NotificationService.send_weekly_security_digest(institution_id)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.weekly_digest_sent",
                institution_id=institution_id,
                details={"institution_id": institution_id, "recipients": len(recipients), "sent": sent_count},
            )
            return {"recipients": len(recipients), "sent": sent_count}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.weekly_digest", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.weekly_digest", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.alert_escalation",
    max_retries=3,
    default_retry_delay=60,
)
def send_escalation_notification_task(self, alert_id, escalated_to_id):
    """Send an alert escalation email."""
    try:
        with flask_task_context():
            from flask import url_for

            from app.models import AdminUser, Alert
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            alert = Alert.query.get(alert_id)
            escalated_to = AdminUser.query.get(escalated_to_id)
            if not alert or not escalated_to:
                return False

            detail_url = url_for("admin.alert_detail", alert_id=alert.id, _external=True)
            analyst_name = alert.assigned_analyst.email if alert.assigned_analyst else "TrustSphere analyst"
            body = NotificationService.build_email_html(
                title="Escalated Alert Requires Senior Review",
                body_paragraphs=[
                    f"Severity: {alert.severity.upper()}",
                    f"Description: {alert.description or 'No description provided.'}",
                    f"Escalating analyst: {analyst_name}",
                ],
                cta_text="Open Alert",
                cta_url=detail_url,
                footer_note="This message was generated by TrustSphere alert escalation.",
            )
            ok, message = NotificationService.send_email(
                escalated_to.email,
                f"[ESCALATED] TrustSphere Alert Requires Senior Review: {alert.title}",
                body,
            )
            _ensure_sent(ok, message)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.alert_escalation_sent",
                institution_id=alert.institution_id,
                target_type="alert",
                target_id=alert.id,
                details={"escalated_to": escalated_to.id},
            )
            return True
    except SMTPException as exc:
        return _retry_or_return(self, "email.alert_escalation", exc)
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.alert_escalation", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.alert_escalation", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.email.weekly_digest_all",
    max_retries=1,
    default_retry_delay=60,
)
def send_all_weekly_digests_task(self):
    """Trigger weekly digest tasks for every active institution."""
    try:
        with flask_task_context():
            from app.models import Institution
            from app.services.audit import AuditLogger

            institutions = Institution.query.filter_by(is_active=True).all()
            for institution in institutions:
                send_weekly_security_digest_task.delay(institution.id)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="email.weekly_digest_all_triggered",
                details={"institution_count": len(institutions)},
            )
            return {"triggered": len(institutions)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "email.weekly_digest_all", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "email.weekly_digest_all", exc)
