"""KYC onboarding processing tasks."""

from __future__ import annotations

from datetime import datetime, timedelta
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.email_tasks import send_kyc_decision_notification_task
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return None
    raise self.retry(exc=exc, countdown=countdown)


@celery.task(
    bind=True,
    name="trustsphere.tasks.kyc.process_application",
    max_retries=2,
    default_retry_delay=60,
)
def process_kyc_application_task(self, application_id):
    """Score a pending KYC application asynchronously."""
    try:
        with flask_task_context():
            from app.models import OnboardingApplication
            from app.services.alert_manager import AlertManager
            from app.services.audit import AuditLogger
            from app.services.kyc_scoring import KYCOnboardingScorer
            from app.tasks.email_tasks import send_alert_notification_email_task

            application = OnboardingApplication.query.get(application_id)
            if not application or application.decision != "pending":
                return False

            application = KYCOnboardingScorer.score_application(application)
            db.session.add(application)
            db.session.commit()
            send_kyc_decision_notification_task.delay(application_id)

            alert = None
            if application.decision == "reject" or application.watchlist_match:
                alert = AlertManager.create_alert(
                    institution_id=application.institution_id,
                    user_id=None,
                    alert_type="kyc_fraud",
                    severity="high",
                    title=f"KYC Application Auto Rejected: {application.application_ref}",
                    description=(
                        f"Risk score {application.composite_risk_score}. "
                        f"Watchlist: {bool(application.watchlist_match)}."
                    ),
                    auto_action="kyc_reject",
                )
                if alert:
                    send_alert_notification_email_task.delay(alert.id)

            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="kyc.scored",
                institution_id=application.institution_id,
                target_type="onboarding_application",
                target_id=application.id,
                details={
                    "decision": application.decision,
                    "score": application.composite_risk_score,
                    "alert_id": alert.id if alert else None,
                },
            )
            return {"decision": application.decision, "score": application.composite_risk_score}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.process_application", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.process_application", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.kyc.review_reminder",
    max_retries=1,
    default_retry_delay=60,
)
def scheduled_kyc_review_reminder_task(self):
    """Send reminders for pending KYC applications older than 48 hours."""
    try:
        with flask_task_context():
            from flask import url_for

            from app.models import AdminUser, OnboardingApplication
            from app.services.audit import AuditLogger
            from app.services.notification import NotificationService

            cutoff = datetime.utcnow() - timedelta(hours=48)
            applications = OnboardingApplication.query.filter(
                OnboardingApplication.decision == "pending",
                OnboardingApplication.submitted_at < cutoff,
            ).all()
            sent = 0
            for application in applications:
                reviewer = AdminUser.query.filter(
                    AdminUser.institution_id == application.institution_id,
                    AdminUser.role.in_(["compliance_officer", "super_admin"]),
                    AdminUser._is_active.is_(True),
                ).first()
                if not reviewer:
                    continue
                body = NotificationService.build_email_html(
                    title="KYC Review Reminder",
                    body_paragraphs=[
                        f"Application {application.application_ref} has been pending for more than 48 hours.",
                        f"Current risk score: {application.composite_risk_score}",
                    ],
                    cta_text="Open Application",
                    cta_url=url_for("admin.onboarding_detail", app_id=application.id, _external=True),
                    footer_note="Generated by TrustSphere KYC monitoring.",
                )
                ok, _message = NotificationService.send_email(
                    reviewer.email,
                    f"TrustSphere KYC Review Reminder: {application.application_ref}",
                    body,
                )
                if ok:
                    sent += 1
                    AuditLogger.log(
                        actor_type="system",
                        actor_id=None,
                        action="kyc.review_reminder_sent",
                        institution_id=application.institution_id,
                        target_type="onboarding_application",
                        target_id=application.id,
                        details={"reviewer_id": reviewer.id},
                        commit=False,
                    )
            db.session.commit()
            return {"sent": sent}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.review_reminder", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.review_reminder", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.kyc.watchlist_refresh",
    max_retries=1,
    default_retry_delay=60,
)
def watchlist_refresh_task(self):
    """Refresh the demo KYC watchlist metadata."""
    try:
        with flask_task_context():
            from app.services.audit import AuditLogger
            from app.services.kyc_scoring import KYCOnboardingScorer

            count = len(KYCOnboardingScorer.DEMO_WATCHLIST_HASHES)
            print(f"[TrustSphere] Watchlist refresh: using demo static list ({count} entries)")
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="kyc.watchlist_refreshed",
                details={"entries": count},
            )
            return {"entries": count}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.watchlist_refresh", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.watchlist_refresh", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.kyc.batch_score_pending",
    max_retries=1,
    default_retry_delay=60,
)
def batch_score_pending_applications_task(self):
    """Trigger scoring for pending applications missed by initial processing."""
    try:
        with flask_task_context():
            from app.models import OnboardingApplication
            from app.services.audit import AuditLogger

            cutoff = datetime.utcnow() - timedelta(minutes=5)
            applications = OnboardingApplication.query.filter(
                OnboardingApplication.decision == "pending",
                OnboardingApplication.submitted_at < cutoff,
            ).all()
            for application in applications:
                process_kyc_application_task.delay(application.id)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="kyc.batch_score_pending",
                details={"triggered": len(applications)},
            )
            return {"triggered": len(applications)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.batch_score_pending", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "kyc.batch_score_pending", exc)
