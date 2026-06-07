"""Device intelligence background tasks."""

from __future__ import annotations

from datetime import datetime, timedelta

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
    name="trustsphere.tasks.device.analyse_new",
    max_retries=2,
    default_retry_delay=60,
)
def analyse_new_device_task(self, device_id):
    """Analyse a registered device and create alerts for risky devices."""
    try:
        with flask_task_context():
            from app.models import Device
            from app.services.alert_manager import AlertManager
            from app.services.audit import AuditLogger
            from app.tasks.email_tasks import send_alert_notification_email_task

            device = Device.query.get(device_id)
            if not device or device.is_removed:
                return False

            trust_score = int(device.get_trust_score())
            is_suspicious = device.trust_level == "suspicious" or device.is_rooted or device.is_emulator
            alert = None
            if is_suspicious:
                alert = AlertManager.create_alert(
                    institution_id=device.institution_id,
                    user_id=device.user_id,
                    alert_type="new_device",
                    severity="high",
                    title="Suspicious device detected",
                    description=(
                        f"Device {device.device_name or device.id} has trust score {trust_score}. "
                        f"Rooted: {bool(device.is_rooted)}. Emulator: {bool(device.is_emulator)}."
                    ),
                    auto_action="monitor",
                )
            elif device.trust_level == "new":
                alert = AlertManager.create_alert(
                    institution_id=device.institution_id,
                    user_id=device.user_id,
                    alert_type="new_device",
                    severity="medium",
                    title="New device observed",
                    description=f"A new device was registered with trust score {trust_score}.",
                    auto_action="monitor",
                )

            if alert:
                send_alert_notification_email_task.delay(alert.id)

            AuditLogger.log(
                actor_type="system",
                actor_id=device.user_id,
                action="device.analysis_completed",
                institution_id=device.institution_id,
                target_type="device",
                target_id=device.id,
                details={"trust_score": trust_score, "alert_id": alert.id if alert else None},
            )
            return {"trust_score": trust_score, "alert_id": alert.id if alert else None}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "device.analyse_new", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "device.analyse_new", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.device.trust_decay",
    max_retries=1,
    default_retry_delay=60,
)
def device_trust_decay_task(self):
    """Lower trust for inactive devices."""
    try:
        with flask_task_context():
            from app.models import Device
            from app.services.audit import AuditLogger

            now = datetime.utcnow()
            trusted_cutoff = now - timedelta(days=90)
            known_cutoff = now - timedelta(days=180)
            trusted_devices = Device.query.filter(
                Device.trust_level == "trusted",
                Device.last_seen_at < trusted_cutoff,
                Device.is_removed.is_(False),
            ).all()
            known_devices = Device.query.filter(
                Device.trust_level == "known",
                Device.last_seen_at < known_cutoff,
                Device.is_removed.is_(False),
            ).all()
            for device in trusted_devices:
                device.trust_level = "known"
                db.session.add(device)
            for device in known_devices:
                device.trust_level = "new"
                db.session.add(device)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="device.trust_decay",
                details={"trusted_to_known": len(trusted_devices), "known_to_new": len(known_devices)},
                commit=False,
            )
            db.session.commit()
            return {"trusted_to_known": len(trusted_devices), "known_to_new": len(known_devices)}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "device.trust_decay", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "device.trust_decay", exc)
