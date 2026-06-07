"""Compliance report generation tasks."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
import csv
import io
import uuid

from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.tasks.celery_app import celery
from app.tasks.report_cache import set_report
from app.tasks.task_utils import flask_task_context, log_task_error, rollback_session


def _retry_or_return(self, task_name, exc, countdown=60):
    log_task_error(task_name, exc)
    if self.app.conf.task_always_eager:
        return None
    raise self.retry(exc=exc, countdown=countdown)


def _parse_datetime(value, fallback):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return fallback


def _dict_to_csv(data):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Path", "Value"])

    def write_value(prefix, value):
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                write_value(f"{prefix}.{child_key}" if prefix else child_key, child_value)
        elif isinstance(value, list):
            for index, child_value in enumerate(value, start=1):
                write_value(f"{prefix}.{index}", child_value)
        else:
            writer.writerow([prefix, value])

    write_value("", data)
    return buffer.getvalue()


def _generate_report_data(report_type, institution_id, date_from_value, date_to_value, alert_id=None):
    from app.models import Alert, AuditLog, PrivilegedSession, RiskPolicy, User
    from app.services.report_generator import ComplianceReportGenerator

    if report_type == "rbi_report":
        return ComplianceReportGenerator.generate_rbi_report(institution_id, date_from_value, date_to_value)
    if report_type == "alert_summary":
        return ComplianceReportGenerator.generate_alert_summary_report(institution_id, date_from_value, date_to_value)
    if report_type == "user_risk":
        return ComplianceReportGenerator.generate_user_risk_report(institution_id)
    if report_type == "incident":
        alert_query = Alert.query.filter(Alert.id == alert_id, Alert.institution_id == institution_id)
        if not alert_query.first():
            return {}
        return ComplianceReportGenerator.generate_incident_report(alert_id)
    if report_type == "gdpr_compliance":
        audit_count = AuditLog.query.filter(
            AuditLog.institution_id == institution_id,
            AuditLog.created_at >= date_from_value,
            AuditLog.created_at <= date_to_value,
        ).count()
        alert_count = Alert.query.filter(
            Alert.institution_id == institution_id,
            Alert.created_at >= date_from_value,
            Alert.created_at <= date_to_value,
        ).count()
        suspended_users = User.query.filter_by(institution_id=institution_id, is_suspended=True).count()
        return {
            "period": {"date_from": date_from_value.isoformat(), "date_to": date_to_value.isoformat()},
            "privacy_controls": {
                "data_minimisation": "active",
                "hashed_identifiers": "active",
                "audit_trail_entries": audit_count,
                "security_incidents_reviewed": alert_count,
                "restricted_accounts": suspended_users,
            },
            "evidence": [
                "Customer identifiers are represented through internal IDs and hashes in operational screens.",
                "Security actions are recorded in an immutable audit log.",
                "Risk based access controls are configured through the policy engine.",
            ],
        }
    if report_type == "iso27001":
        active_policy_count = RiskPolicy.query.filter_by(institution_id=institution_id, is_active=True).count()
        pam_alerts = PrivilegedSession.query.filter_by(institution_id=institution_id, alert_generated=True).count()
        open_alerts = Alert.query.filter_by(institution_id=institution_id, status="open").count()
        audit_count = AuditLog.query.filter(
            AuditLog.institution_id == institution_id,
            AuditLog.created_at >= date_from_value,
            AuditLog.created_at <= date_to_value,
        ).count()
        return {
            "period": {"date_from": date_from_value.isoformat(), "date_to": date_to_value.isoformat()},
            "controls": {
                "A.5.15 Access Control": "active" if active_policy_count else "needs review",
                "A.8.15 Logging": "active" if audit_count else "limited evidence",
                "A.8.16 Monitoring Activities": "active",
                "A.5.24 Incident Management": "active" if open_alerts or pam_alerts else "no incidents",
            },
            "metrics": {
                "active_policy_count": active_policy_count,
                "privileged_access_alerts": pam_alerts,
                "open_security_alerts": open_alerts,
                "audit_entries": audit_count,
            },
        }
    return {}


@celery.task(
    bind=True,
    name="trustsphere.tasks.report.generate_compliance",
    max_retries=1,
    default_retry_delay=60,
)
def generate_compliance_report_task(
    self,
    institution_id,
    report_type,
    date_from_iso,
    date_to_iso,
    format_str,
    task_id,
    generated_by_id=None,
    alert_id=None,
):
    """Generate one compliance report into the shared report cache."""
    try:
        with flask_task_context():
            from app.services.audit import AuditLogger
            from app.services.report_generator import ComplianceReportGenerator

            date_to_value = _parse_datetime(date_to_iso, datetime.combine(date.today(), time.max))
            date_from_value = _parse_datetime(date_from_iso, date_to_value - timedelta(days=30))
            set_report(
                task_id,
                "generating",
                format_str=format_str,
                report_type=report_type,
                institution_id=institution_id,
            )
            data = _generate_report_data(report_type, institution_id, date_from_value, date_to_value, alert_id=alert_id)
            if format_str == "csv":
                content = ComplianceReportGenerator.export_to_csv(data, report_type) or _dict_to_csv(data)
            else:
                content = ComplianceReportGenerator.export_to_json(data)
            set_report(
                task_id,
                "completed",
                content=content,
                format_str=format_str,
                report_type=report_type,
                institution_id=institution_id,
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=generated_by_id,
                action="report.generate",
                institution_id=institution_id,
                target_type="report",
                target_id=task_id,
                details={"report_type": report_type, "format": format_str, "alert_id": alert_id},
            )
            return {"task_id": task_id, "status": "completed"}
    except SQLAlchemyError as exc:
        rollback_session()
        set_report(task_id, "failed", report_type=report_type, institution_id=institution_id)
        return _retry_or_return(self, "report.generate_compliance", exc)
    except Exception as exc:
        rollback_session()
        set_report(task_id, "failed", report_type=report_type, institution_id=institution_id)
        return _retry_or_return(self, "report.generate_compliance", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.report.audit_export",
    max_retries=1,
    default_retry_delay=60,
)
def export_audit_log_task(
    self,
    institution_id=None,
    date_from_iso=None,
    date_to_iso=None,
    filters=None,
    task_id=None,
):
    """Export audit log rows to CSV into the shared report cache."""
    task_id = task_id or str(uuid.uuid4())
    try:
        with flask_task_context():
            from app.models import AuditLog
            from app.services.audit import AuditLogger

            now = datetime.utcnow()
            date_from_value = _parse_datetime(date_from_iso, now - timedelta(days=30))
            date_to_value = _parse_datetime(date_to_iso, now)
            query = AuditLog.query.filter(
                AuditLog.created_at >= date_from_value,
                AuditLog.created_at <= date_to_value,
            )
            if institution_id:
                query = query.filter(AuditLog.institution_id == institution_id)
            filters = filters or {}
            if filters.get("actor_type"):
                query = query.filter(AuditLog.actor_type == filters["actor_type"])
            if filters.get("target_type"):
                query = query.filter(AuditLog.target_type == filters["target_type"])
            entries = query.order_by(AuditLog.created_at.desc()).limit(10000).all()

            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["ID", "Timestamp", "Actor Type", "Actor Email", "Action", "Target Type", "Target ID", "IP Address", "Details"])
            for entry in entries:
                writer.writerow([
                    entry.id,
                    entry.created_at.isoformat() if entry.created_at else "",
                    entry.actor_type,
                    entry.actor_email,
                    entry.action,
                    entry.target_type,
                    entry.target_id,
                    entry.ip_address,
                    entry.details,
                ])
            set_report(
                task_id,
                "completed",
                content=buffer.getvalue(),
                format_str="csv",
                report_type="audit_log_export",
                institution_id=institution_id,
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="audit_log.export_async",
                institution_id=institution_id,
                target_type="report",
                target_id=task_id,
                details={"record_count": len(entries)},
            )
            return {"task_id": task_id, "record_count": len(entries)}
    except SQLAlchemyError as exc:
        rollback_session()
        set_report(task_id, "failed", report_type="audit_log_export", institution_id=institution_id)
        return _retry_or_return(self, "report.audit_export", exc)
    except Exception as exc:
        rollback_session()
        set_report(task_id, "failed", report_type="audit_log_export", institution_id=institution_id)
        return _retry_or_return(self, "report.audit_export", exc)


@celery.task(
    bind=True,
    name="trustsphere.tasks.report.daily_scheduled",
    max_retries=1,
    default_retry_delay=60,
)
def scheduled_daily_report_task(self):
    """Trigger daily alert summary reports for every active institution."""
    try:
        with flask_task_context():
            from app.models import Institution
            from app.services.audit import AuditLogger

            date_to_value = datetime.utcnow()
            date_from_value = date_to_value - timedelta(days=1)
            institutions = Institution.query.filter_by(is_active=True).all()
            task_ids = []
            for institution in institutions:
                task_id = str(uuid.uuid4())
                set_report(
                    task_id,
                    "pending",
                    format_str="json",
                    report_type="alert_summary",
                    institution_id=institution.id,
                )
                generate_compliance_report_task.delay(
                    institution.id,
                    "alert_summary",
                    date_from_value.isoformat(),
                    date_to_value.isoformat(),
                    "json",
                    task_id,
                    None,
                    None,
                )
                task_ids.append(task_id)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="report.daily_scheduled",
                details={"institution_count": len(institutions), "task_ids": task_ids},
            )
            return {"triggered": len(task_ids), "task_ids": task_ids}
    except SQLAlchemyError as exc:
        rollback_session()
        return _retry_or_return(self, "report.daily_scheduled", exc)
    except Exception as exc:
        rollback_session()
        return _retry_or_return(self, "report.daily_scheduled", exc)
