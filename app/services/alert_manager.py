"""Security alert lifecycle management."""

from __future__ import annotations

from datetime import datetime, timedelta
import sys

from flask import has_request_context

from app.extensions import db
from app.services.audit import AuditLogger


class AlertManager:
    """Create, assign, prioritise, and resolve alerts."""

    SEVERITY_BASE_PRIORITY = {
        "critical": 0.85,
        "high": 0.65,
        "medium": 0.40,
        "low": 0.15,
    }

    @classmethod
    def create_alert(
        cls,
        institution_id,
        user_id,
        alert_type,
        severity,
        title,
        description,
        session_id=None,
        auto_action="none",
    ):
        """Create and auto assign a new alert."""
        try:
            from app.models import AdminUser, Alert, SessionRecord, User

            if not user_id and session_id:
                session = SessionRecord.query.filter_by(
                    id=session_id,
                    institution_id=institution_id,
                ).first()
                if session:
                    user_id = session.user_id

            if user_id:
                user = User.query.filter_by(id=user_id, institution_id=institution_id).first()
                if not user:
                    raise ValueError("Alert user does not belong to the institution.")

            created_at = datetime.utcnow()
            priority = cls._priority_for_new_alert(institution_id, user_id, severity, created_at)
            alert = Alert(
                institution_id=institution_id,
                session_id=session_id,
                user_id=user_id,
                alert_type=alert_type,
                severity=severity,
                ml_priority_score=priority,
                status="open",
                auto_action_taken=auto_action,
                title=title,
                description=description,
                created_at=created_at,
            )

            analyst = cls._least_loaded_analyst(institution_id)
            if analyst:
                alert.assigned_to = analyst.id

            db.session.add(alert)
            db.session.flush()
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="alert.created",
                institution_id=institution_id,
                target_type="alert",
                target_id=alert.id,
                details={
                    "alert_type": alert_type,
                    "severity": severity,
                    "user_id": user_id,
                },
                commit=False,
            )
            db.session.commit()
            return alert
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] Alert creation failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def _priority_for_new_alert(cls, institution_id, user_id, severity, created_at):
        try:
            from app.models import Alert

            priority = cls.SEVERITY_BASE_PRIORITY.get(severity, 0.40)
            open_alerts = Alert.query.filter_by(
                institution_id=institution_id,
                user_id=user_id,
                status="open",
            ).count()
            if open_alerts > 3:
                priority += 0.10
            ist_hour = (created_at + timedelta(hours=5, minutes=30)).hour
            if ist_hour >= 22 or ist_hour < 6:
                priority += 0.05
            return round(min(priority, 0.99), 2)
        except Exception as exc:
            print(f"[AlertManager] Priority calculation failed: {exc}", file=sys.stderr)
            return cls.SEVERITY_BASE_PRIORITY.get(severity, 0.40)

    @classmethod
    def _least_loaded_analyst(cls, institution_id):
        try:
            from app.models import AdminUser, Alert

            analysts = AdminUser.query.filter(
                AdminUser.institution_id == institution_id,
                AdminUser.role == "security_analyst",
                AdminUser._is_active.is_(True),
            ).all()
            if not analysts:
                return None
            return min(
                analysts,
                key=lambda analyst: Alert.query.filter_by(
                    assigned_to=analyst.id,
                    status="open",
                ).count(),
            )
        except Exception as exc:
            print(f"[AlertManager] Analyst assignment failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def dismiss_alert(cls, alert_id, admin_user, notes=None):
        """Dismiss an alert after analyst review."""
        try:
            alert = cls._get_authorized_alert(alert_id, admin_user)
            if not alert:
                return False, "Alert not found or access denied."
            previous_status = alert.status
            alert.status = "dismissed"
            alert.analyst_notes = notes
            alert.resolved_at = datetime.utcnow()
            cls._audit_admin_action(
                admin_user,
                "alert.dismiss",
                alert,
                {"notes": notes, "previous_status": previous_status},
            )
            db.session.add(alert)
            db.session.commit()
            return True, "Alert dismissed."
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] Alert dismiss failed: {exc}", file=sys.stderr)
            return False, "Alert could not be dismissed."

    @classmethod
    def escalate_alert(cls, alert_id, admin_user, notes=None):
        """Escalate an alert to senior security or compliance staff."""
        try:
            alert = cls._get_authorized_alert(alert_id, admin_user)
            if not alert:
                return False, "Alert not found or access denied."
            previous_status = alert.status
            escalation_target = cls._find_escalation_target(alert.institution_id)
            alert.status = "investigating"
            alert.assigned_to = escalation_target.id if escalation_target else alert.assigned_to
            alert.analyst_notes = notes
            cls._audit_admin_action(
                admin_user,
                "alert.escalate",
                alert,
                {
                    "notes": notes,
                    "previous_status": previous_status,
                    "assigned_to": alert.assigned_to,
                },
            )
            db.session.add(alert)
            db.session.commit()
            return True, "Alert escalated."
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] Alert escalation failed: {exc}", file=sys.stderr)
            return False, "Alert could not be escalated."

    @classmethod
    def resolve_alert(cls, alert_id, admin_user, notes=None):
        """Resolve an alert."""
        try:
            alert = cls._get_authorized_alert(alert_id, admin_user)
            if not alert:
                return False, "Alert not found or access denied."
            previous_status = alert.status
            alert.status = "resolved"
            alert.analyst_notes = notes
            alert.resolved_at = datetime.utcnow()
            cls._audit_admin_action(
                admin_user,
                "alert.resolve",
                alert,
                {"notes": notes, "previous_status": previous_status},
            )
            db.session.add(alert)
            db.session.commit()
            return True, "Alert resolved."
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] Alert resolve failed: {exc}", file=sys.stderr)
            return False, "Alert could not be resolved."

    @classmethod
    def mark_false_positive(cls, alert_id, admin_user):
        """Close an alert as a false positive and lower its model priority."""
        try:
            alert = cls._get_authorized_alert(alert_id, admin_user)
            if not alert:
                return False, "Alert not found or access denied."
            previous_status = alert.status
            alert.status = "false_positive"
            alert.resolved_at = datetime.utcnow()
            alert.ml_priority_score = max(0.0, float(alert.ml_priority_score or 0.0) - 0.2)
            cls._audit_admin_action(
                admin_user,
                "alert.false_positive",
                alert,
                {"previous_status": previous_status},
            )
            db.session.add(alert)
            db.session.commit()
            return True, "Alert marked as false positive."
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] False positive update failed: {exc}", file=sys.stderr)
            return False, "Alert could not be marked as false positive."

    @classmethod
    def _get_authorized_alert(cls, alert_id, admin_user):
        try:
            from app.models import Alert

            alert = Alert.query.get(alert_id)
            if not alert:
                return None
            if getattr(admin_user, "is_super_admin", False):
                return alert
            if alert.institution_id == getattr(admin_user, "institution_id", None):
                return alert
            return None
        except Exception as exc:
            print(f"[AlertManager] Alert authorization failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def _find_escalation_target(cls, institution_id):
        try:
            from app.models import AdminUser

            target = AdminUser.query.filter(
                AdminUser.institution_id == institution_id,
                AdminUser.role.in_(["super_admin", "compliance_officer"]),
                AdminUser._is_active.is_(True),
            ).first()
            if target:
                return target
            return AdminUser.query.filter(
                AdminUser.role == "super_admin",
                AdminUser._is_active.is_(True),
            ).first()
        except Exception as exc:
            print(f"[AlertManager] Escalation target lookup failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def _audit_admin_action(cls, admin_user, action, alert, details):
        try:
            if has_request_context():
                return AuditLogger.log_from_request(
                    admin_user,
                    action,
                    "alert",
                    alert.id,
                    details,
                    commit=False,
                )
            return AuditLogger.log(
                actor_type="admin",
                actor_id=getattr(admin_user, "id", None),
                actor_email=getattr(admin_user, "email", None),
                action=action,
                institution_id=alert.institution_id,
                target_type="alert",
                target_id=alert.id,
                details=details,
                commit=False,
            )
        except Exception as exc:
            print(f"[AlertManager] Audit logging failed: {exc}", file=sys.stderr)
            return False

    @classmethod
    def auto_prioritise_alerts(cls, institution_id=None):
        """Refresh priority scores for open alerts."""
        try:
            from app.models import Alert

            query = Alert.query.filter_by(status="open")
            if institution_id:
                query = query.filter(Alert.institution_id == institution_id)
            alerts = query.all()
            now = datetime.utcnow()
            for alert in alerts:
                priority = cls.SEVERITY_BASE_PRIORITY.get(alert.severity, 0.40)
                if alert.created_at:
                    age_days = max((now - alert.created_at).days, 0)
                    priority += min(age_days * 0.01, 0.15)
                if alert.user and alert.user.last_active_at:
                    hours_since_activity = (now - alert.user.last_active_at).total_seconds() / 3600
                    if hours_since_activity <= 24:
                        priority += 0.05
                alert.ml_priority_score = round(min(priority, 0.99), 2)
                db.session.add(alert)
            if alerts:
                AuditLogger.log(
                    actor_type="system",
                    actor_id=None,
                    action="alert.auto_prioritise",
                    institution_id=institution_id,
                    target_type="alert",
                    target_id=None,
                    details={"updated_count": len(alerts)},
                    commit=False,
                )
            db.session.commit()
            return len(alerts)
        except Exception as exc:
            db.session.rollback()
            print(f"[AlertManager] Auto prioritisation failed: {exc}", file=sys.stderr)
            return 0

    @classmethod
    def get_alerts_for_institution(cls, institution_id, filters=None, page=1, per_page=25):
        """Return paginated alerts for an institution."""
        try:
            from app.models import Alert
            from app.utils.pagination import paginate_query

            query = Alert.query.filter_by(institution_id=institution_id)
            filters = filters or {}
            if filters.get("severity"):
                query = query.filter(Alert.severity == filters["severity"])
            if filters.get("alert_type"):
                query = query.filter(Alert.alert_type == filters["alert_type"])
            if filters.get("status"):
                query = query.filter(Alert.status == filters["status"])
            if filters.get("date_from"):
                query = query.filter(Alert.created_at >= cls._coerce_datetime(filters["date_from"]))
            if filters.get("date_to"):
                query = query.filter(Alert.created_at <= cls._coerce_datetime(filters["date_to"]))
            query = query.order_by(Alert.ml_priority_score.desc(), Alert.created_at.desc())
            return paginate_query(query, page, per_page)
        except Exception as exc:
            print(f"[AlertManager] Alert pagination failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def get_alert_with_context(cls, alert_id):
        """Return alert details with related session, risk, user, and device context."""
        try:
            from app.models import Alert, Device, RiskEvent

            alert = Alert.query.get(alert_id)
            if not alert:
                return {}
            risk_events = []
            if alert.session_id:
                risk_events = (
                    RiskEvent.query.filter_by(session_id=alert.session_id)
                    .order_by(RiskEvent.evaluated_at.asc())
                    .all()
                )
            prior_alerts = (
                Alert.query.filter(
                    Alert.user_id == alert.user_id,
                    Alert.id != alert.id,
                )
                .order_by(Alert.created_at.desc())
                .limit(5)
                .all()
            )
            devices = (
                Device.query.filter_by(user_id=alert.user_id, is_removed=False)
                .order_by(Device.last_seen_at.desc())
                .all()
            )
            return {
                "alert": alert.to_dict(),
                "session": alert.session.to_dict() if alert.session else None,
                "user": alert.user.to_dict() if alert.user else None,
                "risk_events": [event.to_dict() for event in risk_events],
                "user_recent_alerts": [item.to_dict() for item in prior_alerts],
                "devices": [device.to_dict() for device in devices],
            }
        except Exception as exc:
            print(f"[AlertManager] Alert context failed: {exc}", file=sys.stderr)
            return {}

    @staticmethod
    def _coerce_datetime(value):
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value))
