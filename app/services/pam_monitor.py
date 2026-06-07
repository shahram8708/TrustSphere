"""Privileged access monitoring service."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import statistics
import sys

from app.extensions import db
from app.services.audit import AuditLogger


class PrivilegedAccessMonitor:
    """Monitor employee privileged sessions for insider threat patterns."""

    THRESHOLD_ACTIONS_PER_HOUR = 100
    THRESHOLD_RECORDS_PER_SESSION = 500
    THRESHOLD_EXPORT_KB = 10240
    THRESHOLD_OFF_HOURS_START = 22
    THRESHOLD_OFF_HOURS_END = 6
    CRITICAL_SYSTEMS = {"Reporting-DB", "Backup-Server", "Admin-Portal"}

    @classmethod
    def start_session(cls, employee_user_id, institution_id, role, privilege_level, system_accessed):
        """Create a new privileged access session."""
        try:
            from app.models import PrivilegedSession

            session = PrivilegedSession(
                employee_user_id=employee_user_id,
                institution_id=institution_id,
                role=role,
                privilege_level=privilege_level,
                system_accessed=system_accessed,
                actions_count=0,
                data_records_accessed=0,
                export_volume_kb=0,
                anomaly_flags=json.dumps({}),
                risk_score=5,
                alert_generated=False,
                started_at=datetime.utcnow(),
            )
            db.session.add(session)
            db.session.flush()
            AuditLogger.log(
                actor_type="system",
                actor_id=employee_user_id,
                action="pam.session.start",
                institution_id=institution_id,
                target_type="privileged_session",
                target_id=session.id,
                details={"system_accessed": system_accessed, "privilege_level": privilege_level},
                commit=False,
            )
            db.session.commit()
            return session
        except Exception as exc:
            db.session.rollback()
            print(f"[PrivilegedAccessMonitor] Session start failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def log_action(cls, priv_session_id, action_type, records_accessed=0, export_kb=0):
        """Update privileged activity counters and run anomaly checks."""
        try:
            from app.models import PrivilegedSession

            session = PrivilegedSession.query.get(priv_session_id)
            if not session:
                return None
            session.actions_count = int(session.actions_count or 0) + 1
            session.data_records_accessed = int(session.data_records_accessed or 0) + int(records_accessed or 0)
            session.export_volume_kb = int(session.export_volume_kb or 0) + int(export_kb or 0)
            anomalies = cls._check_anomalies(session)
            session.risk_score = cls._calculate_risk_score(session, anomalies)
            db.session.add(session)
            db.session.commit()
            return session
        except Exception as exc:
            db.session.rollback()
            print(f"[PrivilegedAccessMonitor] Action logging failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def _check_anomalies(cls, priv_session):
        """Return anomaly flags and create alerts for newly detected anomalies."""
        try:
            current_flags = cls._load_flags(priv_session.anomaly_flags)
            detected = {}

            if (
                int(priv_session.actions_count or 0) > cls.THRESHOLD_ACTIONS_PER_HOUR
                and priv_session.duration_hours < 1
            ):
                detected["high_action_velocity"] = 0.85

            if int(priv_session.data_records_accessed or 0) > cls.THRESHOLD_RECORDS_PER_SESSION:
                detected["bulk_record_access"] = min(
                    0.95,
                    0.5 + int(priv_session.data_records_accessed or 0) / 2000,
                )

            if int(priv_session.export_volume_kb or 0) > cls.THRESHOLD_EXPORT_KB:
                detected["large_data_export"] = min(
                    0.98,
                    0.6 + int(priv_session.export_volume_kb or 0) / 50000,
                )

            if priv_session.started_at:
                hour = priv_session.started_at.hour
                if hour >= cls.THRESHOLD_OFF_HOURS_START or hour < cls.THRESHOLD_OFF_HOURS_END:
                    detected["off_hours_access"] = 0.65

            if (
                priv_session.system_accessed in cls.CRITICAL_SYSTEMS
                and priv_session.privilege_level == "standard"
            ):
                detected["unauthorized_system_access"] = 0.90

            new_anomalies = {
                key: value
                for key, value in detected.items()
                if key not in current_flags
            }
            if new_anomalies:
                current_flags.update(new_anomalies)
                priv_session.anomaly_flags = json.dumps(current_flags, sort_keys=True)
                priv_session.alert_generated = True
                db.session.add(priv_session)
                cls._create_anomaly_alert(priv_session, new_anomalies)
            return current_flags
        except Exception as exc:
            print(f"[PrivilegedAccessMonitor] Anomaly check failed: {exc}", file=sys.stderr)
            return cls._load_flags(getattr(priv_session, "anomaly_flags", None))

    @classmethod
    def _create_anomaly_alert(cls, priv_session, anomalies):
        try:
            from app.services.alert_manager import AlertManager

            severity = cls._severity_for_anomalies(anomalies)
            labels = [key.replace("_", " ").title() for key in anomalies]
            title = "Privileged access anomaly: " + ", ".join(labels)
            description = (
                f"Privileged session {priv_session.id} on {priv_session.system_accessed} "
                f"generated anomaly flags {json.dumps(anomalies, sort_keys=True)}."
            )
            AlertManager.create_alert(
                institution_id=priv_session.institution_id,
                user_id=priv_session.employee_user_id,
                alert_type="insider_anomaly",
                severity=severity,
                title=title,
                description=description,
                session_id=None,
                auto_action="investigate",
            )
            AuditLogger.log(
                actor_type="system",
                actor_id=priv_session.employee_user_id,
                action="pam.anomaly_alert",
                institution_id=priv_session.institution_id,
                target_type="privileged_session",
                target_id=priv_session.id,
                details={"anomalies": anomalies, "severity": severity},
                commit=False,
            )
        except Exception as exc:
            print(f"[PrivilegedAccessMonitor] Anomaly alert failed: {exc}", file=sys.stderr)

    @staticmethod
    def _severity_for_anomalies(anomalies):
        highest = max(anomalies.values()) if anomalies else 0
        if highest > 0.85:
            return "critical"
        if highest > 0.70:
            return "high"
        return "medium"

    @classmethod
    def compute_risk_score(cls, priv_session, commit=True):
        """Compute, save, and return a privileged session risk score."""
        try:
            flags = cls._load_flags(priv_session.anomaly_flags)
            score = cls._calculate_risk_score(priv_session, flags)
            priv_session.risk_score = score
            db.session.add(priv_session)
            if commit:
                db.session.commit()
            return score
        except Exception as exc:
            if commit:
                db.session.rollback()
            print(f"[PrivilegedAccessMonitor] Risk score calculation failed: {exc}", file=sys.stderr)
            return int(getattr(priv_session, "risk_score", 0) or 0)

    @classmethod
    def _calculate_risk_score(cls, priv_session, flags):
        score = 5.0
        score += min((int(priv_session.actions_count or 0) / 200) * 20, 20)
        score += min((int(priv_session.data_records_accessed or 0) / 1000) * 30, 30)
        score += min((int(priv_session.export_volume_kb or 0) / 20480) * 30, 30)
        if priv_session.started_at:
            hour = priv_session.started_at.hour
            if hour >= cls.THRESHOLD_OFF_HOURS_START or hour < cls.THRESHOLD_OFF_HOURS_END:
                score += 15
        if any(float(value) > 0.8 for value in (flags or {}).values()):
            score += 20
        return int(min(round(score), 100))

    @classmethod
    def end_session(cls, priv_session_id):
        """End a privileged session and persist its final risk score."""
        try:
            from app.models import PrivilegedSession

            session = PrivilegedSession.query.get(priv_session_id)
            if not session:
                return None
            session.ended_at = datetime.utcnow()
            cls.compute_risk_score(session, commit=False)
            AuditLogger.log(
                actor_type="system",
                actor_id=session.employee_user_id,
                action="pam.session.end",
                institution_id=session.institution_id,
                target_type="privileged_session",
                target_id=session.id,
                details={"risk_score": session.risk_score},
                commit=False,
            )
            db.session.add(session)
            db.session.commit()
            return session
        except Exception as exc:
            db.session.rollback()
            print(f"[PrivilegedAccessMonitor] Session end failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def get_employee_risk_summary(cls, employee_user_id, institution_id, days=30):
        """Return privileged access risk summary for an employee."""
        try:
            from app.models import PrivilegedSession

            cutoff = datetime.utcnow() - timedelta(days=int(days or 30))
            sessions = (
                PrivilegedSession.query.filter(
                    PrivilegedSession.employee_user_id == employee_user_id,
                    PrivilegedSession.institution_id == institution_id,
                    PrivilegedSession.started_at >= cutoff,
                )
                .order_by(PrivilegedSession.started_at.desc())
                .all()
            )
            risk_scores = [int(session.risk_score or 0) for session in sessions]
            return {
                "total_sessions": len(sessions),
                "high_risk_sessions": sum(1 for session in sessions if int(session.risk_score or 0) > 60),
                "total_records_accessed": sum(int(session.data_records_accessed or 0) for session in sessions),
                "total_export_kb": sum(int(session.export_volume_kb or 0) for session in sessions),
                "alerts_generated": sum(1 for session in sessions if session.alert_generated),
                "avg_risk_score": round(statistics.mean(risk_scores), 2) if risk_scores else 0.0,
                "last_session_at": sessions[0].started_at.isoformat() if sessions and sessions[0].started_at else None,
            }
        except Exception as exc:
            print(f"[PrivilegedAccessMonitor] Employee summary failed: {exc}", file=sys.stderr)
            return {
                "total_sessions": 0,
                "high_risk_sessions": 0,
                "total_records_accessed": 0,
                "total_export_kb": 0,
                "alerts_generated": 0,
                "avg_risk_score": 0.0,
                "last_session_at": None,
            }

    @staticmethod
    def _load_flags(raw_value):
        if not raw_value:
            return {}
        try:
            value = json.loads(raw_value)
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}
