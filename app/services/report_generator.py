"""Compliance and security report generation."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from io import StringIO
import csv
import json
import statistics
import sys


class ComplianceReportGenerator:
    """Generate operational and regulatory reports from TrustSphere data."""

    @classmethod
    def generate_rbi_report(cls, institution_id, date_from, date_to):
        """Generate RBI cybersecurity framework reporting metrics."""
        try:
            from app.models import Alert, AuditLog, OnboardingApplication, PrivilegedSession, SessionRecord, User

            sessions = cls._sessions(institution_id, date_from, date_to)
            alerts = cls._alerts(institution_id, date_from, date_to)
            resolved_alerts = [
                alert for alert in alerts if alert.resolved_at and alert.created_at
            ]
            resolution_hours = [
                (alert.resolved_at - alert.created_at).total_seconds() / 3600
                for alert in resolved_alerts
            ]
            stepup_sessions = [session for session in sessions if session.stepup_triggered]
            passed_stepups = [
                session for session in stepup_sessions if session.stepup_outcome == "passed"
            ]
            high_risk_sessions = [session for session in sessions if int(session.risk_score_peak or 0) > 80]
            users_over_threshold = User.query.filter(
                User.institution_id == institution_id,
                User.risk_score_current > 60,
            ).count()
            pam_alerts = PrivilegedSession.query.filter(
                PrivilegedSession.institution_id == institution_id,
                PrivilegedSession.started_at >= date_from,
                PrivilegedSession.started_at <= date_to,
                PrivilegedSession.alert_generated.is_(True),
            ).count()
            audit_count = AuditLog.query.filter(
                AuditLog.institution_id == institution_id,
                AuditLog.created_at >= date_from,
                AuditLog.created_at <= date_to,
            ).count()
            onboarding = OnboardingApplication.query.filter(
                OnboardingApplication.institution_id == institution_id,
                OnboardingApplication.submitted_at >= date_from,
                OnboardingApplication.submitted_at <= date_to,
            ).all()

            severity_counts = Counter(alert.severity for alert in alerts)
            decision_counts = Counter(application.decision for application in onboarding)
            false_positive_count = sum(1 for alert in alerts if alert.status == "false_positive")

            return {
                "period": cls._period(date_from, date_to),
                "session_analytics": {
                    "total_sessions": len(sessions),
                    "high_risk_sessions": len(high_risk_sessions),
                    "average_peak_risk": round(
                        statistics.mean([session.risk_score_peak or 0 for session in sessions]),
                        2,
                    )
                    if sessions
                    else 0.0,
                },
                "alert_analytics": {
                    "total_alerts": len(alerts),
                    "by_severity": dict(severity_counts),
                    "average_resolution_hours": round(statistics.mean(resolution_hours), 2)
                    if resolution_hours
                    else 0.0,
                    "false_positive_rate": round(false_positive_count / len(alerts), 4)
                    if alerts
                    else 0.0,
                },
                "authentication_metrics": {
                    "stepup_triggered_sessions": len(stepup_sessions),
                    "stepup_success_rate": round(len(passed_stepups) / len(stepup_sessions), 4)
                    if stepup_sessions
                    else 0.0,
                    "users_above_risk_threshold": users_over_threshold,
                },
                "privileged_access_metrics": {
                    "pam_alert_sessions": pam_alerts,
                },
                "onboarding_metrics": {
                    "total_applications": len(onboarding),
                    "decisions": dict(decision_counts),
                },
                "audit_metrics": {
                    "audit_log_entries": audit_count,
                },
                "compliance_controls": [
                    {
                        "control": "Continuous monitoring",
                        "requirement": "RBI cyber risk monitoring",
                        "status": "active" if sessions else "no activity",
                    },
                    {
                        "control": "Incident tracking",
                        "requirement": "Cyber incident detection and response",
                        "status": "active" if alerts else "no incidents",
                    },
                    {
                        "control": "Privileged access oversight",
                        "requirement": "Access governance",
                        "status": "active",
                    },
                    {
                        "control": "Audit evidence",
                        "requirement": "Immutable operational logs",
                        "status": "active" if audit_count else "limited evidence",
                    },
                ],
            }
        except Exception as exc:
            print(f"[ComplianceReportGenerator] RBI report failed: {exc}", file=sys.stderr)
            return cls._empty_report("rbi_report", date_from, date_to)

    @classmethod
    def generate_alert_summary_report(cls, institution_id, date_from, date_to):
        """Generate alert volume and resolution summary."""
        try:
            from app.models import Alert, User

            alerts = cls._alerts(institution_id, date_from, date_to)
            severity_counts = Counter(alert.severity for alert in alerts)
            type_counts = Counter(alert.alert_type for alert in alerts)
            status_counts = Counter(alert.status for alert in alerts)
            resolved = [alert for alert in alerts if alert.resolved_at and alert.created_at]
            resolution_hours = [
                (alert.resolved_at - alert.created_at).total_seconds() / 3600
                for alert in resolved
            ]

            user_counts = Counter(alert.user_id for alert in alerts if alert.user_id)
            top_users = []
            for user_id, count in user_counts.most_common(5):
                user = User.query.get(user_id)
                top_users.append(
                    {
                        "masked_user_id": user.get_masked_id() if user else user_id[:8] + "***",
                        "alert_count": count,
                    }
                )

            # include detailed alert rows to enable full CSV/JSON exports
            alerts_list = []
            for alert in alerts:
                d = alert.to_dict()
                try:
                    d["masked_user_id"] = alert.user.get_masked_id() if alert.user else None
                except Exception:
                    d["masked_user_id"] = None
                alerts_list.append(d)

            return {
                "period": cls._period(date_from, date_to),
                "severity_counts": dict(severity_counts),
                "alert_type_counts": dict(type_counts),
                "resolution_stats": {
                    "open": status_counts.get("open", 0),
                    "investigating": status_counts.get("investigating", 0),
                    "resolved": status_counts.get("resolved", 0),
                    "dismissed": status_counts.get("dismissed", 0),
                    "false_positive": status_counts.get("false_positive", 0),
                },
                "average_resolution_hours": round(statistics.mean(resolution_hours), 2)
                if resolution_hours
                else 0.0,
                "top_users": top_users,
                "alert_trend": cls._alert_trend(alerts, date_from, date_to),
                "alerts": alerts_list,
            }
        except Exception as exc:
            print(f"[ComplianceReportGenerator] Alert summary failed: {exc}", file=sys.stderr)
            return cls._empty_report("alert_summary", date_from, date_to)

    @classmethod
    def generate_user_risk_report(cls, institution_id):
        """Generate current user risk snapshot."""
        try:
            from app.models import Alert, SessionRecord, User
            from app.services.risk_engine import ContinuousRiskEngine

            users = User.query.filter_by(institution_id=institution_id).all()
            distribution = Counter(
                ContinuousRiskEngine.get_risk_category_for_score(
                    user.risk_score_current,
                    institution_id,
                )
                for user in users
            )
            cutoff = datetime.utcnow() - timedelta(days=30)
            recent_user_ids = {
                session.user_id
                for session in SessionRecord.query.filter(
                    SessionRecord.institution_id == institution_id,
                    SessionRecord.started_at >= cutoff,
                ).all()
            }
            top_users = sorted(
                users,
                key=lambda user: int(user.risk_score_current or 0),
                reverse=True,
            )[:10]
            top_rows = []
            for user in top_users:
                open_alerts = Alert.query.filter_by(
                    institution_id=institution_id,
                    user_id=user.id,
                    status="open",
                ).count()
                top_rows.append(
                    {
                        "masked_user_id": user.get_masked_id(),
                        "risk_category": ContinuousRiskEngine.get_risk_category_for_score(
                            user.risk_score_current,
                            institution_id,
                        ),
                        "risk_score": user.risk_score_current,
                        "last_active": user.last_active_at.isoformat() if user.last_active_at else None,
                        "open_alerts_count": open_alerts,
                    }
                )
            scores = [int(user.risk_score_current or 0) for user in users]
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "distribution": {
                    "Low": distribution.get("Low", 0),
                    "Medium": distribution.get("Medium", 0),
                    "High": distribution.get("High", 0),
                    "Critical": distribution.get("Critical", 0),
                },
                "suspended_users": sum(1 for user in users if user.is_suspended),
                "users_with_no_recent_activity": sum(1 for user in users if user.id not in recent_user_ids),
                "top_high_risk_users": top_rows,
                "average_risk_score": round(statistics.mean(scores), 2) if scores else 0.0,
            }
        except Exception as exc:
            print(f"[ComplianceReportGenerator] User risk report failed: {exc}", file=sys.stderr)
            return cls._empty_report("user_risk", datetime.utcnow(), datetime.utcnow())

    @classmethod
    def generate_incident_report(cls, alert_id):
        """Generate a detailed incident report for one alert."""
        try:
            from app.models import Alert, AuditLog, RiskEvent

            alert = Alert.query.get(alert_id)
            if not alert:
                return {}
            session = alert.session
            user = alert.user
            risk_events = []
            if session:
                risk_events = (
                    RiskEvent.query.filter_by(session_id=session.id)
                    .order_by(RiskEvent.evaluated_at.asc())
                    .all()
                )
            actions = (
                AuditLog.query.filter(
                    AuditLog.target_type == "alert",
                    AuditLog.target_id == alert.id,
                )
                .order_by(AuditLog.created_at.asc())
                .all()
            )
            prior_alert_count = (
                Alert.query.filter(
                    Alert.user_id == alert.user_id,
                    Alert.id != alert.id,
                ).count()
                if alert.user_id
                else 0
            )
            account_tenure_days = None
            if user and user.created_at:
                account_tenure_days = (datetime.utcnow() - user.created_at).days

            return {
                "alert": alert.to_dict(),
                "session": session.to_dict() if session else None,
                "risk_event_timeline": [
                    {
                        "timestamp": event.evaluated_at.isoformat() if event.evaluated_at else None,
                        "event_type": event.event_type,
                        "risk_before": event.risk_score_before,
                        "risk_after": event.risk_score_after,
                        "risk_delta": event.risk_delta,
                        "contributing_factors": event.get_contributing_factors_dict(),
                    }
                    for event in risk_events
                ],
                "user_context": {
                    "masked_user_id": user.get_masked_id() if user else None,
                    "user_type": user.user_type if user else None,
                    "account_tenure_days": account_tenure_days,
                    "prior_alert_count": prior_alert_count,
                },
                "actions_taken": [action.to_dict() for action in actions],
                "analyst_notes": alert.analyst_notes,
                "resolution_timeline": {
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
                    "status": alert.status,
                },
            }
        except Exception as exc:
            print(f"[ComplianceReportGenerator] Incident report failed: {exc}", file=sys.stderr)
            return {}

    @classmethod
    def export_to_csv(cls, data_dict, report_type):
        """Export a report dictionary to CSV."""
        try:
            buffer = StringIO()
            writer = csv.writer(buffer)
            if report_type == "alert_summary":
                # Severity summary
                writer.writerow(["Severity", "Count"])
                for severity, count in sorted(data_dict.get("severity_counts", {}).items(), key=lambda x: x[0]):
                    writer.writerow([severity or "", count])

                writer.writerow([])

                # Alert type summary with resolution breakdown (computed from detailed alerts when available)
                writer.writerow(["Alert Type", "Total", "Resolved", "Dismissed", "False Positive"])
                # build per-type counters
                per_type = {}
                for t, total in (data_dict.get("alert_type_counts") or {}).items():
                    per_type[t] = {"total": total, "resolved": 0, "dismissed": 0, "false_positive": 0}

                # If detailed alerts are present, compute resolved/dismissed/false_positive per type
                for alert in data_dict.get("alerts", []):
                    t = alert.get("alert_type") or ""
                    row = per_type.setdefault(t, {"total": 0, "resolved": 0, "dismissed": 0, "false_positive": 0})
                    # ensure total counts reflect detailed rows if alert_type_counts was empty
                    row["total"] = row.get("total", 0) + 1
                    status = (alert.get("status") or "").lower()
                    if status == "resolved":
                        row["resolved"] += 1
                    elif status == "dismissed":
                        row["dismissed"] += 1
                    elif status == "false_positive":
                        row["false_positive"] += 1

                for alert_type, stats in sorted(per_type.items(), key=lambda x: x[0]):
                    writer.writerow([
                        alert_type or "",
                        stats.get("total", 0),
                        stats.get("resolved", 0),
                        stats.get("dismissed", 0),
                        stats.get("false_positive", 0),
                    ])

                writer.writerow([])

                # Detailed alerts table
                writer.writerow([
                    "ID",
                    "Created At",
                    "Alert Type",
                    "Alert Type Display",
                    "Severity",
                    "Status",
                    "Resolved At",
                    "User ID",
                    "Masked User ID",
                    "Title",
                    "Description",
                ])
                for alert in data_dict.get("alerts", []):
                    writer.writerow([
                        alert.get("id"),
                        alert.get("created_at"),
                        alert.get("alert_type"),
                        alert.get("alert_type_display"),
                        alert.get("severity"),
                        alert.get("status"),
                        alert.get("resolved_at"),
                        alert.get("user_id"),
                        alert.get("masked_user_id"),
                        alert.get("title"),
                        alert.get("description"),
                    ])
            elif report_type == "rbi_report":
                writer.writerow(["Metric", "Value", "Target", "Status"])
                for section, values in data_dict.items():
                    if isinstance(values, dict):
                        for key, value in values.items():
                            writer.writerow([f"{section}.{key}", value, "", ""])
                for control in data_dict.get("compliance_controls", []):
                    writer.writerow([
                        control.get("control"),
                        control.get("requirement"),
                        "Implemented",
                        control.get("status"),
                    ])
            elif report_type == "user_risk":
                writer.writerow(["Masked User ID", "Risk Category", "Risk Score", "Last Active", "Open Alerts"])
                for row in data_dict.get("top_high_risk_users", []):
                    writer.writerow([
                        row.get("masked_user_id"),
                        row.get("risk_category"),
                        row.get("risk_score"),
                        row.get("last_active"),
                        row.get("open_alerts_count"),
                    ])
            elif report_type == "incident":
                writer.writerow(["Timestamp", "Event Type", "Risk Before", "Risk After", "Action Taken"])
                for row in data_dict.get("risk_event_timeline", []):
                    writer.writerow([
                        row.get("timestamp"),
                        row.get("event_type"),
                        row.get("risk_before"),
                        row.get("risk_after"),
                        "",
                    ])
                for action in data_dict.get("actions_taken", []):
                    writer.writerow([
                        action.get("created_at"),
                        "",
                        "",
                        "",
                        action.get("action"),
                    ])
            return buffer.getvalue()
        except Exception as exc:
            print(f"[ComplianceReportGenerator] CSV export failed: {exc}", file=sys.stderr)
            return ""

    @classmethod
    def export_to_json(cls, data_dict):
        """Export a report dictionary to formatted JSON."""
        try:
            return json.dumps(data_dict, indent=2, default=str)
        except Exception as exc:
            print(f"[ComplianceReportGenerator] JSON export failed: {exc}", file=sys.stderr)
            return "{}"

    @classmethod
    def get_report_metadata(cls, report_type):
        """Return metadata for report selection UI."""
        try:
            metadata = {
                "rbi_report": {
                    "name": "RBI Cybersecurity Framework Report",
                    "description": "Operational control evidence for cyber monitoring, incident response, and access governance.",
                    "suggested_frequency": "Monthly",
                    "regulatory_mapping": ["RBI Cybersecurity Framework", "DPDP Act"],
                },
                "alert_summary": {
                    "name": "Alert Summary Report",
                    "description": "Alert volume, severity, resolution, and user concentration metrics.",
                    "suggested_frequency": "Weekly",
                    "regulatory_mapping": ["ISO 27001", "PCI DSS"],
                },
                "user_risk": {
                    "name": "User Risk Snapshot",
                    "description": "Current distribution of user risk with highest risk identities.",
                    "suggested_frequency": "Daily",
                    "regulatory_mapping": ["RBI Cybersecurity Framework", "PSD2 SCA"],
                },
                "incident": {
                    "name": "Incident Report",
                    "description": "Detailed investigation record for a single security alert.",
                    "suggested_frequency": "Per incident",
                    "regulatory_mapping": ["RBI Cybersecurity Framework", "ISO 27001"],
                },
            }
            return metadata.get(report_type, {})
        except Exception as exc:
            print(f"[ComplianceReportGenerator] Metadata lookup failed: {exc}", file=sys.stderr)
            return {}

    @staticmethod
    def _sessions(institution_id, date_from, date_to):
        from app.models import SessionRecord

        return SessionRecord.query.filter(
            SessionRecord.institution_id == institution_id,
            SessionRecord.started_at >= date_from,
            SessionRecord.started_at <= date_to,
        ).all()

    @staticmethod
    def _alerts(institution_id, date_from, date_to):
        from app.models import Alert

        return Alert.query.filter(
            Alert.institution_id == institution_id,
            Alert.created_at >= date_from,
            Alert.created_at <= date_to,
        ).all()

    @staticmethod
    def _period(date_from, date_to):
        return {
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
        }

    @staticmethod
    def _alert_trend(alerts, date_from, date_to):
        counts = Counter(alert.created_at.date().isoformat() for alert in alerts if alert.created_at)
        days = []
        current = date_from.date()
        final = date_to.date()
        while current <= final:
            key = current.isoformat()
            days.append({"date": key, "count": counts.get(key, 0)})
            current += timedelta(days=1)
        return days

    @classmethod
    def _empty_report(cls, report_type, date_from, date_to):
        if report_type == "rbi_report":
            return {
                "period": cls._period(date_from, date_to),
                "session_analytics": {},
                "alert_analytics": {},
                "authentication_metrics": {},
                "privileged_access_metrics": {},
                "onboarding_metrics": {},
                "compliance_controls": [],
            }
        if report_type == "alert_summary":
            return {
                "period": cls._period(date_from, date_to),
                "severity_counts": {},
                "alert_type_counts": {},
                "resolution_stats": {},
                "average_resolution_hours": 0.0,
                "top_users": [],
                "alert_trend": [],
            }
        if report_type == "user_risk":
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "suspended_users": 0,
                "users_with_no_recent_activity": 0,
                "top_high_risk_users": [],
                "average_risk_score": 0.0,
            }
        return {}
