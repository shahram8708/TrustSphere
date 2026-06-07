"""Celery Beat schedule for TrustSphere background jobs."""

from __future__ import annotations

from celery.schedules import crontab

from app.tasks.celery_app import celery
from app.tasks.alert_notify import alert_escalation_reminder_task, auto_prioritise_alerts_task
from app.tasks.behavioural_update import rebuild_all_profiles_task
from app.tasks.data_cleanup import (
    cleanup_expired_challenges_task,
    cleanup_stale_reports_task,
    purge_old_audit_logs_task,
    purge_old_sessions_task,
)
from app.tasks.device_analysis import device_trust_decay_task
from app.tasks.email_tasks import send_all_weekly_digests_task
from app.tasks.kyc_processing import (
    batch_score_pending_applications_task,
    scheduled_kyc_review_reminder_task,
    watchlist_refresh_task,
)
from app.tasks.pam_analysis import check_active_pam_sessions_task
from app.tasks.report_build import scheduled_daily_report_task
from app.tasks.risk_update import recalculate_all_session_baselines_task


registered_periodic_tasks = (
    alert_escalation_reminder_task,
    auto_prioritise_alerts_task,
    batch_score_pending_applications_task,
    check_active_pam_sessions_task,
    cleanup_expired_challenges_task,
    cleanup_stale_reports_task,
    device_trust_decay_task,
    purge_old_audit_logs_task,
    purge_old_sessions_task,
    rebuild_all_profiles_task,
    recalculate_all_session_baselines_task,
    scheduled_daily_report_task,
    scheduled_kyc_review_reminder_task,
    send_all_weekly_digests_task,
    watchlist_refresh_task,
)
for task in registered_periodic_tasks:
    getattr(task, "name", None)


celery.conf.beat_schedule = {
    "auto-prioritise-alerts": {
        "task": "trustsphere.tasks.alert.auto_prioritise",
        "schedule": crontab(minute="*/30"),
        "args": [],
    },
    "check-active-pam-sessions": {
        "task": "trustsphere.tasks.pam.check_active_sessions",
        "schedule": crontab(minute=0),
        "args": [],
    },
    "batch-score-pending-kyc": {
        "task": "trustsphere.tasks.kyc.batch_score_pending",
        "schedule": crontab(minute=15),
        "args": [],
    },
    "cleanup-expired-challenges": {
        "task": "trustsphere.tasks.cleanup.expired_challenges",
        "schedule": crontab(minute="*/15"),
        "args": [],
    },
    "daily-scheduled-report": {
        "task": "trustsphere.tasks.report.daily_scheduled",
        "schedule": crontab(hour=0, minute=30),
        "args": [],
    },
    "kyc-review-reminder": {
        "task": "trustsphere.tasks.kyc.review_reminder",
        "schedule": crontab(hour=1, minute=0),
        "args": [],
    },
    "alert-escalation-reminder": {
        "task": "trustsphere.tasks.alert.escalation_reminder",
        "schedule": crontab(hour=1, minute=30),
        "args": [],
    },
    "watchlist-refresh": {
        "task": "trustsphere.tasks.kyc.watchlist_refresh",
        "schedule": crontab(hour=2, minute=0),
        "args": [],
    },
    "device-trust-decay": {
        "task": "trustsphere.tasks.device.trust_decay",
        "schedule": crontab(hour=2, minute=0, day_of_week="monday"),
        "args": [],
    },
    "session-baseline-refresh": {
        "task": "trustsphere.tasks.risk.session_baseline_refresh",
        "schedule": crontab(hour=3, minute=0, day_of_week="monday"),
        "args": [],
    },
    "weekly-security-digests": {
        "task": "trustsphere.tasks.email.weekly_digest_all",
        "schedule": crontab(hour=6, minute=0, day_of_week="monday"),
        "args": [],
    },
    "rebuild-behavioural-profiles": {
        "task": "trustsphere.tasks.behavioural.rebuild_all",
        "schedule": crontab(hour=3, minute=0, day_of_month="1"),
        "args": [],
    },
    "session-purge": {
        "task": "trustsphere.tasks.cleanup.purge_old_sessions",
        "schedule": crontab(hour=4, minute=0, day_of_month="1"),
        "args": [],
    },
    "audit-log-archival": {
        "task": "trustsphere.tasks.cleanup.archive_audit_logs",
        "schedule": crontab(hour=5, minute=0, day_of_month="1"),
        "args": [],
    },
    "cleanup-stale-reports": {
        "task": "trustsphere.tasks.cleanup.stale_reports",
        "schedule": crontab(hour=23, minute=30),
        "args": [],
    },
}
