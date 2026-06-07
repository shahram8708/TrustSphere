"""Background task package for TrustSphere.

The task layer includes Celery setup, email delivery, risk refresh, alert
lifecycle handling, report generation, behavioural profile updates, device
analysis, KYC processing, PAM monitoring, scheduled jobs, and cleanup jobs.
"""

from app.tasks.celery_app import celery
from app.tasks.alert_notify import (
    alert_created_task,
    alert_escalation_reminder_task,
    auto_prioritise_alerts_task,
    block_user_session_task,
    escalate_alert_task,
)
from app.tasks.behavioural_update import rebuild_all_profiles_task, update_behavioural_profile_task
from app.tasks.data_cleanup import (
    cleanup_expired_challenges_task,
    cleanup_stale_reports_task,
    purge_old_audit_logs_task,
    purge_old_sessions_task,
)
from app.tasks.device_analysis import analyse_new_device_task, device_trust_decay_task
from app.tasks.email_tasks import (
    send_account_recovery_status_task,
    send_alert_notification_email_task,
    send_all_weekly_digests_task,
    send_contact_form_notification_task,
    send_demo_request_notification_task,
    send_escalation_notification_task,
    send_kyc_decision_notification_task,
    send_password_reset_email_task,
    send_stepup_challenge_notification_task,
    send_verification_email_task,
    send_weekly_security_digest_task,
)
from app.tasks.kyc_processing import (
    batch_score_pending_applications_task,
    process_kyc_application_task,
    scheduled_kyc_review_reminder_task,
    watchlist_refresh_task,
)
from app.tasks.pam_analysis import (
    check_active_pam_sessions_task,
    generate_pam_report_task,
    pam_anomaly_alert_task,
    pam_session_timeout_task,
)
from app.tasks.report_build import (
    export_audit_log_task,
    generate_compliance_report_task,
    scheduled_daily_report_task,
)
from app.tasks.risk_update import (
    async_risk_score_update_task,
    batch_recalculate_risk_scores_task,
    recalculate_all_session_baselines_task,
)

__all__ = [
    "celery",
    "alert_created_task",
    "alert_escalation_reminder_task",
    "analyse_new_device_task",
    "async_risk_score_update_task",
    "auto_prioritise_alerts_task",
    "batch_recalculate_risk_scores_task",
    "batch_score_pending_applications_task",
    "block_user_session_task",
    "check_active_pam_sessions_task",
    "cleanup_expired_challenges_task",
    "cleanup_stale_reports_task",
    "device_trust_decay_task",
    "escalate_alert_task",
    "export_audit_log_task",
    "generate_compliance_report_task",
    "generate_pam_report_task",
    "pam_anomaly_alert_task",
    "pam_session_timeout_task",
    "process_kyc_application_task",
    "purge_old_audit_logs_task",
    "purge_old_sessions_task",
    "rebuild_all_profiles_task",
    "recalculate_all_session_baselines_task",
    "scheduled_daily_report_task",
    "scheduled_kyc_review_reminder_task",
    "send_account_recovery_status_task",
    "send_alert_notification_email_task",
    "send_all_weekly_digests_task",
    "send_contact_form_notification_task",
    "send_demo_request_notification_task",
    "send_escalation_notification_task",
    "send_kyc_decision_notification_task",
    "send_password_reset_email_task",
    "send_stepup_challenge_notification_task",
    "send_verification_email_task",
    "send_weekly_security_digest_task",
    "update_behavioural_profile_task",
    "watchlist_refresh_task",
]
