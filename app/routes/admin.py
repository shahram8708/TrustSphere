"""Administrative SOC routes for TrustSphere."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, time, timedelta
import csv
import hashlib
import io
import json
import uuid
import secrets
import string

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, session as flask_session, url_for
from flask_login import current_user
from sqlalchemy import and_, case, func, or_, text
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.forms import (
    AlertActionForm,
    OnboardingDecisionForm,
    PolicyForm,
    ReportForm,
    SessionFilterForm,
    SettingsForm,
    SingleUserCreateForm,
    BulkUserUploadForm,
    UserActionForm,
    UserFilterForm,
)
from app.models import (
    AdminUser,
    Alert,
    AuditLog,
    BehaviouralProfile,
    Device,
    Institution,
    OnboardingApplication,
    PrivilegedSession,
    RiskEvent,
    RiskPolicy,
    SessionRecord,
    User,
)
from app.services import AlertManager, AuditLogger
from app.services.kyc_scoring import KYCOnboardingScorer
from app.services.notification import NotificationService
from app.services.pam_monitor import PrivilegedAccessMonitor
from app.services.report_generator import ComplianceReportGenerator
from app.tasks.report_cache import get_report, list_recent_reports, set_report
from app.utils.decorators import admin_required, super_admin_required, role_required
from app.utils.pagination import get_page_from_request, paginate_query
from app.utils.response import error_response, success_response


admin_bp = Blueprint("admin", __name__)


ALERT_TYPE_OPTIONS = [
    "ato_attempt",
    "insider_anomaly",
    "kyc_fraud",
    "new_device",
    "impossible_travel",
    "bulk_export",
    "suspicious_behaviour",
    "account_recovery_abuse",
    "credential_stuffing",
    "session_hijacking",
]
SEVERITY_OPTIONS = ["low", "medium", "high", "critical"]
STATUS_OPTIONS = ["open", "investigating", "resolved", "dismissed", "false_positive", "all"]
ACTION_COLORS = {
    "allow": "success",
    "monitor": "info",
    "stepup": "warning",
    "block": "danger",
}
ACTION_ICONS = {
    "allow": "bi-check",
    "monitor": "bi-eye",
    "stepup": "bi-shield-exclamation",
    "block": "bi-x-circle",
}


def get_institution_filter():
    """
    Return the institution id that must be applied to scoped queries.
    Super admins can choose one institution or view all institutions.
    Regular admins only see their own institution.
    """
    if getattr(current_user, "is_super_admin", False):
        selected = flask_session.get("admin_institution_filter")
        if selected and selected != "all":
            return selected
        return None
    return getattr(current_user, "institution_id", None) or "__missing_institution__"


def apply_institution_filter(query, model_class, institution_filter_id):
    """Apply tenant scoping to a query when an institution id is required."""
    if institution_filter_id is not None:
        return query.filter(model_class.institution_id == institution_filter_id)
    return query


def _parse_date_arg(name):
    raw_value = (request.args.get(name) or "").strip()
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%d").date()
    except ValueError:
        flash("Date filters must use the YYYY-MM-DD format.", "warning")
        return None


def _int_arg(name, default=0, minimum=0, maximum=100):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _bool_value(raw_value):
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    return None


def _safe_sort_dir():
    return "asc" if (request.args.get("sort_dir") or "").lower() == "asc" else "desc"


def _order_by(column, direction):
    return column.asc() if direction == "asc" else column.desc()


def _status_color(status):
    return {
        "open": "secondary",
        "investigating": "primary",
        "resolved": "success",
        "dismissed": "dark",
        "false_positive": "info",
    }.get(status, "secondary")


def _stepup_color(outcome):
    return {
        "passed": "success",
        "failed": "danger",
        "timeout": "warning",
        "pending": "warning",
        "skipped": "secondary",
        "none": "secondary",
    }.get(outcome, "secondary")


def _risk_color(score):
    score = int(score or 0)
    if score <= 30:
        return "success"
    if score <= 60:
        return "warning"
    return "danger"


def _event_display(event_type):
    return {
        "login": "Login",
        "transaction": "Transaction",
        "data_export": "Data Export",
        "step_up": "Step Up Triggered",
        "page_nav": "Page Navigation",
        "account_recovery": "Account Recovery",
        "behaviour_sample": "Behaviour Sample",
        "config_change": "Configuration Change",
    }.get(event_type, (event_type or "Event").replace("_", " ").title())


def _channel_label(channel):
    return {
        "web_browser": "Web Browser",
        "mobile_app": "Mobile App",
        "api": "API",
        "atm": "ATM",
    }.get(channel, (channel or "Unknown").replace("_", " ").title())


def _mask_email(email):
    if not email:
        return "***"
    local, _, domain = email.partition("@")
    return f"{local[:3]}***@{domain}" if domain else f"{local[:3]}***"


def _mask_ip(ip_address):
    if not ip_address:
        return "***"
    digest = hashlib.sha256(ip_address.encode("utf-8")).hexdigest()
    return f"ip:{digest[:10]}"


def _generate_password(length=12):
    """Generate a secure alphanumeric password for new users."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _country_flag(country_code):
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(0x1F1E6 + ord(code[1]) - ord("A"))


def _analysts_for_scope(inst_filter):
    query = AdminUser.query.filter(
        AdminUser.role.in_(["security_analyst", "compliance_officer", "it_admin", "super_admin"]),
        AdminUser._is_active.is_(True),
    )
    if inst_filter is not None:
        query = query.filter(or_(AdminUser.institution_id == inst_filter, AdminUser.role == "super_admin"))
    elif not getattr(current_user, "is_super_admin", False):
        query = query.filter(AdminUser.institution_id == current_user.institution_id)
    return query.order_by(AdminUser.email.asc()).all()


def _populate_alert_form(form, analysts):
    form.assign_to.choices = [("", "Select Analyst...")] + [
        (analyst.id, f"{analyst.email[:3]}*** {analyst.get_role_display()}")
        for analyst in analysts
    ]
    return form


def _system_health():
    health = {"db": "healthy", "celery": "unknown", "redis": "unknown", "overall": "healthy"}
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        health["db"] = "down"
        health["overall"] = "critical"
        return health

    try:
        from app.tasks.celery_app import celery

        broker = celery.conf.broker_url
        health["celery"] = "healthy" if broker else "unavailable"
    except Exception:
        health["celery"] = "unavailable"

    try:
        import redis

        health["redis"] = "unavailable" if redis is None else "unknown"
    except Exception:
        health["redis"] = "unavailable"

    if any(value not in {"healthy", "unknown"} for key, value in health.items() if key != "overall"):
        health["overall"] = "degraded"
    return health


def _active_policy_status(inst_filter):
    if inst_filter is None:
        return None

    policy = RiskPolicy.query.filter(
        RiskPolicy.institution_id == inst_filter,
        RiskPolicy.is_active.is_(True),
    ).order_by(RiskPolicy.activated_at.desc().nullslast(), RiskPolicy.created_at.desc()).first()
    if not policy:
        return None

    since = datetime.utcnow() - timedelta(days=1)
    alert_hits = {}
    for level in SEVERITY_OPTIONS:
        alert_hits[level] = Alert.query.filter(
            Alert.institution_id == inst_filter,
            Alert.severity == level,
            Alert.created_at >= since,
        ).count()

    return {
        "policy": policy,
        "threshold_low": policy.threshold_low,
        "threshold_medium": policy.threshold_medium,
        "threshold_high": policy.threshold_high,
        "alert_hits": alert_hits,
    }


def _risk_distribution_query(inst_filter, today_start):
    query = db.session.query(SessionRecord.risk_score_peak).filter(SessionRecord.started_at >= today_start)
    query = apply_institution_filter(query, SessionRecord, inst_filter)
    distribution = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for score_value in query.all():
        score = int(score_value[0] or 0)
        if score <= 30:
            distribution["Low"] += 1
        elif score <= 60:
            distribution["Medium"] += 1
        elif score <= 80:
            distribution["High"] += 1
        else:
            distribution["Critical"] += 1
    return distribution


def _common_institution_context(inst_filter):
    institutions = []
    selected_institution = None
    current_filter = flask_session.get("admin_institution_filter", "all")
    if getattr(current_user, "is_super_admin", False):
        institutions = Institution.query.order_by(Institution.name.asc()).all()
        if inst_filter:
            selected_institution = Institution.query.filter_by(id=inst_filter).first()
    return {
        "institutions_list": institutions,
        "current_institution_filter": current_filter,
        "selected_institution": selected_institution,
    }


@admin_bp.get("/")
@admin_bp.get("/dashboard")
@admin_required
def dashboard():
    inst_filter = get_institution_filter()
    now = datetime.utcnow()
    today_start = datetime.combine(date.today(), time.min)
    yesterday_start = today_start - timedelta(days=1)

    active_sessions_query = SessionRecord.query.filter(SessionRecord.ended_at.is_(None))
    active_sessions_query = apply_institution_filter(active_sessions_query, SessionRecord, inst_filter)
    active_sessions_count = active_sessions_query.count()

    yesterday_window = now - timedelta(days=1)
    active_yesterday_query = SessionRecord.query.filter(
        SessionRecord.started_at <= yesterday_window,
        or_(SessionRecord.ended_at.is_(None), SessionRecord.ended_at >= yesterday_window),
    )
    active_yesterday_query = apply_institution_filter(active_yesterday_query, SessionRecord, inst_filter)
    active_yesterday_count = active_yesterday_query.count()
    active_sessions_delta = 0
    if active_yesterday_count:
        active_sessions_delta = round(((active_sessions_count - active_yesterday_count) / active_yesterday_count) * 100)
    elif active_sessions_count:
        active_sessions_delta = 100
    active_sessions_trend = "same"
    if active_sessions_delta > 0:
        active_sessions_trend = "up"
    elif active_sessions_delta < 0:
        active_sessions_trend = "down"

    alert_counts_query = db.session.query(Alert.severity, func.count(Alert.id)).filter(Alert.status == "open")
    alert_counts_query = apply_institution_filter(alert_counts_query, Alert, inst_filter)
    open_alerts_by_severity = {level: 0 for level in SEVERITY_OPTIONS}
    open_alerts_by_severity.update(dict(alert_counts_query.group_by(Alert.severity).all()))
    total_open_alerts = sum(open_alerts_by_severity.values())

    risk_today_query = RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id).filter(
        RiskEvent.evaluated_at >= today_start,
    )
    risk_today_query = apply_institution_filter(risk_today_query, RiskEvent, inst_filter)
    risk_events_today = risk_today_query.count()

    risk_yesterday_query = RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id).filter(
        RiskEvent.evaluated_at >= yesterday_start,
        RiskEvent.evaluated_at < today_start,
    )
    risk_yesterday_query = apply_institution_filter(risk_yesterday_query, RiskEvent, inst_filter)
    risk_events_yesterday = risk_yesterday_query.count()
    risk_events_delta = risk_events_today - risk_events_yesterday
    risk_events_trend = "same"
    if risk_events_delta > 0:
        risk_events_trend = "up"
    elif risk_events_delta < 0:
        risk_events_trend = "down"

    top_alerts_query = Alert.query.filter(Alert.status == "open").options(
        joinedload(Alert.user),
        joinedload(Alert.session),
    )
    top_alerts_query = apply_institution_filter(top_alerts_query, Alert, inst_filter)
    top_alerts = (
        top_alerts_query.order_by(Alert.ml_priority_score.desc(), Alert.created_at.desc())
        .limit(10)
        .all()
    )

    session_risk_distribution = _risk_distribution_query(inst_filter, today_start)
    session_risk_total = sum(session_risk_distribution.values())

    recent_events_query = RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id).options(
        joinedload(RiskEvent.session).joinedload(SessionRecord.user),
    )
    recent_events_query = apply_institution_filter(recent_events_query, RiskEvent, inst_filter)
    recent_events = recent_events_query.order_by(RiskEvent.evaluated_at.desc()).limit(20).all()

    context = {
        "active_sessions_count": active_sessions_count,
        "active_sessions_delta": abs(active_sessions_delta),
        "active_sessions_trend": active_sessions_trend,
        "open_alerts_by_severity": open_alerts_by_severity,
        "total_open_alerts": total_open_alerts,
        "risk_events_today": risk_events_today,
        "risk_events_yesterday": risk_events_yesterday,
        "risk_events_delta": abs(risk_events_delta),
        "risk_events_trend": risk_events_trend,
        "system_health": _system_health(),
        "top_alerts": top_alerts,
        "session_risk_distribution": session_risk_distribution,
        "session_risk_total": session_risk_total,
        "recent_events": recent_events,
        "policy_status": _active_policy_status(inst_filter),
        "event_display": _event_display,
        "action_colors": ACTION_COLORS,
        "action_icons": ACTION_ICONS,
        "channel_label": _channel_label,
        "status_color": _status_color,
        "risk_color": _risk_color,
    }
    context.update(_common_institution_context(inst_filter))
    return render_template("admin/dashboard.html", **context)


@admin_bp.get("/alerts")
@admin_required
def alerts():
    inst_filter = get_institution_filter()
    selected_status = (request.args.get("status") or "open").strip()
    user_filter = (request.args.get("user_id") or "").strip()
    severity_values = []
    raw_severity_values = request.args.getlist("severity")
    if raw_severity_values:
        for raw_value in raw_severity_values:
            severity_values.extend([item for item in raw_value.split(",") if item in SEVERITY_OPTIONS])
    severity_values = list(dict.fromkeys(severity_values))
    selected_type = (request.args.get("alert_type") or "").strip()
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")
    sort_by = (request.args.get("sort_by") or "ml_priority_score").strip()
    sort_dir = _safe_sort_dir()

    query = Alert.query.options(joinedload(Alert.user), joinedload(Alert.assigned_analyst))
    query = apply_institution_filter(query, Alert, inst_filter)
    if severity_values:
        query = query.filter(Alert.severity.in_(severity_values))
    if selected_type in ALERT_TYPE_OPTIONS:
        query = query.filter(Alert.alert_type == selected_type)
    if user_filter:
        query = query.filter(Alert.user_id == user_filter)
    if selected_status and selected_status != "all" and selected_status in STATUS_OPTIONS:
        query = query.filter(Alert.status == selected_status)
    if date_from:
        query = query.filter(Alert.created_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(Alert.created_at < datetime.combine(date_to + timedelta(days=1), time.min))

    sort_column = Alert.ml_priority_score
    if sort_by == "created_at":
        sort_column = Alert.created_at
    query = query.order_by(_order_by(sort_column, sort_dir), Alert.created_at.desc())
    pagination = paginate_query(query, get_page_from_request(), per_page=25)

    count_query = db.session.query(Alert.status, func.count(Alert.id))
    count_query = apply_institution_filter(count_query, Alert, inst_filter)
    alert_counts_by_status = {"open": 0, "investigating": 0, "resolved": 0}
    alert_counts_by_status.update(dict(count_query.group_by(Alert.status).all()))

    analysts = _analysts_for_scope(inst_filter)
    action_form = _populate_alert_form(AlertActionForm(), analysts)

    return render_template(
        "admin/alerts.html",
        pagination=pagination,
        alerts=pagination.items,
        severity_options=SEVERITY_OPTIONS,
        alert_type_options=ALERT_TYPE_OPTIONS,
        status_options=STATUS_OPTIONS,
        selected_severities=severity_values,
        selected_severity=",".join(severity_values),
        selected_type=selected_type,
        selected_status=selected_status,
        user_filter=user_filter,
        selected_date_from=date_from.isoformat() if date_from else "",
        selected_date_to=date_to.isoformat() if date_to else "",
        sort_by=sort_by,
        sort_dir=sort_dir,
        alert_counts_by_status=alert_counts_by_status,
        action_form=action_form,
        analysts=analysts,
        status_color=_status_color,
        mask_email=_mask_email,
    )


@admin_bp.get("/alerts/<alert_id>")
@admin_required
def alert_detail(alert_id):
    inst_filter = get_institution_filter()
    alert_query = Alert.query.filter(Alert.id == alert_id).options(
        joinedload(Alert.user),
        joinedload(Alert.session),
        joinedload(Alert.assigned_analyst),
    )
    alert_query = apply_institution_filter(alert_query, Alert, inst_filter)
    alert = alert_query.first_or_404()

    session_record = None
    if alert.session_id:
        session_query = SessionRecord.query.filter(SessionRecord.id == alert.session_id).options(
            joinedload(SessionRecord.device),
            joinedload(SessionRecord.user),
        )
        session_query = apply_institution_filter(session_query, SessionRecord, inst_filter)
        session_record = session_query.first()

    risk_events = []
    if session_record:
        risk_event_query = RiskEvent.query.filter(RiskEvent.session_id == session_record.id)
        risk_event_query = apply_institution_filter(risk_event_query, RiskEvent, inst_filter)
        risk_events = risk_event_query.order_by(RiskEvent.evaluated_at.asc()).all()

    timeline_data = [
        {
            "label": _event_display(event.event_type),
            "x": index,
            "risk": event.risk_score_after,
            "action": event.cre_response_action,
            "timestamp": event.evaluated_at.isoformat() if event.evaluated_at else None,
        }
        for index, event in enumerate(risk_events)
    ]

    highest_event = max(risk_events, key=lambda event: event.risk_score_after or 0, default=None)
    factor_data = []
    if highest_event:
        factor_data = [
            {"factor": key.replace("_", " ").title(), "value": int(value or 0)}
            for key, value in highest_event.get_contributing_factors_dict().items()
        ]
        factor_data.sort(key=lambda item: item["value"], reverse=True)

    user_query = User.query.filter(User.id == alert.user_id)
    user_query = apply_institution_filter(user_query, User, inst_filter)
    user = user_query.first_or_404()

    prior_alerts_query = Alert.query.filter(Alert.user_id == alert.user_id)
    prior_alerts_query = apply_institution_filter(prior_alerts_query, Alert, inst_filter)
    prior_alerts_count = prior_alerts_query.count()

    device_count_query = Device.query.filter(Device.user_id == alert.user_id, Device.is_removed.is_(False))
    device_count_query = apply_institution_filter(device_count_query, Device, inst_filter)
    device_count = device_count_query.count()

    last_session_query = SessionRecord.query.filter(SessionRecord.user_id == alert.user_id)
    last_session_query = apply_institution_filter(last_session_query, SessionRecord, inst_filter)
    last_session = last_session_query.order_by(SessionRecord.started_at.desc()).first()
    typical_location = "Unknown"
    if last_session and last_session.ip_city:
        typical_location = f"{last_session.ip_city}, {last_session.ip_country or 'Unknown'}"

    audit_query = AuditLog.query.filter(AuditLog.target_type == "alert", AuditLog.target_id == alert_id)
    audit_query = apply_institution_filter(audit_query, AuditLog, inst_filter)
    audit_history = audit_query.order_by(AuditLog.created_at.desc()).limit(10).all()

    analysts = _analysts_for_scope(inst_filter)
    action_form = _populate_alert_form(AlertActionForm(), analysts)
    account_tenure_days = (datetime.utcnow() - user.created_at).days if user.created_at else 0

    return render_template(
        "admin/alert_detail.html",
        alert=alert,
        session_record=session_record,
        risk_events=risk_events,
        timeline_json=json.dumps(timeline_data),
        factor_breakdown_json=json.dumps(factor_data),
        factor_breakdown=factor_data,
        user=user,
        user_context={
            "prior_alerts_count": prior_alerts_count,
            "device_count": device_count,
            "typical_location": typical_location,
            "account_tenure_days": account_tenure_days,
        },
        audit_history=audit_history,
        action_form=action_form,
        analysts=analysts,
        mask_email=_mask_email,
        mask_ip=_mask_ip,
        status_color=_status_color,
        action_colors=ACTION_COLORS,
        event_display=_event_display,
        risk_color=_risk_color,
    )


@admin_bp.route("/users/new", methods=["GET", "POST"])
@admin_required
@role_required("it_admin")
def users_create():
    """Create a single user; only IT admins or super admins may access."""
    inst_filter = get_institution_filter()
    form = SingleUserCreateForm()

    # Populate institution choices for super admins, otherwise lock to current institution
    if getattr(current_user, "is_super_admin", False):
        institutions = Institution.query.order_by(Institution.name.asc()).all()
        form.institution_id.choices = [("", "Select Institution...")] + [(i.id, i.name) for i in institutions]
    else:
        form.institution_id.choices = [(current_user.institution_id, getattr(current_user, "institution", None) and current_user.institution.name)]
        form.institution_id.data = current_user.institution_id

    if form.validate_on_submit():
        email = (form.email.data or "").strip().lower()
        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("admin.users_create"))

        if getattr(current_user, "is_super_admin", False):
            institution_id = form.institution_id.data or None
            if not institution_id:
                flash("Select an institution for the new user.", "error")
                return redirect(url_for("admin.users_create"))
        else:
            institution_id = current_user.institution_id

        exists = User.query.filter(User.email == email, User.institution_id == institution_id).first()
        if exists:
            flash("A user with that email already exists in the selected institution.", "error")
            return redirect(url_for("admin.users_create"))

        user = User(
            email=email,
            display_name=(form.display_name.data or "").strip() or None,
            external_user_id=(form.external_user_id.data or "").strip() or None,
            phone=(form.phone.data or "").strip() or None,
            user_type=form.user_type.data,
            institution_id=institution_id,
        )

        password = _generate_password(12)
        user.set_password(password)

        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.create", "user", None, {"email": email, "user_type": user.user_type}, commit=False)
        try:
            db.session.commit()
            # Queue credentials email via Celery task
            try:
                from app.tasks.email_tasks import send_account_created_email_task

                send_account_created_email_task.delay(user.id, password)
            except Exception:
                # Fall back to synchronous send if task import fails
                subject = "Your new TrustSphere account"
                body = NotificationService.build_email_html(
                    title="Your TrustSphere account has been created",
                    body_paragraphs=[
                        f"An account was created for you as a {user.user_type}.",
                        f"Email: {user.email}",
                        f"Temporary password: {password}",
                    ],
                    footer_note="Please change your password after first login.",
                )
                NotificationService.send_email(user.email, subject, body)

            flash("User created; credentials will be emailed.", "success")
            return redirect(url_for("admin.user_detail", user_id=user.id))
        except Exception as exc:
            db.session.rollback()
            flash("Failed to create user.", "error")
            return redirect(url_for("admin.users"))

    return render_template("admin/users_create.html", form=form)


@admin_bp.route("/users/bulk", methods=["GET", "POST"])
@admin_required
@role_required("it_admin")
def users_bulk_create():
    """Upload a CSV to create multiple users in bulk. CSV should include: email,display_name,external_user_id,phone,user_type[,institution_id]"""
    form = BulkUserUploadForm()
    if form.validate_on_submit():
        uploaded = form.csv_file.data
        data = uploaded.read()
        try:
            text = data.decode("utf-8")
        except Exception:
            try:
                text = data.decode("latin-1")
            except Exception:
                flash("Uploaded file must be a UTF-8 CSV.", "error")
                return redirect(url_for("admin.users_bulk_create"))

        reader = csv.DictReader(io.StringIO(text))
        created = 0
        failures = []
        created_users = []
        for idx, row in enumerate(reader, start=1):
            email = (row.get("email") or "").strip().lower()
            if not email:
                failures.append((idx, "missing email"))
                continue

            # Determine institution for row: prefer CSV value for super admins, otherwise use current user's institution
            institution_id = current_user.institution_id
            if getattr(current_user, "is_super_admin", False):
                inst_val = (row.get("institution_id") or "").strip()
                if inst_val:
                    institution_id = inst_val

            user_type = (row.get("user_type") or form.default_user_type.data or "customer").strip().lower()
            if user_type not in {"customer", "employee"}:
                user_type = "customer"

            exists = User.query.filter(User.email == email, User.institution_id == institution_id).first()
            if exists:
                failures.append((idx, "already exists"))
                continue

            user = User(
                email=email,
                display_name=(row.get("display_name") or "").strip() or None,
                external_user_id=(row.get("external_user_id") or "").strip() or None,
                phone=(row.get("phone") or "").strip() or None,
                user_type=user_type,
                institution_id=institution_id,
            )
            password = _generate_password(12)
            user.set_password(password)
            db.session.add(user)
            created += 1
            created_users.append((user, password))

        # Commit created users
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            flash("Failed to create users; database error.", "error")
            return redirect(url_for("admin.users"))

        # Queue email send tasks for created users
        queued = 0
        for user, password in created_users:
            try:
                from app.tasks.email_tasks import send_account_created_email_task

                send_account_created_email_task.delay(user.id, password)
                queued += 1
            except Exception:
                # If task unavailable, attempt best-effort synchronous send
                try:
                    subject = "Your new TrustSphere account"
                    body = NotificationService.build_email_html(
                        title="Your TrustSphere account has been created",
                        body_paragraphs=[
                            f"An account was created for you as a {user.user_type}.",
                            f"Email: {user.email}",
                            f"Temporary password: {password}",
                        ],
                        footer_note="Please change your password after first login.",
                    )
                    NotificationService.send_email(user.email, subject, body)
                    queued += 1
                except Exception:
                    continue

        AuditLogger.log_from_request(current_user, "user.bulk_create", "user", None, {"created": created, "failed": len(failures)}, commit=False)
        flash(f"Created {created} users; queued {queued} emails. Failures: {len(failures)}.", "success" if created else "warning")
        return redirect(url_for("admin.users"))

    return render_template("admin/users_bulk.html", form=form)


@admin_bp.post("/alerts/<alert_id>/action")
@admin_required
def alert_action(alert_id):
    inst_filter = get_institution_filter()
    alert_query = Alert.query.filter(Alert.id == alert_id)
    alert_query = apply_institution_filter(alert_query, Alert, inst_filter)
    alert = alert_query.first_or_404()

    form = _populate_alert_form(AlertActionForm(), _analysts_for_scope(inst_filter))
    if not form.validate_on_submit():
        flash("Alert action could not be verified.", "error")
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")
        return redirect(url_for("admin.alert_detail", alert_id=alert_id))

    action = form.action.data
    notes = form.notes.data

    if action == "notes":
        alert.analyst_notes = notes
        db.session.add(alert)
        AuditLogger.log_from_request(
            current_user,
            "alert.notes",
            "alert",
            alert.id,
            {"notes": notes},
            commit=False,
        )
        db.session.commit()
        flash("Investigation notes saved.", "success")
        return redirect(url_for("admin.alert_detail", alert_id=alert_id))

    if action == "dismiss":
        success, message = AlertManager.dismiss_alert(alert_id, current_user, notes)
        flash("Alert dismissed." if success else message, "success" if success else "error")
        return redirect(url_for("admin.alerts") if success else url_for("admin.alert_detail", alert_id=alert_id))

    if action == "escalate":
        success, message = AlertManager.escalate_alert(alert_id, current_user, notes)
        if success:
            from app.tasks.alert_notify import escalate_alert_task

            escalate_alert_task.delay(alert_id, str(current_user.id))
        flash("Alert escalated to senior analyst." if success else message, "success" if success else "error")
        return redirect(url_for("admin.alert_detail", alert_id=alert_id))

    if action == "resolve":
        success, message = AlertManager.resolve_alert(alert_id, current_user, notes)
        flash("Alert resolved." if success else message, "success" if success else "error")
        return redirect(url_for("admin.alerts") if success else url_for("admin.alert_detail", alert_id=alert_id))

    if action == "false_positive":
        success, message = AlertManager.mark_false_positive(alert_id, current_user)
        flash(
            "Alert marked as false positive. ML model updated." if success else message,
            "success" if success else "error",
        )
        return redirect(url_for("admin.alerts") if success else url_for("admin.alert_detail", alert_id=alert_id))

    if action == "block_user":
        user_query = User.query.filter(User.id == alert.user_id)
        user_query = apply_institution_filter(user_query, User, inst_filter)
        user = user_query.first_or_404()
        user.is_suspended = True
        alert.status = "investigating"
        alert.analyst_notes = notes
        db.session.add(user)
        db.session.add(alert)
        AuditLogger.log_from_request(
            current_user,
            "user.suspend_from_alert",
            "user",
            alert.user_id,
            {"alert_id": alert_id, "reason": notes},
            commit=False,
        )
        db.session.commit()
        from app.tasks.alert_notify import block_user_session_task

        block_user_session_task.delay(
            alert.user_id,
            str(alert.session_id) if alert.session_id else None,
            f"Blocked by analyst {current_user.email[:10]}***",
        )
        flash("User account suspended and alert actioned.", "success")
        return redirect(url_for("admin.alert_detail", alert_id=alert_id))

    if action == "assign":
        if not form.assign_to.data:
            flash("Select an analyst before assigning the alert.", "error")
            return redirect(url_for("admin.alert_detail", alert_id=alert_id))
        allowed_ids = {analyst.id for analyst in _analysts_for_scope(inst_filter)}
        if form.assign_to.data not in allowed_ids:
            flash("Selected analyst is not available for this institution.", "error")
            return redirect(url_for("admin.alert_detail", alert_id=alert_id))
        alert.assigned_to = form.assign_to.data
        alert.status = "investigating"
        alert.analyst_notes = notes
        db.session.add(alert)
        AuditLogger.log_from_request(
            current_user,
            "alert.assign",
            "alert",
            alert.id,
            {"assigned_to": alert.assigned_to, "notes": notes},
            commit=False,
        )
        db.session.commit()
        flash("Alert assigned to analyst.", "success")
        return redirect(url_for("admin.alert_detail", alert_id=alert_id))

    flash("Invalid alert action.", "error")
    return redirect(url_for("admin.alert_detail", alert_id=alert_id))


@admin_bp.post("/alerts/bulk-action")
@admin_required
def alert_bulk_action():
    inst_filter = get_institution_filter()
    alert_ids = request.form.getlist("alert_ids")
    action = request.form.get("bulk_action")
    if action != "dismiss" or not alert_ids:
        flash("No bulk action was applied.", "warning")
        return redirect(url_for("admin.alerts"))

    query = Alert.query.filter(Alert.id.in_(alert_ids), Alert.status == "open")
    query = apply_institution_filter(query, Alert, inst_filter)
    alerts_to_update = query.all()
    for alert in alerts_to_update:
        alert.status = "dismissed"
        alert.resolved_at = datetime.utcnow()
        alert.analyst_notes = "Bulk dismissed from alert queue"
        db.session.add(alert)
    AuditLogger.log_from_request(
        current_user,
        "alert.bulk_dismiss",
        "alert",
        None,
        {"alert_ids": [alert.id for alert in alerts_to_update], "count": len(alerts_to_update)},
        commit=False,
    )
    db.session.commit()
    flash(f"{len(alerts_to_update)} alerts dismissed.", "success")
    return redirect(url_for("admin.alerts"))


@admin_bp.get("/users")
@admin_required
def users():
    inst_filter = get_institution_filter()
    search = (request.args.get("search") or "").strip()
    user_type = (request.args.get("user_type") or "").strip()
    risk_min = _int_arg("risk_min", 0)
    risk_max = _int_arg("risk_max", 100)
    if risk_min > risk_max:
        risk_min, risk_max = risk_max, risk_min
    suspended_filter = _bool_value((request.args.get("is_suspended") or "").strip())
    sort_by = (request.args.get("sort_by") or "risk_score_current").strip()
    sort_dir = _safe_sort_dir()

    query = User.query.options(joinedload(User.institution))
    query = apply_institution_filter(query, User, inst_filter)
    if user_type in {"customer", "employee"}:
        query = query.filter(User.user_type == user_type)
    query = query.filter(User.risk_score_current >= risk_min, User.risk_score_current <= risk_max)
    if suspended_filter is not None:
        query = query.filter(User.is_suspended.is_(suspended_filter))
    if search:
        query = query.filter(
            or_(
                User.external_user_id.ilike(f"%{search}%"),
                User.display_name.ilike(f"%{search}%"),
                User.id.ilike(f"{search.rstrip('*')}%"),
            )
        )

    sort_column = User.risk_score_current
    if sort_by == "last_active_at":
        sort_column = User.last_active_at
    elif sort_by == "created_at":
        sort_column = User.created_at
    query = query.order_by(_order_by(sort_column, sort_dir), User.created_at.desc())
    pagination = paginate_query(query, get_page_from_request(), per_page=25)

    user_ids = [user.id for user in pagination.items]
    alert_counts = {}
    device_counts = {}
    if user_ids:
        alert_count_query = db.session.query(Alert.user_id, func.count(Alert.id)).filter(
            Alert.user_id.in_(user_ids),
            Alert.status == "open",
        )
        alert_count_query = apply_institution_filter(alert_count_query, Alert, inst_filter)
        alert_counts = dict(alert_count_query.group_by(Alert.user_id).all())

        device_count_query = db.session.query(Device.user_id, func.count(Device.id)).filter(
            Device.user_id.in_(user_ids),
            Device.is_removed.is_(False),
        )
        device_count_query = apply_institution_filter(device_count_query, Device, inst_filter)
        device_counts = dict(device_count_query.group_by(Device.user_id).all())

    stats_query = User.query
    stats_query = apply_institution_filter(stats_query, User, inst_filter)
    today_start = datetime.combine(date.today(), time.min)
    user_stats = {
        "total": stats_query.count(),
        "high_risk": stats_query.filter(User.risk_score_current > 60).count(),
        "suspended": stats_query.filter(User.is_suspended.is_(True)).count(),
        "active_today": stats_query.filter(User.last_active_at >= today_start).count(),
    }

    filter_form = UserFilterForm(data={
        "search": search,
        "user_type": user_type,
        "risk_min": risk_min,
        "risk_max": risk_max,
        "is_suspended": request.args.get("is_suspended", ""),
    })
    action_form = UserActionForm()

    return render_template(
        "admin/users.html",
        pagination=pagination,
        users=pagination.items,
        alert_counts=alert_counts,
        device_counts=device_counts,
        filter_form=filter_form,
        action_form=action_form,
        user_stats=user_stats,
        search=search,
        user_type=user_type,
        risk_min=risk_min,
        risk_max=risk_max,
        is_suspended=request.args.get("is_suspended", ""),
        sort_by=sort_by,
        sort_dir=sort_dir,
        risk_color=_risk_color,
    )


@admin_bp.get("/users/<user_id>")
@admin_required
def user_detail(user_id):
    inst_filter = get_institution_filter()
    user_query = User.query.filter(User.id == user_id).options(joinedload(User.institution))
    user_query = apply_institution_filter(user_query, User, inst_filter)
    user = user_query.first_or_404()

    trust_order = case(
        (Device.trust_level == "suspicious", 0),
        (Device.trust_level == "new", 1),
        (Device.trust_level == "known", 2),
        (Device.trust_level == "trusted", 3),
        else_=4,
    )
    devices_query = Device.query.filter(Device.user_id == user.id, Device.is_removed.is_(False))
    devices_query = apply_institution_filter(devices_query, Device, inst_filter)
    devices = devices_query.order_by(trust_order, Device.last_seen_at.desc()).all()

    sessions_query = SessionRecord.query.filter(SessionRecord.user_id == user.id).options(joinedload(SessionRecord.device))
    sessions_query = apply_institution_filter(sessions_query, SessionRecord, inst_filter)
    sessions = sessions_query.order_by(SessionRecord.started_at.desc()).limit(10).all()

    alerts_query = Alert.query.filter(Alert.user_id == user.id)
    alerts_query = apply_institution_filter(alerts_query, Alert, inst_filter)
    alerts = alerts_query.order_by(Alert.created_at.desc()).limit(10).all()
    open_alerts_count = alerts_query.filter(Alert.status == "open").count()

    risk_history_query = RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id).filter(
        SessionRecord.user_id == user.id,
    )
    risk_history_query = apply_institution_filter(risk_history_query, RiskEvent, inst_filter)
    risk_history_events = (
        risk_history_query.order_by(RiskEvent.evaluated_at.desc())
        .limit(30)
        .all()
    )
    risk_history_events.reverse()
    risk_history_data = [
        {
            "x": event.evaluated_at.isoformat() if event.evaluated_at else None,
            "y": event.risk_score_after,
            "cre_response_action": event.cre_response_action,
        }
        for event in risk_history_events
    ]

    profile_query = BehaviouralProfile.query.filter(
        BehaviouralProfile.user_id == user.id,
        BehaviouralProfile.is_active.is_(True),
    )
    behavioural_profile = profile_query.first()
    if behavioural_profile and hasattr(behavioural_profile, "get_profile_summary"):
        behavioural_summary = behavioural_profile.get_profile_summary()
    else:
        behavioural_summary = {
            "has_profile": behavioural_profile is not None,
            "confidence_level": getattr(behavioural_profile, "confidence_level", None),
            "training_sessions": getattr(behavioural_profile, "training_sessions_count", 0) or 0,
            "profile_version": getattr(behavioural_profile, "profile_version", None),
            "updated_at": getattr(behavioural_profile, "updated_at", None),
        }

    privileged_sessions = None
    if user.user_type == "employee":
        privileged_query = PrivilegedSession.query.filter(PrivilegedSession.employee_user_id == user.id)
        privileged_query = apply_institution_filter(privileged_query, PrivilegedSession, inst_filter)
        privileged_sessions = privileged_query.order_by(PrivilegedSession.started_at.desc()).limit(5).all()

    account_tenure_days = (datetime.utcnow() - user.created_at).days if user.created_at else 0

    return render_template(
        "admin/user_detail.html",
        user=user,
        devices=devices,
        sessions=sessions,
        alerts=alerts,
        open_alerts_count=open_alerts_count,
        risk_history_json=json.dumps(risk_history_data),
        behavioural_summary=behavioural_summary,
        privileged_sessions=privileged_sessions,
        account_tenure_days=account_tenure_days,
        action_form=UserActionForm(),
        status_color=_status_color,
        risk_color=_risk_color,
        channel_label=_channel_label,
        stepup_color=_stepup_color,
    )


@admin_bp.post("/users/<user_id>/action")
@admin_required
def user_action(user_id):
    inst_filter = get_institution_filter()
    user_query = User.query.filter(User.id == user_id)
    user_query = apply_institution_filter(user_query, User, inst_filter)
    user = user_query.first_or_404()
    form = UserActionForm()
    if not form.validate_on_submit():
        flash("User action could not be verified.", "error")
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    action = form.action.data
    reason = form.reason.data
    details = {"reason": reason}

    if action == "suspend":
        if user.is_suspended:
            flash("User is already suspended.", "info")
            return redirect(url_for("admin.user_detail", user_id=user_id))
        user.is_suspended = True
        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.suspend", "user", user.id, details, commit=False)
        db.session.commit()
        flash("User account suspended.", "success")

    elif action == "unsuspend":
        user.is_suspended = False
        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.unsuspend", "user", user.id, details, commit=False)
        db.session.commit()
        flash("User account unsuspended.", "success")

    elif action == "force_stepup":
        user.risk_score_current = 75
        user.risk_score_updated_at = datetime.utcnow()
        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.force_stepup", "user", user.id, details, commit=False)
        db.session.commit()
        flash("Step up verification will be required on next user action.", "success")

    elif action == "reset_behavioural_profile":
        profile = BehaviouralProfile.query.filter(
            BehaviouralProfile.user_id == user.id,
            BehaviouralProfile.is_active.is_(True),
        ).first()
        if profile:
            profile.training_sessions_count = 0
            profile.confidence_level = "low"
            profile.typing_rhythm_vector = None
            profile.mouse_pattern_vector = None
            profile.touch_pattern_vector = None
            profile.interaction_timing_vector = None
            profile.updated_at = datetime.utcnow()
            db.session.add(profile)
        AuditLogger.log_from_request(current_user, "user.reset_profile", "user", user.id, details, commit=False)
        db.session.commit()
        flash("Behavioural profile reset. User will need to re establish baseline.", "success")

    elif action == "flag_high_risk":
        user.risk_score_current = 90
        user.risk_score_updated_at = datetime.utcnow()
        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.flag_high_risk", "user", user.id, details, commit=False)
        db.session.commit()
        AlertManager.create_alert(
            institution_id=user.institution_id,
            user_id=user.id,
            alert_type="suspicious_behaviour",
            severity="high",
            title="User manually flagged as high risk",
            description=reason or "An administrator flagged this user for high risk review.",
            auto_action="manual_flag",
        )
        flash("User flagged as high risk. Risk score set to 90.", "success")

    elif action == "clear_risk_score":
        user.risk_score_current = 20
        user.risk_score_updated_at = datetime.utcnow()
        db.session.add(user)
        AuditLogger.log_from_request(current_user, "user.clear_risk_score", "user", user.id, details, commit=False)
        db.session.commit()
        flash("Risk score cleared to low 20.", "success")

    return redirect(url_for("admin.user_detail", user_id=user_id))


@admin_bp.get("/sessions")
@admin_required
def sessions():
    inst_filter = get_institution_filter()
    channel = (request.args.get("channel") or "").strip()
    user_filter = (request.args.get("user_id") or "").strip()
    risk_min = _int_arg("risk_min", 0)
    risk_max = _int_arg("risk_max", 100)
    if risk_min > risk_max:
        risk_min, risk_max = risk_max, risk_min
    flagged_filter = _bool_value((request.args.get("is_flagged") or "").strip())
    active_filter = _bool_value((request.args.get("is_active") or "").strip())
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")
    sort_by = (request.args.get("sort_by") or "started_at").strip()
    sort_dir = _safe_sort_dir()

    query = SessionRecord.query.options(
        joinedload(SessionRecord.user),
        joinedload(SessionRecord.device),
        joinedload(SessionRecord.alerts),
    )
    query = apply_institution_filter(query, SessionRecord, inst_filter)
    if channel in {"web_browser", "mobile_app", "api", "atm"}:
        query = query.filter(SessionRecord.channel == channel)
    if user_filter:
        query = query.filter(SessionRecord.user_id == user_filter)
    query = query.filter(SessionRecord.risk_score_peak >= risk_min, SessionRecord.risk_score_peak <= risk_max)
    if flagged_filter is not None:
        query = query.filter(SessionRecord.is_flagged.is_(flagged_filter))
    if active_filter is True:
        query = query.filter(SessionRecord.ended_at.is_(None))
    elif active_filter is False:
        query = query.filter(SessionRecord.ended_at.is_not(None))
    if date_from:
        query = query.filter(SessionRecord.started_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(SessionRecord.started_at < datetime.combine(date_to + timedelta(days=1), time.min))

    sort_column = SessionRecord.started_at
    if sort_by == "risk_score_peak":
        sort_column = SessionRecord.risk_score_peak
    query = query.order_by(_order_by(sort_column, sort_dir), SessionRecord.started_at.desc())
    pagination = paginate_query(query, get_page_from_request(), per_page=25)

    today_start = datetime.combine(date.today(), time.min)
    active_count_query = SessionRecord.query.filter(SessionRecord.ended_at.is_(None))
    active_count_query = apply_institution_filter(active_count_query, SessionRecord, inst_filter)
    high_risk_query = SessionRecord.query.filter(
        SessionRecord.risk_score_peak > 60,
        SessionRecord.started_at >= today_start,
    )
    high_risk_query = apply_institution_filter(high_risk_query, SessionRecord, inst_filter)
    flagged_today_query = SessionRecord.query.filter(
        SessionRecord.is_flagged.is_(True),
        SessionRecord.started_at >= today_start,
    )
    flagged_today_query = apply_institution_filter(flagged_today_query, SessionRecord, inst_filter)

    session_rows = []
    for item in pagination.items:
        open_alert = next((alert for alert in item.alerts if alert.status == "open"), None)
        session_rows.append(
            {
                "record": item,
                "flag_emoji": _country_flag(item.ip_country),
                "location": f"{item.ip_city or 'Unknown'}, {item.ip_country or 'Unknown'}",
                "open_alert": open_alert,
            }
        )

    filter_form = SessionFilterForm(data={
        "channel": channel,
        "risk_min": risk_min,
        "risk_max": risk_max,
        "is_flagged": request.args.get("is_flagged", ""),
        "is_active": request.args.get("is_active", ""),
        "date_from": date_from,
        "date_to": date_to,
    })

    return render_template(
        "admin/sessions.html",
        pagination=pagination,
        sessions=pagination.items,
        session_rows=session_rows,
        active_sessions_count=active_count_query.count(),
        high_risk_count=high_risk_query.count(),
        flagged_sessions_count=flagged_today_query.count(),
        filter_form=filter_form,
        channel=channel,
        risk_min=risk_min,
        risk_max=risk_max,
        is_flagged=request.args.get("is_flagged", ""),
        is_active=request.args.get("is_active", ""),
        date_from=date_from.isoformat() if date_from else "",
        date_to=date_to.isoformat() if date_to else "",
        sort_by=sort_by,
        sort_dir=sort_dir,
        user_filter=user_filter,
        channel_label=_channel_label,
        risk_color=_risk_color,
        stepup_color=_stepup_color,
        mask_ip=_mask_ip,
    )


@admin_bp.post("/sessions/<session_id>/flag")
@admin_required
def session_flag(session_id):
    inst_filter = get_institution_filter()
    query = SessionRecord.query.filter(SessionRecord.id == session_id)
    query = apply_institution_filter(query, SessionRecord, inst_filter)
    session_record = query.first_or_404()
    session_record.is_flagged = not bool(session_record.is_flagged)
    db.session.add(session_record)
    AuditLogger.log_from_request(
        current_user,
        "session.flag_toggle",
        "session",
        session_record.id,
        {"is_flagged": session_record.is_flagged},
        commit=False,
    )
    db.session.commit()
    flash("Session flag updated.", "success")
    return redirect(request.referrer or url_for("admin.sessions"))


@admin_bp.post("/set-institution-filter")
@super_admin_required
def set_institution_filter():
    data = request.get_json(silent=True) or {}
    institution_id = request.form.get("institution_id", data.get("institution_id", "")).strip()
    if not institution_id:
        institution_id = "all"
    if institution_id != "all" and not Institution.query.filter_by(id=institution_id).first():
        flash("Institution filter could not be applied.", "error")
        return redirect(request.referrer or url_for("admin.dashboard"))
    flask_session["admin_institution_filter"] = institution_id
    AuditLogger.log_from_request(
        current_user,
        "admin.institution_filter",
        "institution",
        None if institution_id == "all" else institution_id,
        {"institution_id": institution_id},
    )
    if request.is_json:
        return jsonify({"status": "success", "institution_id": institution_id})
    return redirect(request.referrer or url_for("admin.dashboard"))


@admin_bp.get("/onboarding")
@admin_required
def onboarding():
    inst_filter = get_institution_filter()
    decision = (request.args.get("decision") or "all").strip()
    if decision not in {"all", "pending", "manual_review", "approve", "reject"}:
        decision = "all"
    risk_min = _int_arg("risk_min", 0)
    risk_max = _int_arg("risk_max", 100)
    if risk_min > risk_max:
        risk_min, risk_max = risk_max, risk_min
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")

    query = OnboardingApplication.query.options(joinedload(OnboardingApplication.reviewer))
    query = apply_institution_filter(query, OnboardingApplication, inst_filter)
    if decision != "all":
        query = query.filter(OnboardingApplication.decision == decision)
    query = query.filter(
        OnboardingApplication.composite_risk_score >= risk_min,
        OnboardingApplication.composite_risk_score <= risk_max,
    )
    if date_from:
        query = query.filter(OnboardingApplication.submitted_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(OnboardingApplication.submitted_at < datetime.combine(date_to + timedelta(days=1), time.min))
    if decision in {"pending", "manual_review"}:
        query = query.order_by(OnboardingApplication.submitted_at.asc())
    else:
        query = query.order_by(OnboardingApplication.submitted_at.desc())

    pagination = paginate_query(query, get_page_from_request(), per_page=20)

    status_counts = {}
    for status in ["pending", "manual_review", "approve", "reject"]:
        status_query = OnboardingApplication.query.filter(OnboardingApplication.decision == status)
        status_query = apply_institution_filter(status_query, OnboardingApplication, inst_filter)
        status_counts[status] = status_query.count()
    total_query = OnboardingApplication.query
    total_query = apply_institution_filter(total_query, OnboardingApplication, inst_filter)
    status_counts["total"] = total_query.count()

    avg_query = db.session.query(func.avg(OnboardingApplication.composite_risk_score))
    avg_query = apply_institution_filter(avg_query, OnboardingApplication, inst_filter)
    avg_risk_score = avg_query.scalar()

    return render_template(
        "admin/onboarding.html",
        pagination=pagination,
        applications=pagination.items,
        status_counts=status_counts,
        avg_risk_score=float(avg_risk_score) if avg_risk_score is not None else None,
        selected_decision=decision,
        risk_min=risk_min,
        risk_max=risk_max,
        date_from=date_from.isoformat() if date_from else "",
        date_to=date_to.isoformat() if date_to else "",
        risk_color=_risk_color,
        mask_email=_mask_email,
    )


@admin_bp.get("/onboarding/<app_id>")
@admin_required
def onboarding_detail(app_id):
    inst_filter = get_institution_filter()
    query = OnboardingApplication.query.filter(OnboardingApplication.id == app_id).options(
        joinedload(OnboardingApplication.reviewer),
        joinedload(OnboardingApplication.institution),
    )
    query = apply_institution_filter(query, OnboardingApplication, inst_filter)
    application = query.first_or_404()

    risk_factors = KYCOnboardingScorer.generate_risk_factor_report(application)
    decision_form = OnboardingDecisionForm(data={"decision": application.decision})

    audit_query = AuditLog.query.filter(
        AuditLog.target_type == "onboarding_application",
        AuditLog.target_id == app_id,
    )
    audit_query = apply_institution_filter(audit_query, AuditLog, inst_filter)
    audit_history = audit_query.order_by(AuditLog.created_at.asc()).all()

    reviewer_query = AdminUser.query.filter(AdminUser._is_active.is_(True))
    reviewer_query = apply_institution_filter(reviewer_query, AdminUser, inst_filter)
    reviewers = reviewer_query.order_by(AdminUser.email.asc()).all()

    return render_template(
        "admin/onboarding_detail.html",
        application=application,
        risk_factors=risk_factors,
        risk_factors_json=json.dumps(risk_factors),
        decision_form=decision_form,
        audit_history=audit_history,
        watchlist_detail=application.get_watchlist_match_detail_dict(),
        reviewers=reviewers,
        risk_color=_risk_color,
        mask_email=_mask_email,
    )


@admin_bp.post("/onboarding/<app_id>/decide")
@admin_required
def onboarding_decide(app_id):
    inst_filter = get_institution_filter()
    query = OnboardingApplication.query.filter(OnboardingApplication.id == app_id)
    query = apply_institution_filter(query, OnboardingApplication, inst_filter)
    application = query.first_or_404()
    form = OnboardingDecisionForm()
    if not form.validate_on_submit():
        for errors in form.errors.values():
            for error in errors:
                flash(error, "error")
        return redirect(url_for("admin.onboarding_detail", app_id=app_id))

    notes = form.reviewer_notes.data or ""
    application.decision = form.decision.data
    application.reviewer_id = current_user.id
    application.reviewer_notes = notes
    application.decided_at = datetime.utcnow()
    db.session.add(application)
    db.session.commit()

    AuditLogger.log_from_request(
        current_user,
        f"onboarding.{form.decision.data}",
        "onboarding_application",
        app_id,
        {"decision": form.decision.data, "notes_length": len(notes)},
    )

    from app.tasks.kyc_processing import send_kyc_decision_notification_task

    send_kyc_decision_notification_task.delay(app_id)

    if form.decision.data == "approve":
        flash("Application approved.", "success")
    elif form.decision.data == "manual_review":
        flash("Application sent to manual review queue.", "success")
    elif form.decision.data == "reject":
        flash("Application rejected.", "warning")
        AlertManager.create_alert(
            institution_id=application.institution_id,
            user_id=None,
            alert_type="kyc_fraud",
            severity="high",
            title=f"KYC Application Rejected: {application.application_ref}",
            description=(
                f"Application rejected by {current_user.email[:20]}. "
                f"Risk score: {application.composite_risk_score}. "
                f"Reason: {notes[:100]}"
            ),
            auto_action="kyc_reject",
        )
    return redirect(url_for("admin.onboarding"))


@admin_bp.get("/privileged")
@admin_required
def privileged():
    inst_filter = get_institution_filter()
    role = (request.args.get("role") or "").strip()
    privilege_level = (request.args.get("privilege_level") or "all").strip()
    if privilege_level not in {"all", "standard", "elevated", "admin"}:
        privilege_level = "all"
    risk_min = _int_arg("risk_min", 0)
    risk_max = _int_arg("risk_max", 100)
    if risk_min > risk_max:
        risk_min, risk_max = risk_max, risk_min
    has_anomaly = (request.args.get("has_anomaly") or "").strip()
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")

    query = PrivilegedSession.query.options(joinedload(PrivilegedSession.employee))
    query = apply_institution_filter(query, PrivilegedSession, inst_filter)
    if role:
        query = query.filter(PrivilegedSession.role == role)
    if privilege_level != "all":
        query = query.filter(PrivilegedSession.privilege_level == privilege_level)
    query = query.filter(
        PrivilegedSession.risk_score >= risk_min,
        PrivilegedSession.risk_score <= risk_max,
    )
    if has_anomaly == "true":
        query = query.filter(PrivilegedSession.alert_generated.is_(True))
    elif has_anomaly == "false":
        query = query.filter(PrivilegedSession.alert_generated.is_(False))
    if date_from:
        query = query.filter(PrivilegedSession.started_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(PrivilegedSession.started_at < datetime.combine(date_to + timedelta(days=1), time.min))
    query = query.order_by(PrivilegedSession.risk_score.desc(), PrivilegedSession.started_at.desc())
    pagination = paginate_query(query, get_page_from_request(), per_page=25)

    total_query = PrivilegedSession.query
    total_query = apply_institution_filter(total_query, PrivilegedSession, inst_filter)
    active_query = PrivilegedSession.query.filter(PrivilegedSession.ended_at.is_(None))
    active_query = apply_institution_filter(active_query, PrivilegedSession, inst_filter)
    high_risk_query = PrivilegedSession.query.filter(PrivilegedSession.risk_score > 60)
    high_risk_query = apply_institution_filter(high_risk_query, PrivilegedSession, inst_filter)
    alerts_query = PrivilegedSession.query.filter(PrivilegedSession.alert_generated.is_(True))
    alerts_query = apply_institution_filter(alerts_query, PrivilegedSession, inst_filter)
    export_query = db.session.query(func.sum(PrivilegedSession.export_volume_kb))
    export_query = apply_institution_filter(export_query, PrivilegedSession, inst_filter)
    records_query = db.session.query(func.sum(PrivilegedSession.data_records_accessed))
    records_query = apply_institution_filter(records_query, PrivilegedSession, inst_filter)

    summary_stats = {
        "total_sessions": total_query.count(),
        "active_sessions": active_query.count(),
        "high_risk_sessions": high_risk_query.count(),
        "alerts_generated": alerts_query.count(),
        "total_export_kb": int(export_query.scalar() or 0),
        "total_records_accessed": int(records_query.scalar() or 0),
    }

    role_query = db.session.query(PrivilegedSession.role).filter(PrivilegedSession.role.is_not(None)).distinct()
    role_query = apply_institution_filter(role_query, PrivilegedSession, inst_filter)
    role_options = [row[0] for row in role_query.order_by(PrivilegedSession.role.asc()).all() if row[0]]

    return render_template(
        "admin/privileged.html",
        pagination=pagination,
        sessions=pagination.items,
        summary_stats=summary_stats,
        role_options=role_options,
        selected_role=role,
        selected_privilege_level=privilege_level,
        risk_min=risk_min,
        risk_max=risk_max,
        has_anomaly=has_anomaly,
        date_from=date_from.isoformat() if date_from else "",
        date_to=date_to.isoformat() if date_to else "",
        risk_color=_risk_color,
        mask_email=_mask_email,
    )


@admin_bp.get("/privileged/<session_id>")
@admin_required
def privileged_detail(session_id):
    inst_filter = get_institution_filter()
    query = PrivilegedSession.query.filter(PrivilegedSession.id == session_id).options(
        joinedload(PrivilegedSession.employee),
        joinedload(PrivilegedSession.institution),
    )
    query = apply_institution_filter(query, PrivilegedSession, inst_filter)
    priv_session = query.first_or_404()

    employee_query = User.query.filter(User.id == priv_session.employee_user_id)
    employee_query = apply_institution_filter(employee_query, User, inst_filter)
    employee = employee_query.first()

    anomaly_lookup = {
        "bulk_record_access": {
            "name": "Bulk Record Access",
            "explanation": f"Accessed {priv_session.data_records_accessed} customer records, above the 500 record threshold.",
            "recommendation": "Verify this access was part of an approved audit or business process.",
        },
        "large_data_export": {
            "name": "Large Data Export",
            "explanation": f"Exported {priv_session.export_volume_kb} KB during the session, above the 10240 KB threshold.",
            "recommendation": "Confirm the export destination and business approval.",
        },
        "off_hours_access": {
            "name": "Off Hours Access",
            "explanation": "Session started outside the normal operating window.",
            "recommendation": "Review staffing schedule, ticket reference, and supervisor approval.",
        },
        "high_action_velocity": {
            "name": "High Action Velocity",
            "explanation": f"Recorded {priv_session.actions_count} privileged actions in a short period.",
            "recommendation": "Check whether automation or scripted access was authorized.",
        },
        "unauthorized_system_access": {
            "name": "Unauthorized System Access",
            "explanation": f"Accessed {priv_session.system_accessed} with privilege level {priv_session.privilege_level}.",
            "recommendation": "Confirm role entitlements and remove excess privileges if needed.",
        },
    }
    anomaly_details = []
    for key, value in priv_session.get_anomaly_flags_dict().items():
        score = float(value or 0)
        metadata = anomaly_lookup.get(
            key,
            {
                "name": key.replace("_", " ").title(),
                "explanation": "An anomalous privileged access pattern was detected.",
                "recommendation": "Review the session activity and approval context.",
            },
        )
        severity = "critical" if score >= 0.85 else "high" if score >= 0.70 else "medium"
        anomaly_details.append({
            "name": metadata["name"],
            "score": score,
            "score_pct": int(round(score * 100)),
            "severity": severity,
            "explanation": metadata["explanation"],
            "recommendation": metadata["recommendation"],
        })

    risk_summary = PrivilegedAccessMonitor.get_employee_risk_summary(
        priv_session.employee_user_id,
        priv_session.institution_id,
        days=30,
    )

    related_alert_query = Alert.query.filter(
        Alert.user_id == priv_session.employee_user_id,
        Alert.alert_type == "insider_anomaly",
    )
    related_alert_query = apply_institution_filter(related_alert_query, Alert, inst_filter)
    related_alerts = related_alert_query.order_by(Alert.created_at.desc()).limit(5).all()

    audit_query = AuditLog.query.filter(
        AuditLog.target_type == "privileged_session",
        AuditLog.target_id == session_id,
    )
    audit_query = apply_institution_filter(audit_query, AuditLog, inst_filter)
    audit_history = audit_query.order_by(AuditLog.created_at.asc()).all()

    return render_template(
        "admin/privileged_detail.html",
        priv_session=priv_session,
        employee=employee,
        anomaly_details=anomaly_details,
        risk_summary=risk_summary,
        related_alerts=related_alerts,
        audit_history=audit_history,
        risk_color=_risk_color,
        mask_email=_mask_email,
    )


def _default_stepup_rules():
    return [
        {"risk_min": 31, "risk_max": 60, "channel": "all", "verification_method": "otp", "timeout_seconds": 120},
        {"risk_min": 61, "risk_max": 80, "channel": "all", "verification_method": "push_notification", "timeout_seconds": 90},
        {"risk_min": 81, "risk_max": 95, "channel": "web_browser", "verification_method": "video_kyc", "timeout_seconds": 300},
        {"risk_min": 81, "risk_max": 95, "channel": "mobile_app", "verification_method": "biometric", "timeout_seconds": 120},
    ]


def _default_channel_policies():
    return {
        "mobile_app": {"enabled": False, "risk_multiplier": 1.0, "stepup_threshold": 60},
        "web_browser": {"enabled": False, "risk_multiplier": 1.0, "stepup_threshold": 60},
        "api": {"enabled": False, "risk_multiplier": 1.0, "stepup_threshold": 50},
        "atm": {"enabled": False, "risk_multiplier": 1.0, "stepup_threshold": 55},
    }


def _default_ml_weights():
    return {
        "device": 0.25,
        "behavioural": 0.20,
        "geographic": 0.15,
        "network": 0.15,
        "transaction": 0.15,
        "time": 0.10,
    }


def _effective_policy_institution(inst_filter):
    if inst_filter is not None:
        return inst_filter
    if getattr(current_user, "institution_id", None):
        return current_user.institution_id
    first_institution = Institution.query.order_by(Institution.created_at.asc()).first()
    return first_institution.id if first_institution else None


@admin_bp.route("/policy", methods=["GET", "POST"])
@admin_required
def policy():
    inst_filter = get_institution_filter()
    effective_inst_id = _effective_policy_institution(inst_filter)
    if not effective_inst_id:
        flash("Create an institution before configuring a risk policy.", "warning")
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        form = PolicyForm()
        if not form.validate_on_submit():
            for errors in form.errors.values():
                for error in errors:
                    flash(error, "error")
            return redirect(url_for("admin.policy"))

        try:
            stepup_rules = json.loads(form.stepup_rules_json.data or "[]")
            if not isinstance(stepup_rules, list):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            flash("Step up rules must be valid JSON.", "error")
            return redirect(url_for("admin.policy"))

        try:
            channel_policies = json.loads(form.channel_policies_json.data or "{}")
            if not isinstance(channel_policies, dict):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            flash("Channel policies must be valid JSON.", "error")
            return redirect(url_for("admin.policy"))

        weight_config = {
            "device": float(form.ml_weight_device.data or 0),
            "behavioural": float(form.ml_weight_behavioural.data or 0),
            "geographic": float(form.ml_weight_geographic.data or 0),
            "network": float(form.ml_weight_network.data or 0),
            "transaction": float(form.ml_weight_transaction.data or 0),
            "time": float(form.ml_weight_time.data or 0),
        }

        old_policies = RiskPolicy.query.filter(
            RiskPolicy.institution_id == effective_inst_id,
            RiskPolicy.is_active.is_(True),
        ).all()
        for old_policy in old_policies:
            old_policy.is_active = False
            db.session.add(old_policy)

        new_policy = RiskPolicy(
            institution_id=effective_inst_id,
            policy_name=form.policy_name.data,
            threshold_low=form.threshold_low.data,
            threshold_medium=form.threshold_medium.data,
            threshold_high=form.threshold_high.data,
            stepup_rules=json.dumps(stepup_rules, sort_keys=True),
            channel_policies=json.dumps(channel_policies, sort_keys=True),
            ml_weight_config=json.dumps(weight_config, sort_keys=True),
            is_active=True,
            created_by=current_user.id,
            activated_at=datetime.utcnow(),
        )
        db.session.add(new_policy)
        AuditLogger.log_from_request(
            current_user,
            "policy.update",
            "risk_policy",
            new_policy.id,
            {
                "policy_name": new_policy.policy_name,
                "institution_id": effective_inst_id,
                "thresholds": [new_policy.threshold_low, new_policy.threshold_medium, new_policy.threshold_high],
            },
            commit=False,
        )
        db.session.commit()
        flash("Risk policy saved and activated.", "success")
        return redirect(url_for("admin.policy"))

    active_policy = RiskPolicy.query.filter_by(institution_id=effective_inst_id, is_active=True).first()
    policy_history = (
        RiskPolicy.query.filter_by(institution_id=effective_inst_id)
        .order_by(RiskPolicy.created_at.desc())
        .limit(5)
        .all()
    )
    form = PolicyForm()
    stepup_rules_list = _default_stepup_rules()
    channel_policies = _default_channel_policies()
    weight_config = _default_ml_weights()
    if active_policy:
        form.policy_name.data = active_policy.policy_name
        form.threshold_low.data = active_policy.threshold_low
        form.threshold_medium.data = active_policy.threshold_medium
        form.threshold_high.data = active_policy.threshold_high
        stepup_rules_list = active_policy.get_stepup_rules_list() or stepup_rules_list
        channel_policies = active_policy._parse_json(active_policy.channel_policies, channel_policies)
        weight_config.update(active_policy._parse_json(active_policy.ml_weight_config, {}))
    else:
        form.policy_name.data = "Default Risk Policy"
        form.threshold_low.data = 30
        form.threshold_medium.data = 60
        form.threshold_high.data = 80
    form.stepup_rules_json.data = json.dumps(stepup_rules_list)
    form.channel_policies_json.data = json.dumps(channel_policies)
    form.ml_weight_device.data = weight_config["device"]
    form.ml_weight_behavioural.data = weight_config["behavioural"]
    form.ml_weight_geographic.data = weight_config["geographic"]
    form.ml_weight_network.data = weight_config["network"]
    form.ml_weight_transaction.data = weight_config["transaction"]
    form.ml_weight_time.data = weight_config["time"]

    today_start = datetime.combine(date.today(), time.min)
    alert_distribution = _risk_distribution_query(effective_inst_id, today_start)

    return render_template(
        "admin/policy.html",
        form=form,
        active_policy=active_policy,
        policy_history=policy_history,
        effective_inst_id=effective_inst_id,
        stepup_rules_json_init=json.dumps(stepup_rules_list),
        alert_distribution_json=json.dumps(alert_distribution),
        channel_policies_json=json.dumps(channel_policies),
        channel_policies=channel_policies,
        alert_distribution=alert_distribution,
        weight_config=weight_config,
    )


@admin_bp.post("/policy/test-rule")
@admin_required
def policy_test_rule():
    if not request.is_json:
        return error_response("This endpoint accepts JSON only.", status_code=400)
    inst_filter = get_institution_filter()
    effective_inst_id = _effective_policy_institution(inst_filter)
    if not effective_inst_id:
        return error_response("No institution is available for testing.", status_code=400)
    data = request.get_json(silent=True) or {}
    try:
        risk_min = int(data.get("risk_min", 0))
        risk_max = int(data.get("risk_max", 100))
        channel = data.get("channel") or "all"
    except (TypeError, ValueError):
        return error_response("Rule values are invalid.", status_code=400)

    sessions_query = SessionRecord.query.filter(SessionRecord.institution_id == effective_inst_id)
    sessions = sessions_query.order_by(SessionRecord.started_at.desc()).limit(100).all()
    matches = [
        item
        for item in sessions
        if risk_min <= int(item.risk_score_peak or 0) <= risk_max and channel in {"all", item.channel}
    ]
    sample_matches = []
    for item in matches[:3]:
        sample_matches.append({
            "masked_user_id": item.user.get_masked_id() if item.user else "Protected",
            "channel": _channel_label(item.channel),
            "risk_score": item.risk_score_peak,
        })
    match_pct = (len(matches) / len(sessions) * 100) if sessions else 0
    return success_response(
        {
            "match_count": len(matches),
            "match_percentage": round(match_pct, 1),
            "sample_matches": sample_matches,
            "rule": {
                "risk_min": risk_min,
                "risk_max": risk_max,
                "channel": channel,
                "verification_method": data.get("verification_method", "otp"),
            },
        }
    )


@admin_bp.get("/reports")
@admin_required
def reports():
    report_types = _report_type_metadata()
    inst_filter = get_institution_filter()
    recent_reports = list_recent_reports(inst_filter, limit=5)
    return render_template("admin/reports.html", report_types=report_types, recent_reports=recent_reports)


def _report_type_metadata():
    report_keys = ["rbi_report", "alert_summary", "user_risk", "incident", "gdpr_compliance", "iso27001"]
    fallback = {
        "gdpr_compliance": {
            "name": "GDPR Compliance Report",
            "description": "Privacy governance evidence covering audit activity, user controls, and incident records.",
            "suggested_frequency": "Quarterly",
            "regulatory_mapping": ["GDPR", "DPDP Act"],
            "sections": ["Data subject controls", "Security incidents", "Audit evidence"],
        },
        "iso27001": {
            "name": "ISO 27001 Controls Report",
            "description": "Control evidence for access governance, monitoring, auditability, and incident response.",
            "suggested_frequency": "Quarterly",
            "regulatory_mapping": ["ISO 27001"],
            "sections": ["Access control", "Operational monitoring", "Incident management"],
        },
    }
    metadata = {}
    for key in report_keys:
        item = ComplianceReportGenerator.get_report_metadata(key) or fallback.get(key, {})
        metadata[key] = {
            "report_type_key": key,
            "name": item.get("name", key.replace("_", " ").title()),
            "description": item.get("description", "Operational TrustSphere report."),
            "suggested_frequency": item.get("suggested_frequency", "As needed"),
            "regulatory_mapping": item.get("regulatory_mapping", []),
            "sections": item.get("sections", ["Summary metrics", "Detailed records", "Audit evidence"]),
        }
    return metadata


def _populate_report_form(form):
    form.institution_id.choices = [("", "Current Institution")]
    if getattr(current_user, "is_super_admin", False):
        institutions = Institution.query.order_by(Institution.name.asc()).all()
        form.institution_id.choices = [("", "Select Institution")] + [(item.id, item.name) for item in institutions]
    return form


def _selected_report_institution(form):
    if getattr(current_user, "is_super_admin", False):
        selected = (form.institution_id.data or "").strip()
        if selected:
            institution = Institution.query.filter_by(id=selected).first()
            return institution.id if institution else None
        first_institution = Institution.query.order_by(Institution.created_at.asc()).first()
        return first_institution.id if first_institution else None
    return current_user.institution_id


def _date_window_from_form(form):
    date_to_value = form.date_to.data or date.today()
    date_from_value = form.date_from.data or (date_to_value - timedelta(days=30))
    return (
        datetime.combine(date_from_value, time.min),
        datetime.combine(date_to_value, time.max),
    )


def _generate_report_data(report_type, institution_id, date_from_value, date_to_value, alert_id=None):
    if report_type == "rbi_report":
        return ComplianceReportGenerator.generate_rbi_report(institution_id, date_from_value, date_to_value)
    if report_type == "alert_summary":
        return ComplianceReportGenerator.generate_alert_summary_report(institution_id, date_from_value, date_to_value)
    if report_type == "user_risk":
        return ComplianceReportGenerator.generate_user_risk_report(institution_id)
    if report_type == "incident":
        alert_query = Alert.query.filter(Alert.id == alert_id)
        alert_query = alert_query.filter(Alert.institution_id == institution_id)
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


@admin_bp.route("/reports/generate", methods=["GET", "POST"])
@admin_required
def reports_generate():
    report_types = _report_type_metadata()
    selected_type = (request.args.get("report_type") or request.form.get("report_type") or "rbi_report").strip()
    if selected_type not in report_types:
        selected_type = "rbi_report"
    form = _populate_report_form(ReportForm(data={"report_type": selected_type}))
    task_id = request.args.get("task_id") or flask_session.get("last_report_task_id")

    if request.method == "POST":
        form = _populate_report_form(ReportForm())
        if not form.validate_on_submit():
            for errors in form.errors.values():
                for error in errors:
                    flash(error, "error")
            return redirect(url_for("admin.reports_generate", report_type=selected_type))
        institution_id = _selected_report_institution(form)
        if not institution_id:
            flash("Select a valid institution for this report.", "error")
            return redirect(url_for("admin.reports_generate", report_type=form.report_type.data))
        date_from_value, date_to_value = _date_window_from_form(form)
        task_id = str(uuid.uuid4())
        set_report(
            task_id,
            "pending",
            format_str=form.format.data,
            report_type=form.report_type.data,
            institution_id=institution_id,
        )
        from app.tasks.report_build import generate_compliance_report_task

        generate_compliance_report_task.delay(
            institution_id,
            form.report_type.data,
            date_from_value.isoformat(),
            date_to_value.isoformat(),
            form.format.data,
            task_id,
            current_user.id,
            form.alert_id.data,
        )
        flask_session["last_report_task_id"] = task_id
        AuditLogger.log_from_request(
            current_user,
            "report.generate_queued",
            "report",
            task_id,
            {
                "report_type": form.report_type.data,
                "format": form.format.data,
                "institution_id": institution_id,
            },
        )
        flash("Report generation started.", "success")
        return redirect(url_for("admin.reports_generate", report_type=form.report_type.data, task_id=task_id))

    form.report_type.data = selected_type
    last_report = get_report(task_id) if task_id else None
    return render_template(
        "admin/reports_generate.html",
        form=form,
        report_types=report_types,
        selected_type=selected_type,
        last_report=last_report,
        task_id=task_id,
    )


@admin_bp.get("/reports/download/<report_id>")
@admin_bp.get("/reports/<report_id>/download")
@admin_required
def reports_download(report_id):
    entry = get_report(report_id)
    if not entry:
        flash("Report not found or has expired.", "error")
        return redirect(url_for("admin.reports"))
    inst_filter = get_institution_filter()
    if inst_filter is not None and entry.get("institution_id") != inst_filter:
        flash("Report not found or has expired.", "error")
        return redirect(url_for("admin.reports"))
    # If the report isn't marked completed, allow download only if content is present.
    if entry.get("status") != "completed" and not entry.get("content"):
        flash("Report is still generating. Please wait.", "warning")
        return redirect(url_for("admin.reports"))
    extension = "csv" if entry.get("format") == "csv" else "json"
    mimetype = "text/csv" if extension == "csv" else "application/json"
    filename = f"trustsphere_{entry.get('report_type', 'report')}_{date.today()}.{extension}"
    return Response(
        entry.get("content", ""),
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@admin_bp.get("/reports/status/<task_id>")
@admin_required
def report_status(task_id):
    """Return JSON status for one report task id for client-side polling."""
    entry = get_report(task_id)
    if not entry:
        return jsonify({"status": None, "has_content": False}), 404
    created_at = entry.get("created_at")
    created_at_iso = None
    if isinstance(created_at, datetime):
        created_at_iso = created_at.isoformat()
    elif isinstance(created_at, str):
        created_at_iso = created_at
    return jsonify(
        {
            "status": entry.get("status"),
            "has_content": bool(entry.get("content")),
            "report_type": entry.get("report_type"),
            "format": entry.get("format"),
            "created_at": created_at_iso,
        }
    )


@admin_bp.get("/audit-log")
@admin_required
def audit_log():
    inst_filter = get_institution_filter()
    actor_type = (request.args.get("actor_type") or "").strip()
    target_type = (request.args.get("target_type") or "").strip()
    action_contains = (request.args.get("action_contains") or request.args.get("action") or "").strip()
    actor_email = (request.args.get("actor_email") or "").strip()
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")

    query = AuditLog.query
    query = apply_institution_filter(query, AuditLog, inst_filter)
    if actor_type:
        query = query.filter(AuditLog.actor_type == actor_type)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    if action_contains:
        query = query.filter(AuditLog.action.ilike(f"%{action_contains}%"))
    if actor_email:
        query = query.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if date_from:
        query = query.filter(AuditLog.created_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(AuditLog.created_at < datetime.combine(date_to + timedelta(days=1), time.min))
    pagination = paginate_query(query.order_by(AuditLog.created_at.desc()), get_page_from_request(), per_page=50)

    today_start = datetime.combine(date.today(), time.min)
    today_query = AuditLog.query.filter(AuditLog.created_at >= today_start)
    today_query = apply_institution_filter(today_query, AuditLog, inst_filter)
    total_entries_today = today_query.count()

    actor_query = db.session.query(AuditLog.actor_type).filter(AuditLog.actor_type.is_not(None)).distinct()
    actor_query = apply_institution_filter(actor_query, AuditLog, inst_filter)
    actor_type_options = [row[0] for row in actor_query.order_by(AuditLog.actor_type.asc()).all()]
    target_query = db.session.query(AuditLog.target_type).filter(AuditLog.target_type.is_not(None)).distinct()
    target_query = apply_institution_filter(target_query, AuditLog, inst_filter)
    target_type_options = [row[0] for row in target_query.order_by(AuditLog.target_type.asc()).all()]

    active_filter_count = sum(bool(value) for value in [actor_type, target_type, action_contains, actor_email, date_from, date_to])

    return render_template(
        "admin/audit_log.html",
        pagination=pagination,
        entries=pagination.items,
        total_entries_today=total_entries_today,
        actor_type_options=actor_type_options,
        target_type_options=target_type_options,
        selected_actor_type=actor_type,
        selected_target_type=target_type,
        action_contains=action_contains,
        actor_email=actor_email,
        date_from=date_from.isoformat() if date_from else "",
        date_to=date_to.isoformat() if date_to else "",
        active_filter_count=active_filter_count,
        mask_email=_mask_email,
        actor_badge_color=_actor_badge_color,
    )


def _actor_badge_color(actor_type):
    return {
        "admin": "primary",
        "admin_user": "primary",
        "system": "secondary",
        "api": "info",
        "customer": "warning",
    }.get(actor_type, "secondary")


@admin_bp.get("/audit-log/export")
@admin_required
def audit_log_export():
    inst_filter = get_institution_filter()
    actor_type = (request.args.get("actor_type") or "").strip()
    target_type = (request.args.get("target_type") or "").strip()
    action_contains = (request.args.get("action") or "").strip()
    actor_email = (request.args.get("actor_email") or "").strip()
    date_from = _parse_date_arg("date_from")
    date_to = _parse_date_arg("date_to")

    query = AuditLog.query
    query = apply_institution_filter(query, AuditLog, inst_filter)
    query = query.filter(AuditLog.created_at >= datetime.utcnow() - timedelta(days=30))
    if actor_type:
        query = query.filter(AuditLog.actor_type == actor_type)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    if action_contains:
        query = query.filter(AuditLog.action.ilike(f"%{action_contains}%"))
    if actor_email:
        query = query.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if date_from:
        query = query.filter(AuditLog.created_at >= datetime.combine(date_from, time.min))
    if date_to:
        query = query.filter(AuditLog.created_at < datetime.combine(date_to + timedelta(days=1), time.min))

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ID", "Timestamp", "Actor Type", "Actor Email", "Action", "Target Type", "Target ID", "IP Address", "Details"])
    entries = query.order_by(AuditLog.created_at.desc()).limit(10000).all()
    for entry in entries:
        details_text = entry.details or "{}"
        if len(details_text) > 200:
            details_text = details_text[:200]
        writer.writerow([
            entry.id,
            entry.created_at.isoformat() if entry.created_at else "",
            entry.actor_type,
            entry.actor_email,
            entry.action,
            entry.target_type,
            entry.target_id,
            entry.ip_address,
            details_text,
        ])
    AuditLogger.log_from_request(
        current_user,
        "audit_log.export",
        "audit_log",
        None,
        {"record_count": len(entries)},
    )
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=trustsphere_audit_log.csv"},
    )


def _settings_form_with_config():
    return SettingsForm(data={
        "mail_server": current_app.config.get("MAIL_SERVER"),
        "mail_port": current_app.config.get("MAIL_PORT"),
        "mail_use_tls": current_app.config.get("MAIL_USE_TLS"),
        "mail_username": current_app.config.get("MAIL_USERNAME"),
        "platform_maintenance_mode": current_app.config.get("PLATFORM_MAINTENANCE_MODE", False),
        "max_login_attempts": current_app.config.get("MAX_LOGIN_ATTEMPTS", 5),
        "session_timeout_minutes": int(current_app.permanent_session_lifetime.total_seconds() / 60),
    })


def _celery_tasks_status():
    return [
        {"task_name": "auto_prioritise_alerts", "schedule": "Every 30 minutes", "last_run": None, "status": "unknown"},
        {"task_name": "weekly_security_digest", "schedule": "Weekly", "last_run": None, "status": "unknown"},
        {"task_name": "refresh_policy_metrics", "schedule": "Every hour", "last_run": None, "status": "unknown"},
    ]


@admin_bp.route("/settings", methods=["GET", "POST"])
@super_admin_required
def settings():
    form = _settings_form_with_config() if request.method == "GET" else SettingsForm()
    if request.method == "POST":
        if not form.validate_on_submit():
            for errors in form.errors.values():
                for error in errors:
                    flash(error, "error")
            return redirect(url_for("admin.settings"))

        if form.submit_add_institution.data:
            name = (form.new_institution_name.data or "").strip()
            domain = (form.new_institution_domain.data or "").strip().lower()
            if not name or not domain:
                flash("Institution name and domain are required.", "error")
                return redirect(url_for("admin.settings"))
            if Institution.query.filter_by(domain=domain).first():
                flash("An institution with this domain already exists.", "error")
                return redirect(url_for("admin.settings"))
            raw_key, api_key_hash = Institution.generate_api_key()
            institution = Institution(
                name=name,
                domain=domain,
                plan_tier=form.new_institution_plan_tier.data,
                api_key_hash=api_key_hash,
                is_active=True,
            )
            db.session.add(institution)
            AuditLogger.log_from_request(
                current_user,
                "institution.create",
                "institution",
                institution.id,
                {"name": name, "domain": domain, "plan_tier": institution.plan_tier},
                commit=False,
            )
            db.session.commit()
            flash(f"Institution created. API key: {raw_key}", "success")
            return redirect(url_for("admin.settings"))

        if "mail_server" in request.form:
            current_app.config["MAIL_SERVER"] = form.mail_server.data or current_app.config.get("MAIL_SERVER")
        if "mail_port" in request.form:
            current_app.config["MAIL_PORT"] = form.mail_port.data or current_app.config.get("MAIL_PORT")
        if "mail_use_tls" in request.form:
            current_app.config["MAIL_USE_TLS"] = bool(form.mail_use_tls.data)
        if "mail_username" in request.form:
            current_app.config["MAIL_USERNAME"] = form.mail_username.data or current_app.config.get("MAIL_USERNAME")
        if "mail_password" in request.form and form.mail_password.data:
            current_app.config["MAIL_PASSWORD"] = form.mail_password.data
        if "platform_maintenance_mode" in request.form:
            current_app.config["PLATFORM_MAINTENANCE_MODE"] = bool(form.platform_maintenance_mode.data)
        if "max_login_attempts" in request.form:
            current_app.config["MAX_LOGIN_ATTEMPTS"] = form.max_login_attempts.data or 5
        if "session_timeout_minutes" in request.form:
            current_app.permanent_session_lifetime = timedelta(minutes=form.session_timeout_minutes.data or 30)
        AuditLogger.log_from_request(
            current_user,
            "settings.update",
            "platform_settings",
            None,
            {
                "mail_server": current_app.config.get("MAIL_SERVER"),
                "maintenance_mode": current_app.config.get("PLATFORM_MAINTENANCE_MODE"),
                "session_timeout_minutes": form.session_timeout_minutes.data,
            },
        )
        flash("Platform settings saved.", "success")
        return redirect(url_for("admin.settings"))

    institutions = Institution.query.order_by(Institution.name.asc()).all()
    admin_users = AdminUser.query.options(joinedload(AdminUser.institution)).order_by(AdminUser.created_at.desc()).all()
    user_counts = {
        row[0]: row[1]
        for row in db.session.query(User.institution_id, func.count(User.id)).group_by(User.institution_id).all()
    }
    api_keys_info = [
        {
            "institution": institution,
            "masked_key": "****" + (institution.api_key_hash or "")[-6:] if institution.api_key_hash else "Not generated",
        }
        for institution in institutions
    ]
    return render_template(
        "admin/settings.html",
        form=form,
        institutions=institutions,
        admin_users=admin_users,
        user_counts=user_counts,
        api_keys_info=api_keys_info,
        celery_tasks_status=_celery_tasks_status(),
        mask_email=_mask_email,
    )


@admin_bp.post("/settings/institutions/<institution_id>/regenerate-api-key")
@super_admin_required
def regenerate_api_key(institution_id):
    institution = Institution.query.filter_by(id=institution_id).first_or_404()
    raw_key, api_key_hash = Institution.generate_api_key()
    institution.api_key_hash = api_key_hash
    institution.updated_at = datetime.utcnow()
    db.session.add(institution)
    AuditLogger.log_from_request(
        current_user,
        "api_key.regenerate",
        "institution",
        institution.id,
        {"institution": institution.name},
        commit=False,
    )
    db.session.commit()
    flash(f"API key regenerated for {institution.name}. New key: {raw_key}", "success")
    return redirect(url_for("admin.settings"))


@admin_bp.post("/settings/institutions/<institution_id>/toggle")
@super_admin_required
def toggle_institution(institution_id):
    institution = Institution.query.filter_by(id=institution_id).first_or_404()
    institution.is_active = not institution.is_active
    institution.updated_at = datetime.utcnow()
    db.session.add(institution)
    AuditLogger.log_from_request(
        current_user,
        "institution.toggle_active",
        "institution",
        institution.id,
        {"is_active": institution.is_active},
        commit=False,
    )
    db.session.commit()
    flash("Institution status updated.", "success")
    return redirect(url_for("admin.settings"))


@admin_bp.post("/settings/admin-users/<admin_user_id>/toggle")
@super_admin_required
def toggle_admin_user(admin_user_id):
    admin_user = AdminUser.query.filter_by(id=admin_user_id).first_or_404()
    if admin_user.id == current_user.id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin.settings"))
    admin_user.is_active = not admin_user.is_active
    db.session.add(admin_user)
    AuditLogger.log_from_request(
        current_user,
        "admin_user.toggle_active",
        "admin_user",
        admin_user.id,
        {"is_active": admin_user.is_active},
        commit=False,
    )
    db.session.commit()
    flash("Admin user status updated.", "success")
    return redirect(url_for("admin.settings"))


@admin_bp.post("/settings/admin-users/create")
@super_admin_required
def create_admin_user():
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or "security_analyst").strip()
    institution_id = (request.form.get("institution_id") or "").strip() or None
    temp_password = request.form.get("temp_password") or ""
    if not email or not temp_password:
        flash("Email and temporary password are required.", "error")
        return redirect(url_for("admin.settings"))
    if role not in {"super_admin", "security_analyst", "compliance_officer", "read_only", "it_admin"}:
        flash("Admin role is invalid.", "error")
        return redirect(url_for("admin.settings"))
    if AdminUser.query.filter_by(email=email).first():
        flash("An admin user with this email already exists.", "error")
        return redirect(url_for("admin.settings"))
    if institution_id and not Institution.query.filter_by(id=institution_id).first():
        flash("Selected institution does not exist.", "error")
        return redirect(url_for("admin.settings"))
    admin_user = AdminUser(email=email, role=role, institution_id=institution_id, is_active=True)
    admin_user.set_password(temp_password)
    db.session.add(admin_user)
    AuditLogger.log_from_request(
        current_user,
        "admin_user.create",
        "admin_user",
        admin_user.id,
        {"email": _mask_email(email), "role": role, "institution_id": institution_id},
        commit=False,
    )
    db.session.commit()
    flash("Admin user created.", "success")
    return redirect(url_for("admin.settings"))


@admin_bp.post("/settings/run-task/<task_name>")
@super_admin_required
def run_task(task_name):
    tasks = {
        "auto_prioritise_alerts": lambda: AlertManager.auto_prioritise_alerts(),
        "weekly_security_digest": lambda: sum(
            NotificationService.send_weekly_security_digest(institution.id)
            for institution in Institution.query.filter_by(is_active=True).all()
        ),
        "refresh_policy_metrics": lambda: RiskPolicy.query.filter_by(is_active=True).count(),
    }
    task = tasks.get(task_name)
    if not task:
        flash("Task not found.", "error")
        return redirect(url_for("admin.settings"))
    result = task()
    AuditLogger.log_from_request(
        current_user,
        "task.run",
        "celery_task",
        task_name,
        {"result": result},
    )
    flash(f"Task {task_name.replace('_', ' ').title()} ran successfully.", "success")
    return redirect(url_for("admin.settings"))


@admin_bp.post("/settings/test-email")
@super_admin_required
def test_email():
    ok, message = NotificationService.send_email(
        current_user.email,
        "TrustSphere Test Email",
        "<h2>Test email from TrustSphere</h2><p>SMTP configuration is working correctly.</p>",
    )
    AuditLogger.log_from_request(
        current_user,
        "settings.test_email",
        "platform_settings",
        None,
        {"success": ok},
    )
    if ok:
        flash("Test email sent.", "success")
    else:
        flash(f"Test email failed: {message}", "error")
    return redirect(url_for("admin.settings"))
