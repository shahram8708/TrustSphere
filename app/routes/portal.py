"""Customer security portal routes."""

from __future__ import annotations

from datetime import datetime, time, timedelta
from functools import wraps
import json

from flask import Blueprint, flash, redirect, render_template, request, session as flask_session, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy import case

from app.extensions import db
from app.forms import DeviceNameForm, PreferencesForm, RecoveryInitiateForm, RecoveryVerifyForm
from app.models import Alert, Device, Institution, RiskEvent, SessionRecord, User
from app.services import (
    AuditLogger,
    ContinuousRiskEngine,
    DeviceIntelligenceService,
    EncryptionService,
    NotificationService,
    StepUpOrchestrator,
)
from app.utils.ip_intel import get_client_ip, get_ip_info
from app.utils.pagination import get_page_from_request, paginate_query


portal_bp = Blueprint("portal", __name__)


def portal_login_required(view_func):
    """Require an active customer or employee portal user."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not getattr(current_user, "is_authenticated", False):
            flash("Please log in to access your security portal.", "warning")
            return redirect(url_for("auth.login"))

        user = current_user._get_current_object()
        if not isinstance(user, User):
            flash("Please log in to access your security portal.", "warning")
            return redirect(url_for("auth.login"))

        if user.is_suspended:
            flash("Your account has been suspended. Please contact your bank for assistance.", "error")
            return redirect(url_for("auth.login"))

        return view_func(*args, **kwargs)

    return wrapped


def _get_security_tip(user, suspicious_devices, open_alerts_count):
    if len(suspicious_devices) > 0:
        return {
            "type": "warning",
            "icon": "bi-exclamation-triangle-fill",
            "message": "A suspicious device was detected on your account. Review your registered devices.",
            "action_text": "Review Devices",
            "action_url": url_for("portal.devices"),
        }
    if open_alerts_count > 0:
        suffix = "s" if open_alerts_count > 1 else ""
        return {
            "type": "danger",
            "icon": "bi-shield-exclamation",
            "message": f"You have {open_alerts_count} unresolved security alert{suffix}.",
            "action_text": "View Alerts",
            "action_url": url_for("portal.alerts"),
        }
    if (user.risk_score_current or 0) > 60:
        return {
            "type": "warning",
            "icon": "bi-graph-up-arrow",
            "message": "Your account risk score is elevated. This may be due to recent unusual activity.",
            "action_text": "View Activity",
            "action_url": url_for("portal.activity"),
        }
    if len([device for device in suspicious_devices if device.trust_level == "new"]) > 0:
        return {
            "type": "info",
            "icon": "bi-phone-vibrate",
            "message": "A new device was recently used to access your account.",
            "action_text": "Review Devices",
            "action_url": url_for("portal.devices"),
        }
    return {
        "type": "success",
        "icon": "bi-shield-check-fill",
        "message": "Your account is secure. All activity looks normal.",
        "action_text": None,
        "action_url": None,
    }


def _load_json_object(raw_value):
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
        return value if isinstance(value, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _default_preferences():
    return {
        "preferred_stepup_method": "push_notification",
        "email_alerts_enabled": True,
        "sms_alerts_enabled": False,
        "high_value_transaction_alert": False,
        "transaction_alert_threshold": None,
        "new_device_alert": True,
        "foreign_login_alert": True,
        "language": "en",
    }


def _load_user_config(user):
    return _load_json_object(getattr(user, "config_json", None))


def _load_user_preferences(user):
    config = _load_user_config(user)
    preferences = dict(_default_preferences())
    stored_preferences = config.get("security_preferences", config)
    if isinstance(stored_preferences, dict):
        preferences.update(
            {
                key: stored_preferences[key]
                for key in preferences
                if key in stored_preferences
            }
        )
    return preferences


def _store_user_preferences(user, preferences):
    config = _load_user_config(user)
    config["security_preferences"] = preferences
    user.config_json = json.dumps(config, sort_keys=True)


def _date_from_request(name):
    raw_value = (request.args.get(name) or "").strip()
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%d").date()
    except ValueError:
        flash("Date filters must use the YYYY-MM-DD format.", "warning")
        return None


def _risk_category_for_score(score):
    score = int(score or 0)
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def _risk_color_for_score(score):
    return {
        "Low": "success",
        "Medium": "warning",
        "High": "danger",
        "Critical": "danger",
    }[_risk_category_for_score(score)]


def _channel_label(channel):
    return {
        "web_browser": "Web Browser",
        "mobile_app": "Mobile App",
        "api": "API",
        "atm": "ATM",
    }.get(channel, (channel or "Unknown").replace("_", " ").title())


def _event_display(event_type):
    return {
        "login": "Login",
        "transaction": "Transfer Initiated",
        "data_export": "Data Export",
        "step_up": "Step Up Verification",
        "page_nav": "Page Navigation",
        "account_recovery": "Account Recovery",
        "behaviour_sample": "Behaviour Sample",
    }.get(event_type, (event_type or "Activity").replace("_", " ").title())


def _event_icon(event_type):
    return {
        "login": "bi-box-arrow-in-right",
        "transaction": "bi-currency-rupee",
        "data_export": "bi-file-earmark-arrow-down",
        "step_up": "bi-shield-check",
        "page_nav": "bi-geo-alt",
        "account_recovery": "bi-key",
        "behaviour_sample": "bi-activity",
    }.get(event_type, "bi-activity")


def _action_color(action):
    return {
        "allow": "success",
        "monitor": "warning",
        "stepup": "warning",
        "block": "danger",
    }.get(action, "secondary")


def _stepup_outcome_color(outcome):
    return {
        "passed": "success",
        "failed": "danger",
        "timeout": "warning",
        "pending": "warning",
    }.get(outcome, "secondary")


def _recovery_method_for_score(score):
    score = int(score or 0)
    if score <= 40:
        return "otp"
    if score <= 70:
        return "otp"
    if score <= 85:
        return "manual_review"
    return "account_hold"


def _recovery_description(method):
    descriptions = {
        "otp": "A secure code has been sent to your registered mobile number.",
        "manual_review": (
            "For your security, this recovery request requires manual review. "
            "Your bank will contact you through a registered channel."
        ),
        "account_hold": (
            "This recovery attempt has triggered account protection. "
            "Please contact your bank directly using an official support channel."
        ),
    }
    return StepUpOrchestrator.METHOD_DESCRIPTIONS.get(method, descriptions.get(method, "Please complete verification."))


def _clear_recovery_session():
    for key in list(flask_session.keys()):
        if key.startswith("recovery_"):
            flask_session.pop(key, None)


def _recovery_reference():
    user_id = str(flask_session.get("recovery_user_id") or "UNKNOWN")
    return f"TSRCV{user_id[:6].upper()}"


@portal_bp.get("/")
@portal_bp.get("/dashboard")
@portal_login_required
def dashboard():
    user = current_user._get_current_object()
    institution = Institution.query.filter_by(id=user.institution_id).first()
    devices = (
        Device.query.filter_by(
            user_id=user.id,
            institution_id=user.institution_id,
            is_removed=False,
        )
        .order_by(Device.last_seen_at.desc())
        .all()
    )
    devices_count = len(devices)
    trusted_devices_count = len([device for device in devices if device.trust_level == "trusted"])
    suspicious_devices = [device for device in devices if device.trust_level == "suspicious"]
    open_alerts_query = Alert.query.filter_by(
        user_id=user.id,
        institution_id=user.institution_id,
        status="open",
    )
    open_alerts = open_alerts_query.order_by(Alert.created_at.desc()).limit(3).all()
    open_alerts_count = open_alerts_query.count()
    recent_sessions = (
        SessionRecord.query.filter_by(
            user_id=user.id,
            institution_id=user.institution_id,
        )
        .order_by(SessionRecord.started_at.desc())
        .limit(5)
        .all()
    )
    last_session = recent_sessions[0] if recent_sessions else None
    last_login_device_name = last_session.device.device_name if last_session and last_session.device else "Unknown"
    last_login_location = (
        f"{last_session.ip_city}, {last_session.ip_country}"
        if last_session and last_session.ip_city
        else "Unknown location"
    )
    recent_activity = (
        RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id)
        .filter(
            SessionRecord.user_id == user.id,
            SessionRecord.institution_id == user.institution_id,
            RiskEvent.institution_id == user.institution_id,
        )
        .order_by(RiskEvent.evaluated_at.desc())
        .limit(5)
        .all()
    )
    stepup_sessions = [session for session in recent_sessions if session.stepup_triggered]
    stepup_success_rate = 0
    if stepup_sessions:
        passed_count = len([session for session in stepup_sessions if session.stepup_outcome == "passed"])
        stepup_success_rate = int(round((passed_count / len(stepup_sessions)) * 100))

    return render_template(
        "portal/dashboard.html",
        user=user,
        institution=institution,
        risk_score=user.risk_score_current or 0,
        risk_category=user.get_risk_category(),
        risk_color=user.get_risk_color(),
        devices=devices,
        devices_count=devices_count,
        trusted_devices_count=trusted_devices_count,
        suspicious_devices=suspicious_devices,
        open_alerts=open_alerts,
        open_alerts_count=open_alerts_count,
        recent_sessions=recent_sessions,
        last_session=last_session,
        last_login_device_name=last_login_device_name,
        last_login_location=last_login_location,
        recent_activity=recent_activity,
        security_tip=_get_security_tip(user, suspicious_devices, open_alerts_count),
        stepup_success_rate=stepup_success_rate,
        event_display=_event_display,
        event_icon=_event_icon,
        action_color=_action_color,
        body_sdk="active",
    )


@portal_bp.get("/devices")
@portal_login_required
def devices():
    user = current_user._get_current_object()
    trust_order = case(
        (Device.trust_level == "suspicious", 0),
        (Device.trust_level == "new", 1),
        (Device.trust_level == "known", 2),
        (Device.trust_level == "trusted", 3),
        else_=4,
    )
    device_rows = (
        Device.query.filter_by(
            user_id=user.id,
            institution_id=user.institution_id,
            is_removed=False,
        )
        .order_by(trust_order, Device.last_seen_at.desc())
        .all()
    )
    device_counts = {
        "trusted": 0,
        "known": 0,
        "new": 0,
        "suspicious": 0,
    }
    for device in device_rows:
        if device.trust_level in device_counts:
            device_counts[device.trust_level] += 1

    current_device_fingerprint = DeviceIntelligenceService.extract_fingerprint_from_request(request)
    return render_template(
        "portal/devices.html",
        devices=device_rows,
        device_counts=device_counts,
        rename_form=DeviceNameForm(),
        current_device_fingerprint=current_device_fingerprint,
    )


@portal_bp.post("/devices/<device_id>/remove")
@portal_login_required
def device_remove(device_id):
    user = current_user._get_current_object()
    device = Device.query.filter_by(
        id=device_id,
        user_id=user.id,
        institution_id=user.institution_id,
        is_removed=False,
    ).first()
    if not device:
        flash("Device not found or permission denied.", "error")
        return redirect(url_for("portal.devices"))

    success, message = DeviceIntelligenceService.mark_device_removed(device_id, user.id)
    if success:
        AuditLogger.log_from_request(user, "device.remove", "device", device_id, {"device_id": device_id})
        flash("Device removed successfully. It will need to verify again on next login.", "success")
    else:
        flash(message, "error")
    return redirect(url_for("portal.devices"))


@portal_bp.post("/devices/<device_id>/rename")
@portal_login_required
def device_rename(device_id):
    user = current_user._get_current_object()
    form = DeviceNameForm()
    if not form.validate_on_submit():
        flash("Please provide a valid device name.", "error")
        return redirect(url_for("portal.devices"))

    if form.device_id.data and form.device_id.data != device_id:
        flash("Device rename request could not be verified.", "error")
        return redirect(url_for("portal.devices"))

    device = Device.query.filter_by(
        id=device_id,
        user_id=user.id,
        institution_id=user.institution_id,
        is_removed=False,
    ).first()
    if not device:
        flash("Device not found or permission denied.", "error")
        return redirect(url_for("portal.devices"))

    success, message = DeviceIntelligenceService.rename_device(device_id, user.id, form.device_name.data)
    if success:
        new_name = str(form.device_name.data or "")
        AuditLogger.log_from_request(user, "device.rename", "device", device_id, {"new_name": new_name[:20] + "..."})
        flash("Device renamed successfully.", "success")
    else:
        flash(message, "error")
    return redirect(url_for("portal.devices"))


@portal_bp.get("/activity")
@portal_login_required
def activity():
    user = current_user._get_current_object()
    today = datetime.utcnow().date()
    default_from = today - timedelta(days=30)
    date_from = _date_from_request("date_from") or default_from
    date_to = _date_from_request("date_to") or today

    if date_from > date_to:
        flash("Start date must be before end date.", "warning")
        date_from, date_to = default_from, today
    if date_to - date_from > timedelta(days=90):
        flash("Activity history is limited to a 90 day range.", "warning")
        date_from = date_to - timedelta(days=90)

    date_from_dt = datetime.combine(date_from, time.min)
    date_to_dt = datetime.combine(date_to, time.max)
    channel_options = [
        ("", "All Channels"),
        ("web_browser", "Web Browser"),
        ("mobile_app", "Mobile App"),
        ("api", "API"),
        ("atm", "ATM"),
    ]
    valid_channels = {value for value, _label in channel_options}
    selected_channel = (request.args.get("channel") or "").strip()
    if selected_channel not in valid_channels:
        selected_channel = ""

    query = SessionRecord.query.filter_by(
        user_id=user.id,
        institution_id=user.institution_id,
    ).filter(
        SessionRecord.started_at >= date_from_dt,
        SessionRecord.started_at <= date_to_dt,
    )
    if selected_channel:
        query = query.filter(SessionRecord.channel == selected_channel)
    query = query.order_by(SessionRecord.started_at.desc())
    total_sessions_in_range = query.count()
    pagination = paginate_query(query, page=get_page_from_request(), per_page=20)

    session_events_map = {session.id: [] for session in pagination.items}
    session_ids = list(session_events_map.keys())
    if session_ids:
        events = (
            RiskEvent.query.join(SessionRecord, RiskEvent.session_id == SessionRecord.id)
            .filter(
                RiskEvent.session_id.in_(session_ids),
                RiskEvent.institution_id == user.institution_id,
                SessionRecord.user_id == user.id,
                SessionRecord.institution_id == user.institution_id,
            )
            .order_by(RiskEvent.evaluated_at.desc())
            .all()
        )
        for event in events:
            session_events_map.setdefault(event.session_id, []).append(event)

    return render_template(
        "portal/activity.html",
        pagination=pagination,
        sessions=pagination.items,
        session_events_map=session_events_map,
        channel_options=channel_options,
        selected_channel=selected_channel,
        date_from_str=date_from.isoformat(),
        date_to_str=date_to.isoformat(),
        total_sessions_in_range=total_sessions_in_range,
        risk_category_for_score=_risk_category_for_score,
        risk_color_for_score=_risk_color_for_score,
        channel_label=_channel_label,
        event_display=_event_display,
        action_color=_action_color,
        stepup_outcome_color=_stepup_outcome_color,
    )


@portal_bp.get("/alerts")
@portal_login_required
def alerts():
    user = current_user._get_current_object()
    selected_status = (request.args.get("status") or "all").strip()
    if selected_status not in {"all", "open", "resolved"}:
        selected_status = "all"

    base_query = Alert.query.filter_by(
        user_id=user.id,
        institution_id=user.institution_id,
    )
    query = base_query
    if selected_status != "all":
        query = query.filter(Alert.status == selected_status)

    pagination = paginate_query(
        query.order_by(Alert.created_at.desc()),
        page=get_page_from_request(),
        per_page=15,
    )
    alert_counts = {
        "total": base_query.count(),
        "open": base_query.filter(Alert.status == "open").count(),
        "resolved": base_query.filter(Alert.status == "resolved").count(),
    }

    return render_template(
        "portal/alerts.html",
        pagination=pagination,
        alerts=pagination.items,
        alert_counts=alert_counts,
        selected_status=selected_status,
        form=FlaskForm(),
    )


@portal_bp.post("/alerts/<alert_id>/resolve")
@portal_login_required
def alert_resolve(alert_id):
    user = current_user._get_current_object()
    alert = Alert.query.filter_by(
        id=alert_id,
        user_id=user.id,
        institution_id=user.institution_id,
    ).first_or_404()

    if alert.status != "open":
        flash("This alert has already been resolved.", "info")
        return redirect(url_for("portal.alerts"))

    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    alert.analyst_notes = "Resolved by account holder"
    db.session.commit()
    AuditLogger.log_from_request(user, "alert.customer_resolve", "alert", alert_id)
    flash("Alert marked as resolved.", "success")
    return redirect(url_for("portal.alerts"))


@portal_bp.route("/preferences", methods=["GET", "POST"])
@portal_login_required
def preferences():
    user = current_user._get_current_object()
    if request.method == "POST":
        form = PreferencesForm()
        if form.validate_on_submit():
            threshold = form.transaction_alert_threshold.data
            preferences_data = {
                "preferred_stepup_method": form.preferred_stepup_method.data,
                "email_alerts_enabled": bool(form.email_alerts_enabled.data),
                "sms_alerts_enabled": bool(form.sms_alerts_enabled.data),
                "high_value_transaction_alert": bool(form.high_value_transaction_alert.data),
                "transaction_alert_threshold": float(threshold) if threshold is not None else None,
                "new_device_alert": bool(form.new_device_alert.data),
                "foreign_login_alert": bool(form.foreign_login_alert.data),
                "language": form.language.data,
            }
            _store_user_preferences(user, preferences_data)
            db.session.add(user)
            db.session.commit()
            AuditLogger.log_from_request(user, "preferences.update", "user", user.id)
            flash("Your security preferences have been saved.", "success")
            return redirect(url_for("portal.preferences"))
        return render_template("portal/preferences.html", form=form)

    form = PreferencesForm(data=_load_user_preferences(user))
    return render_template("portal/preferences.html", form=form)


@portal_bp.get("/settings")
@portal_login_required
def settings():
    return redirect(url_for("portal.preferences"))


@portal_bp.route("/recovery/initiate", methods=["GET", "POST"])
def recovery_initiate():
    form = RecoveryInitiateForm()
    if form.validate_on_submit():
        identifier = form.account_identifier.data.strip()
        user = User.query.filter_by(email=identifier.lower()).first()
        if not user:
            user = User.query.filter_by(external_user_id=identifier).first()

        ip_address = get_client_ip(request)
        ip_info = get_ip_info(ip_address)
        risk_score = 50
        if user:
            result = ContinuousRiskEngine.evaluate(
                user_id=user.id,
                session_id=None,
                event_type="account_recovery",
                context_dict={
                    "ip_address": ip_address,
                    "ip_country": ip_info.get("country"),
                    "ip_city": ip_info.get("city"),
                    "channel": "web_browser",
                    "is_account_recovery": True,
                },
                institution_id=user.institution_id,
            )
            risk_score = result.risk_score

        method = _recovery_method_for_score(risk_score)
        challenge_data = None
        if user and method == "otp":
            challenge_data = StepUpOrchestrator.create_challenge(user.id, "otp", None, user.institution_id)
            if challenge_data:
                NotificationService.send_stepup_notification(user.id, "otp", challenge_data)

        flask_session["recovery_user_id"] = user.id if user else None
        flask_session["recovery_method"] = method
        flask_session["recovery_challenge_id"] = challenge_data.get("challenge_id") if challenge_data else None
        flask_session["recovery_risk_score"] = risk_score
        flask_session["recovery_reason"] = form.recovery_reason.data
        AuditLogger.log(
            actor_type="customer",
            actor_id=user.id if user else None,
            action="account_recovery.initiated",
            institution_id=user.institution_id if user else None,
            details={
                "method": method,
                "risk_score": risk_score,
                "reason": form.recovery_reason.data,
                "ip": ip_address,
            },
        )
        return redirect(url_for("portal.recovery_verify"))

    return render_template("portal/recovery/initiate.html", form=form)


@portal_bp.route("/recovery/verify", methods=["GET", "POST"])
def recovery_verify():
    method = flask_session.get("recovery_method")
    risk_score = int(flask_session.get("recovery_risk_score", 50) or 50)
    challenge_id = flask_session.get("recovery_challenge_id")
    if not method:
        flash("Your recovery session has expired. Please start again.", "error")
        return redirect(url_for("portal.recovery_initiate"))

    form = RecoveryVerifyForm()
    form.challenge_id.data = challenge_id or ""
    if request.method == "POST":
        recovery_user_id = flask_session.get("recovery_user_id")
        if method in {"manual_review", "account_hold"}:
            message = (
                "Your recovery request is under manual review."
                if method == "manual_review"
                else "Your account has been protected. Please contact your bank directly."
            )
            _clear_recovery_session()
            flash(message, "info")
            return redirect(url_for("auth.login"))

        if not recovery_user_id or not challenge_id:
            flash("Your recovery session has expired. Please start again.", "error")
            _clear_recovery_session()
            return redirect(url_for("portal.recovery_initiate"))

        if form.validate_on_submit():
            verification_code = "".join(
                character for character in str(form.verification_code.data or "") if character.isdigit()
            )
            success, _message, _updated_risk_score = StepUpOrchestrator.verify_challenge(
                form.challenge_id.data or challenge_id,
                verification_code,
                recovery_user_id,
            )
            if success:
                AuditLogger.log(
                    actor_type="customer",
                    actor_id=recovery_user_id,
                    action="account_recovery.verified",
                )
                user = User.query.get(recovery_user_id)
                if user:
                    NotificationService.send_account_recovery_status_email(
                        user.id,
                        "verified",
                        user.institution_id,
                    )
                _clear_recovery_session()
                flash(
                    "Your identity has been verified. You can now reset your account access. Please contact your bank branch with this verification confirmation.",
                    "success",
                )
                return redirect(url_for("auth.login"))

            flash("Incorrect verification code. Please try again.", "error")

    return render_template(
        "portal/recovery/verify.html",
        method=method,
        risk_score=risk_score,
        form=form,
        method_description=_recovery_description(method),
        recovery_reference=_recovery_reference(),
    )
