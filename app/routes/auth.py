"""Authentication routes for the TrustSphere admin portal."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime
from sqlalchemy import or_

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.extensions import db
from app.forms import ForgotPasswordForm, LoginForm, RegisterForm, ResetPasswordForm
from app.models import AdminUser, Institution, RiskPolicy, User
from app.services import AuditLogger
from app.utils.ip_intel import get_client_ip, get_ip_info
from app.utils.geocode import reverse_geocode


auth_bp = Blueprint("auth", __name__)


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def _load_token(token, salt, max_age):
    try:
        return _serializer().loads(token, salt=salt, max_age=max_age), None
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"


def _safe_next(default):
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return default


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if getattr(current_user, "is_authenticated", False):
        if isinstance(current_user._get_current_object(), User):
            return redirect(url_for("portal.dashboard"))
        return redirect(url_for("admin.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        # Require browser geolocation before attempting authentication
        geo_lat = request.form.get("geo_lat")
        geo_lng = request.form.get("geo_lng")
        if not geo_lat or not geo_lng:
            flash("Please enable location access in your browser to sign in.", "error")
            return render_template("auth/login.html", form=form)

        # Compute best-known IP context and then prefer browser geolocation
        ip_address = get_client_ip(request)
        ip_info = get_ip_info(ip_address)
        try:
            city, country = reverse_geocode(geo_lat, geo_lng)
            if city:
                ip_info["city"] = city
            if country:
                ip_info["country"] = country
        except Exception:
            # Don't block login on reverse geocoding failures
            pass

        identifier = (form.identifier.data or "").strip()
        password = form.password.data

        admin_user = None
        portal_user = None

        if "@" in identifier:
            email = identifier.lower()
            admin_user = AdminUser.query.filter_by(email=email).first()
            if not admin_user:
                portal_user = User.query.filter_by(email=email).first()
        else:
            # Try external id, id (uuid) or display name
            portal_user = (
                User.query.filter(
                    or_(
                        User.external_user_id == identifier,
                        User.id == identifier,
                        User.display_name.ilike(identifier),
                    )
                )
                .first()
            )

        if admin_user:
            # Admin authentication flow
            if admin_user.is_locked:
                remaining = max(int((admin_user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1, 1)
                flash(
                    f"Your account is temporarily locked. Please try again after {remaining} minutes or reset your password.",
                    "error",
                )
                return render_template("auth/login.html", form=form)

            if not admin_user.is_active:
                flash("Your account is inactive. Please contact your administrator.", "error")
                return render_template("auth/login.html", form=form)

            if not admin_user.check_password(password):
                admin_user.increment_failed_login()
                db.session.commit()
                AuditLogger.log_login_failure(identifier, request, "Wrong password")
                flash("Invalid email or password.", "error")
                return render_template("auth/login.html", form=form)

            login_user(admin_user, remember=bool(form.remember_me.data))
            admin_user.last_login_at = datetime.utcnow()
            admin_user.login_ip_last = get_client_ip(request)
            admin_user.failed_login_count = 0
            admin_user.locked_until = None
            db.session.commit()
            AuditLogger.log_login_success(
                admin_user,
                request,
                ip_city=ip_info.get("city"),
                ip_country=ip_info.get("country"),
            )
            flash(f"Welcome back, {admin_user.get_role_display()}.", "success")
            return redirect(_safe_next(url_for("admin.dashboard")))

        if portal_user:
            # Portal user authentication flow (customers and employees)
            if not portal_user.is_active:
                flash("Your account is inactive. Please contact your administrator.", "error")
                return render_template("auth/login.html", form=form)

            if not portal_user.check_password(password):
                AuditLogger.log_login_failure(identifier, request, "Wrong password")
                flash("Invalid credentials.", "error")
                return render_template("auth/login.html", form=form)

            login_user(portal_user, remember=bool(form.remember_me.data))

            # Try to register/update the user's device fingerprint and record a login session.
            try:
                from app.services.device_intel import DeviceIntelligenceService
                from app.services.risk_engine import ContinuousRiskEngine
                from app.models import SessionRecord

                # Extract a server-side fingerprint and simple attributes from headers
                fingerprint = DeviceIntelligenceService.extract_fingerprint_from_request(request)
                ua = request.headers.get("User-Agent", "") or ""
                ua_l = ua.lower()
                device_type = "mobile" if any(x in ua_l for x in ("mobile", "android", "iphone", "ipad")) else "desktop"
                if "windows" in ua_l:
                    os_family = "Windows"
                elif "macintosh" in ua_l or "mac os" in ua_l:
                    os_family = "macOS"
                elif "linux" in ua_l and "android" not in ua_l:
                    os_family = "Linux"
                elif "android" in ua_l:
                    os_family = "Android"
                elif "iphone" in ua_l or "ipad" in ua_l:
                    os_family = "iOS"
                else:
                    os_family = None
                if "chrome" in ua_l and "edg" not in ua_l:
                    browser_family = "Chrome"
                elif "firefox" in ua_l:
                    browser_family = "Firefox"
                elif "safari" in ua_l and "chrome" not in ua_l:
                    browser_family = "Safari"
                elif "edg" in ua_l or "edge" in ua_l:
                    browser_family = "Edge"
                else:
                    browser_family = None

                attributes = {
                    "user_agent": ua,
                    "device_name": f"{browser_family or 'Browser'} on {os_family or 'Device'}",
                    "device_type": device_type,
                    "os_family": os_family,
                    "browser_family": browser_family,
                }

                device_result = DeviceIntelligenceService.register_or_update_device(
                    portal_user.id, portal_user.institution_id, fingerprint, attributes
                )

                # Evaluate a login event so the CRE will create a SessionRecord and RiskEvent
                ip_address = ip_address if "ip_address" in locals() else get_client_ip(request)
                # ip_info may have been updated above from browser geolocation
                context = {
                    "ip_address": ip_address,
                    "ip_country": ip_info.get("country"),
                    "ip_city": ip_info.get("city"),
                    "channel": "web_browser",
                    "device_fingerprint_hash": fingerprint,
                }
                cre_result = ContinuousRiskEngine.evaluate(
                    portal_user.id, None, "login", context, portal_user.institution_id
                )

                # Attach device id to the created session so UI can show device info
                if cre_result and getattr(cre_result, "session_id", None):
                    session = SessionRecord.query.get(cre_result.session_id)
                    if session and device_result and device_result.get("device_id"):
                        session.device_id = device_result.get("device_id")
                        db.session.add(session)
                        db.session.commit()
            except Exception:
                # Don't block login on analytics/device failures
                try:
                    db.session.rollback()
                except Exception:
                    pass

            # Ensure user's last active flag is updated
            portal_user.last_active_at = datetime.utcnow()
            db.session.add(portal_user)
            db.session.commit()
            AuditLogger.log_from_request(
                portal_user,
                "login.success",
                details={"location": f"{ip_info.get('city') or 'Unknown'}, {ip_info.get('country') or 'Unknown'}"},
            )
            flash(f"Welcome back, {portal_user.display_name}.", "success")
            return redirect(_safe_next(url_for("portal.dashboard")))

        AuditLogger.log_login_failure(identifier, request, "Account not found")
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html", form=form)

    return render_template("auth/login.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if getattr(current_user, "is_authenticated", False):
        return redirect(url_for("admin.dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        try:
            raw_api_key, api_key_hash = Institution.generate_api_key()
            institution = Institution(
                name=form.institution_name.data.strip(),
                domain=form.institution_domain.data.strip().lower(),
                api_key_hash=api_key_hash,
                plan_tier=form.plan_tier.data,
                is_active=True,
            )
            db.session.add(institution)
            db.session.flush()

            admin_user = AdminUser(
                institution_id=institution.id,
                email=form.admin_email.data.strip().lower(),
                role="security_analyst",
                is_active=True,
            )
            admin_user.set_password(form.admin_password.data)
            db.session.add(admin_user)
            db.session.flush()

            policy = RiskPolicy(
                institution_id=institution.id,
                policy_name="Default Risk Policy",
                threshold_low=30,
                threshold_medium=60,
                threshold_high=80,
                stepup_rules=json.dumps(
                    [
                        {"risk_min": 0, "risk_max": 30, "channel": "all", "verification_method": "none"},
                        {"risk_min": 31, "risk_max": 60, "channel": "all", "verification_method": "otp"},
                        {"risk_min": 61, "risk_max": 80, "channel": "all", "verification_method": "push_confirm"},
                        {"risk_min": 81, "risk_max": 100, "channel": "all", "verification_method": "manual_review"},
                    ]
                ),
                channel_policies=json.dumps({"web_browser": "standard", "mobile_app": "standard", "api": "strict"}),
                ml_weight_config=json.dumps(
                    {
                        "device": 0.2,
                        "behaviour": 0.25,
                        "network": 0.2,
                        "transaction": 0.2,
                        "account": 0.15,
                    }
                ),
                is_active=True,
                created_by=admin_user.id,
                activated_at=datetime.utcnow(),
            )
            db.session.add(policy)
            db.session.commit()

            from app.tasks.email_tasks import send_verification_email_task

            verify_token = _serializer().dumps(admin_user.id, salt="email-verify-salt")
            send_verification_email_task.delay(admin_user.id, verify_token)

            AuditLogger.log(
                actor_type="system",
                actor_id=admin_user.id,
                action="institution.register",
                institution_id=institution.id,
                details={
                    "institution_name": institution.name,
                    "plan_tier": institution.plan_tier,
                    "api_key_generated": bool(raw_api_key),
                },
            )
            flash(
                "Registration successful. Your TrustSphere account has been created. Please sign in.",
                "success",
            )
            return redirect(url_for("auth.login"))
        except Exception:
            db.session.rollback()
            flash("Registration could not be completed. Please try again.", "error")

    return render_template("auth/register.html", form=form)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = AdminUser.query.filter_by(email=email).first()
        if user and user.is_active:
            token = _serializer().dumps(user.id, salt="password-reset-salt")
            from app.tasks.email_tasks import send_password_reset_email_task

            send_password_reset_email_task.delay(user.id, token)
            AuditLogger.log_password_reset_request(user.email, request)
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html", form=form)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user_id, error = _load_token(token, "password-reset-salt", 3600)
    if error:
        flash("The password reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        admin_user = AdminUser.query.get(user_id)
        if not admin_user:
            flash("The password reset link is invalid or has expired. Please request a new one.", "error")
            return redirect(url_for("auth.forgot_password"))
        admin_user.set_password(form.password.data)
        admin_user.failed_login_count = 0
        admin_user.locked_until = None
        db.session.commit()
        AuditLogger.log_password_reset_complete(admin_user.id, request)
        flash("Your password has been reset successfully. Please sign in with your new password.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form, token=token)


@auth_bp.get("/logout")
def logout():
    if not getattr(current_user, "is_authenticated", False):
        return redirect(url_for("auth.login"))

    user = current_user._get_current_object()
    if isinstance(user, AdminUser):
        AuditLogger.log_logout(user, request)
    elif isinstance(user, User):
        AuditLogger.log_from_request(user, "logout")
    logout_user()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.get("/verify-email/<token>")
def verify_email(token):
    user_id, error = _load_token(token, "email-verify-salt", 86400)
    if error:
        return render_template("auth/verify_email.html", status="expired")

    admin_user = AdminUser.query.get(user_id)
    if not admin_user:
        return render_template("auth/verify_email.html", status="expired")

    if admin_user.is_active:
        return render_template("auth/verify_email.html", status="already_verified")

    admin_user.is_active = True
    db.session.commit()
    AuditLogger.log(
        actor_type="admin",
        actor_id=admin_user.id,
        actor_email=admin_user.email,
        institution_id=admin_user.institution_id,
        action="email.verified",
    )
    return render_template("auth/verify_email.html", status="success")
