"""Versioned REST API blueprint for TrustSphere integrations."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta

from flask import Blueprint, Response, current_app, g, request

from app.extensions import csrf, db
from app.models import Institution, SessionRecord, User
from app.utils.decorators import api_key_required
from app.utils.response import error_response, success_response


api_bp = Blueprint("api", __name__)
csrf.exempt(api_bp)


EVENT_TYPES = {
    "login",
    "transaction",
    "page_nav",
    "config_change",
    "data_export",
    "step_up",
    "behaviour_sample",
}
REPORT_TYPES = {"rbi_report", "alert_summary", "user_risk"}


def _json_body():
    return request.get_json(silent=True) or {}


def _string(value):
    return isinstance(value, str) and bool(value.strip())


def _verify_user(user_id):
    if not _string(user_id):
        return None
    return User.query.filter_by(
        id=user_id.strip(),
        institution_id=g.api_institution.id,
    ).first()


def _parse_report_dates():
    try:
        raw_from = request.args.get("date_from")
        raw_to = request.args.get("date_to")
        if raw_from:
            date_from = datetime.strptime(raw_from, "%Y-%m-%d")
        else:
            date_from = datetime.utcnow() - timedelta(days=30)
        if raw_to:
            parsed_to = datetime.strptime(raw_to, "%Y-%m-%d").date()
            date_to = datetime.combine(parsed_to, time.max)
        else:
            date_to = datetime.utcnow()
        if date_from > date_to:
            return None, None, {"date_range": "date_from must be before date_to"}
        return date_from, date_to, {}
    except ValueError:
        return None, None, {"date": "Dates must use YYYY-MM-DD format"}


@api_bp.post("/risk/evaluate")
@api_key_required
def risk_evaluate():
    """Evaluate risk for a bank supplied user event."""
    data = _json_body()
    errors = {}
    if not _string(data.get("user_id")):
        errors["user_id"] = "user_id is required and must be a non empty string"
    if not _string(data.get("event_type")):
        errors["event_type"] = "event_type is required"
    elif data["event_type"] not in EVENT_TYPES:
        errors["event_type"] = "event_type is not supported"
    if errors:
        return error_response("Validation failed", 422, errors)

    user = _verify_user(data["user_id"])
    if not user:
        return error_response("User not found in this institution", 404)

    session_id = data.get("session_id")
    if session_id:
        session = SessionRecord.query.filter_by(
            id=session_id,
            institution_id=g.api_institution.id,
            user_id=user.id,
        ).first()
        if not session:
            return error_response("Session not found in this institution", 404)

    context_keys = [
        "device_fingerprint_hash",
        "ip_address",
        "ip_country",
        "ip_city",
        "transaction_amount",
        "is_new_beneficiary",
        "behavioural_vector",
        "channel",
        "watchlist_match",
        "stepup_previously_failed",
        "is_account_recovery",
        "export_volume_kb",
    ]
    context = {key: data.get(key) for key in context_keys if key in data}
    context.setdefault("current_hour", datetime.utcnow().hour)

    from app.services.risk_engine import ContinuousRiskEngine

    result = ContinuousRiskEngine.evaluate(
        user_id=user.id,
        session_id=session_id,
        event_type=data["event_type"],
        context_dict=context,
        institution_id=g.api_institution.id,
    )
    return success_response(
        data={
            "risk_score": result.risk_score,
            "risk_category": result.risk_category,
            "contributing_factors": result.contributing_factors,
            "recommended_action": result.recommended_action,
            "processing_ms": result.processing_ms,
            "event_id": result.event_id,
        }
    )


@api_bp.post("/device/register")
@api_key_required
def device_register():
    """Register or refresh a device fingerprint."""
    data = _json_body()
    errors = {}
    if not _string(data.get("user_id")):
        errors["user_id"] = "user_id is required"
    if not _string(data.get("device_fingerprint_hash")):
        errors["device_fingerprint_hash"] = "device_fingerprint_hash is required"
    if errors:
        return error_response("Validation failed", 422, errors)

    user = _verify_user(data["user_id"])
    if not user:
        return error_response("User not found in this institution", 404)

    attributes = {
        key: data.get(key)
        for key in [
            "device_type",
            "os_family",
            "browser_family",
            "user_agent",
            "is_rooted",
            "is_emulator",
            "screen_resolution",
            "hardware_concurrency",
        ]
        if key in data
    }
    from app.services.device_intel import DeviceIntelligenceService

    result = DeviceIntelligenceService.register_or_update_device(
        user_id=user.id,
        institution_id=g.api_institution.id,
        fingerprint_hash=data["device_fingerprint_hash"].strip(),
        attributes_dict=attributes,
    )
    return success_response(data=result)


@api_bp.post("/stepup/initiate")
@api_key_required
def stepup_initiate():
    """Create a step up challenge when policy requires it."""
    data = _json_body()
    errors = {}
    if not _string(data.get("user_id")):
        errors["user_id"] = "user_id is required"
    risk_score = data.get("risk_score")
    if isinstance(risk_score, bool) or not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
        errors["risk_score"] = "risk_score is required and must be an integer from 0 to 100"
    if errors:
        return error_response("Validation failed", 422, errors)

    user = _verify_user(data["user_id"])
    if not user:
        return error_response("User not found in this institution", 404)

    channel = data.get("channel", "web_browser")
    from app.services.notification import NotificationService
    from app.services.stepup_orchestrator import StepUpOrchestrator

    method = StepUpOrchestrator.select_verification_method(
        risk_score,
        channel,
        g.api_institution.id,
    )
    if method is None:
        return success_response(
            data={
                "step_up_required": False,
                "reason": "Risk score below step up threshold",
            }
        )

    challenge_data = StepUpOrchestrator.create_challenge(
        user.id,
        method,
        data.get("session_id"),
        g.api_institution.id,
    )
    if not challenge_data:
        return error_response("Step up challenge could not be created", 500)
    NotificationService.send_stepup_notification(user.id, method, challenge_data)

    return success_response(
        data={
            "step_up_required": True,
            "challenge_id": challenge_data["challenge_id"],
            "method": method,
            "instructions": challenge_data["instructions"],
            "timeout_seconds": challenge_data["timeout_seconds"],
        }
    )


@api_bp.post("/stepup/verify")
@api_key_required
def stepup_verify():
    """Verify a step up challenge."""
    data = _json_body()
    errors = {}
    for field_name in ("challenge_id", "verification_input", "user_id"):
        if not _string(data.get(field_name)):
            errors[field_name] = f"{field_name} is required"
    if errors:
        return error_response("Validation failed", 422, errors)

    user = _verify_user(data["user_id"])
    if not user:
        return error_response("User not found in this institution", 404)

    from app.services.stepup_orchestrator import StepUpOrchestrator

    success, message, updated_risk_score = StepUpOrchestrator.verify_challenge(
        data["challenge_id"],
        data["verification_input"],
        user.id,
    )
    if success and updated_risk_score is not None:
        status = StepUpOrchestrator.get_challenge_status(data["challenge_id"])
        session_id = status.get("session_id")
        if session_id:
            session = SessionRecord.query.filter_by(
                id=session_id,
                institution_id=g.api_institution.id,
                user_id=user.id,
            ).first()
            if session:
                session.stepup_triggered = True
                session.stepup_outcome = "passed"
                session.risk_score_final = updated_risk_score
                db.session.add(session)
                db.session.commit()
        return success_response(
            data={
                "verified": True,
                "updated_risk_score": updated_risk_score,
                "message": message,
            }
        )
    return error_response(message, 400, {"verified": False, "message": message})


@api_bp.post("/alerts/webhook")
@api_key_required
def alerts_webhook():
    """Create an alert from an external bank webhook."""
    data = _json_body()
    errors = {}
    if not _string(data.get("alert_type")):
        errors["alert_type"] = "alert_type is required"
    if not _string(data.get("severity")):
        errors["severity"] = "severity is required"
    elif data["severity"] not in {"low", "medium", "high", "critical"}:
        errors["severity"] = "severity must be low, medium, high, or critical"
    if not _string(data.get("title")):
        errors["title"] = "title is required"
    if errors:
        return error_response("Validation failed", 422, errors)

    user_id = data.get("user_id")
    session_id = data.get("session_id")
    if user_id and not _verify_user(user_id):
        return error_response("User not found in this institution", 404)
    if not user_id and session_id:
        session = SessionRecord.query.filter_by(
            id=session_id,
            institution_id=g.api_institution.id,
        ).first()
        if session:
            user_id = session.user_id

    from app.services.alert_manager import AlertManager

    alert = AlertManager.create_alert(
        institution_id=g.api_institution.id,
        user_id=user_id,
        alert_type=data["alert_type"],
        severity=data["severity"],
        title=data["title"],
        description=data.get("description", ""),
        session_id=session_id,
        auto_action=data.get("auto_action", "none"),
    )
    if not alert:
        return error_response(
            "Alert could not be created. A valid user_id or session_id is required.",
            400,
        )
    return success_response(
        data={
            "alert_id": alert.id,
            "status": "created",
            "ml_priority_score": alert.ml_priority_score,
        }
    )


@api_bp.get("/reports/export")
@api_key_required
def reports_export():
    """Export compliance reports in JSON or CSV format."""
    report_type = request.args.get("report_type")
    output_format = request.args.get("format", "json")
    errors = {}
    if report_type not in REPORT_TYPES:
        errors["report_type"] = "report_type must be rbi_report, alert_summary, or user_risk"
    if output_format not in {"json", "csv"}:
        errors["format"] = "format must be json or csv"
    date_from, date_to, date_errors = _parse_report_dates()
    errors.update(date_errors)
    if errors:
        return error_response("Validation failed", 422, errors)

    from app.services.report_generator import ComplianceReportGenerator

    if report_type == "rbi_report":
        report = ComplianceReportGenerator.generate_rbi_report(
            g.api_institution.id,
            date_from,
            date_to,
        )
    elif report_type == "alert_summary":
        report = ComplianceReportGenerator.generate_alert_summary_report(
            g.api_institution.id,
            date_from,
            date_to,
        )
    else:
        report = ComplianceReportGenerator.generate_user_risk_report(g.api_institution.id)

    if output_format == "csv":
        csv_body = ComplianceReportGenerator.export_to_csv(report, report_type)
        filename = f"trustsphere_{report_type}_{date.today().isoformat()}.csv"
        response = Response(csv_body, content_type="text/csv")
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    return success_response(data=report)


@api_bp.get("/health")
def health():
    """Return platform health information."""
    database_status = "connected"
    try:
        db.session.query(Institution.id).limit(1).all()
    except Exception:
        database_status = "error"
    return success_response(
        data={
            "status": "healthy",
            "platform": "TrustSphere",
            "version": current_app.config.get("PLATFORM_VERSION", "1.0.0"),
            "database": database_status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    )
