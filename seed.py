"""Seed data for the TrustSphere development database."""

from datetime import datetime, timedelta
import hashlib
import json
import random

from flask import current_app

from app.extensions import db
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


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _random_datetime_within(days, rng):
    return datetime.utcnow() - timedelta(
        days=rng.randint(0, days),
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
    )


def _normal_vector(length, rng):
    values = [rng.random() for _ in range(length)]
    total = sum(value * value for value in values) ** 0.5
    if total == 0:
        return values
    return [round(value / total, 6) for value in values]


def _confidence_from_sessions(count):
    if count < 5:
        return "low"
    if count <= 20:
        return "medium"
    return "high"


def _priority_for_severity(severity, rng):
    if severity == "critical":
        return round(rng.uniform(0.85, 0.99), 2)
    if severity == "high":
        return round(rng.uniform(0.60, 0.84), 2)
    if severity == "medium":
        return round(rng.uniform(0.30, 0.59), 2)
    return round(rng.uniform(0.05, 0.29), 2)


def seed_database():
    """Seed the development database once."""
    if Institution.query.count() > 0:
        print("[Seed] Database already seeded. Skipping.")
        return

    rng = random.Random(2026)
    now = datetime.utcnow()

    platform_raw_key, platform_key_hash = Institution.generate_api_key()
    platform = Institution(
        name="TrustSphere Platform",
        domain="trustsphere.internal",
        api_key_hash=platform_key_hash,
        plan_tier="enterprise",
        is_active=True,
    )
    horizon = Institution(
        name="Horizon Bank India",
        domain="horizonbank.in",
        plan_tier="growth",
        is_active=True,
    )
    horizon.set_config(
        {
            "max_sessions_per_user": 5,
            "alert_email_enabled": True,
            "stepup_enabled": True,
        }
    )
    db.session.add_all([platform, horizon])
    db.session.flush()
    print(f"[Seed] Demo platform API key: {platform_raw_key}")

    admin_specs = [
        (
            current_app.config.get("DEFAULT_ADMIN_EMAIL", "admin@trustsphere.com"),
            current_app.config.get("DEFAULT_ADMIN_PASSWORD", "Admin@TrustSphere2026"),
            "super_admin",
            None,
        ),
        ("priya.sharma@horizonbank.in", "Analyst@Horizon2026", "security_analyst", horizon.id),
        ("rajesh.kumar@horizonbank.in", "Comply@Horizon2026", "compliance_officer", horizon.id),
        ("meera.pillai@horizonbank.in", "ITAdmin@Horizon2026", "it_admin", horizon.id),
        ("auditor@horizonbank.in", "ReadOnly@2026", "read_only", horizon.id),
    ]
    admin_users = []
    for email, password, role, institution_id in admin_specs:
        admin = AdminUser(
            email=email,
            role=role,
            institution_id=institution_id,
            is_active=True,
            mfa_enabled=role in {"super_admin", "it_admin"},
        )
        admin.set_password(password)
        admin_users.append(admin)
    db.session.add_all(admin_users)
    db.session.flush()
    priya = admin_users[1]

    stepup_rules = [
        {
            "risk_min": 31,
            "risk_max": 60,
            "channel": "all",
            "verification_method": "push_notification",
            "timeout_seconds": 120,
        },
        {
            "risk_min": 61,
            "risk_max": 80,
            "channel": "web_browser",
            "verification_method": "otp",
            "timeout_seconds": 60,
        },
        {
            "risk_min": 61,
            "risk_max": 80,
            "channel": "mobile_app",
            "verification_method": "biometric",
            "timeout_seconds": 30,
        },
        {
            "risk_min": 81,
            "risk_max": 100,
            "channel": "all",
            "verification_method": "video_kyc",
            "timeout_seconds": 300,
        },
    ]
    policy = RiskPolicy(
        institution_id=horizon.id,
        policy_name="Horizon Bank Default Policy",
        threshold_low=30,
        threshold_medium=60,
        threshold_high=80,
        stepup_rules=json.dumps(stepup_rules),
        channel_policies=json.dumps(
            {
                "mobile_app": {"biometric_preferred": True},
                "api": {"service_token_required": True},
                "atm": {"card_present_required": True},
            }
        ),
        ml_weight_config=json.dumps(
            {
                "device_trust": 0.25,
                "geo_velocity": 0.20,
                "behavioural_deviation": 0.25,
                "transaction_anomaly": 0.20,
                "network_reputation": 0.10,
            }
        ),
        is_active=True,
        activated_at=now,
        created_by=priya.id,
    )
    db.session.add(policy)
    db.session.flush()

    names = [
        "Aarav Mehta",
        "Vivaan Reddy",
        "Aditya Nair",
        "Vihaan Iyer",
        "Arjun Menon",
        "Sai Krishnan",
        "Reyansh Gupta",
        "Ayaan Khan",
        "Krishna Rao",
        "Ishaan Bose",
        "Shaurya Sinha",
        "Atharv Desai",
        "Ananya Sharma",
        "Diya Patel",
        "Myra Singh",
        "Ira Joshi",
        "Aadhya Kulkarni",
        "Saanvi Chatterjee",
        "Prisha Verma",
        "Kavya Pillai",
        "Riya Malhotra",
        "Anika Bhat",
        "Meera Subramanian",
        "Tara Banerjee",
        "Nandini Shah",
        "Neha Kapoor",
        "Pooja Narayan",
        "Sneha Mukherjee",
        "Rohan Khanna",
        "Karan Bansal",
        "Nikhil Agarwal",
        "Rahul Jain",
        "Siddharth Rao",
        "Manav Chawla",
        "Kabir Arora",
        "Priyanka Dutta",
        "Rajesh Kumar",
        "Meera Pillai",
        "Vikram Sethi",
        "Anil Thomas",
        "Suresh Nambiar",
        "Lakshmi Raman",
        "Farhan Ali",
        "Devika Menon",
        "Amitabh Sen",
        "Rakesh Yadav",
        "Sunita Rao",
        "Harish Bhatia",
        "Geeta Nair",
        "Pranav Saxena",
    ]
    user_types = ["customer"] * 35 + ["employee"] * 12 + ["admin"] * 3
    risk_scores = (
        [rng.randint(10, 35) for _ in range(30)]
        + [rng.randint(36, 65) for _ in range(12)]
        + [rng.randint(66, 85) for _ in range(6)]
        + [rng.randint(86, 98) for _ in range(2)]
    )
    suspended_indexes = {8, 40, 48}
    users = []
    customer_number = 10001
    employee_number = 1001
    for index, name in enumerate(names):
        user_type = user_types[index]
        if user_type == "customer":
            external_id = f"HB-CUST-{customer_number:05d}"
            customer_number += 1
        else:
            external_id = f"HB-EMP-{employee_number:04d}"
            employee_number += 1
        user = User(
            institution_id=horizon.id,
            external_user_id=external_id,
            user_type=user_type,
            display_name=name,
            email=f"user{index + 1}@horizonbank.in",
            phone=f"+9198000{index + 1000}",
            risk_score_current=risk_scores[index],
            risk_score_updated_at=_random_datetime_within(30, rng),
            is_suspended=index in suspended_indexes,
            created_at=_random_datetime_within(365, rng),
            last_active_at=_random_datetime_within(30, rng),
        )
        # Set a default password for seeded accounts to allow sign in during development
        if user.user_type == "customer":
            user.set_password("TestCustomer@123")
        elif user.user_type == "employee":
            user.set_password("TestEmployee@123")
        else:
            user.set_password("AdminUser@Trust2026")
        users.append(user)
    db.session.add_all(users)
    db.session.flush()

    customer_users = [user for user in users if user.user_type == "customer"]
    profile_counts = [3, 8, 15, 25, 32]
    behavioural_profiles = []
    for user, count in zip(customer_users[:5], profile_counts):
        profile = BehaviouralProfile(
            user_id=user.id,
            profile_version=1,
            training_sessions_count=count,
            confidence_level=_confidence_from_sessions(count),
            is_active=True,
            created_at=_random_datetime_within(180, rng),
            updated_at=_random_datetime_within(30, rng),
        )
        profile.set_vector("typing_rhythm_vector", _normal_vector(50, rng))
        profile.set_vector("mouse_pattern_vector", _normal_vector(40, rng))
        db.session.add(profile)
        db.session.flush()
        user.behavioural_profile_id = profile.id
        behavioural_profiles.append(profile)

    trust_levels = ["trusted"] * 15 + ["known"] * 10 + ["new"] * 7 + ["suspicious"] * 3
    device_types = ["mobile"] * 20 + ["desktop"] * 10 + ["tablet"] * 5
    os_values = ["iOS", "Android", "Windows", "macOS", "Linux"]
    browser_values = ["Chrome", "Safari", "Firefox", "Edge", "Samsung Browser"]
    devices = []
    for index in range(35):
        user = users[index % 20]
        first_seen = _random_datetime_within(180, rng)
        last_seen = first_seen + timedelta(days=rng.randint(0, 120), hours=rng.randint(1, 20))
        device = Device(
            user_id=user.id,
            institution_id=horizon.id,
            device_fingerprint_hash=_sha256(f"{user.id}:device:{index}:horizon"),
            device_name=f"{device_types[index].title()} {index + 1}",
            device_type=device_types[index],
            os_family=os_values[index % len(os_values)],
            browser_family=browser_values[index % len(browser_values)],
            trust_level=trust_levels[index],
            is_rooted=index in {28, 33},
            is_emulator=index == 34,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            is_removed=index in {6, 18, 29},
        )
        devices.append(device)
    db.session.add_all(devices)
    db.session.flush()

    channels = ["web_browser"] * 30 + ["mobile_app"] * 20 + ["api"] * 8 + ["atm"] * 2
    countries = ["IN"] * 54 + ["US"] * 3 + ["GB"] * 2 + ["CN"]
    cities_by_country = {
        "IN": ["Mumbai", "Delhi", "Bengaluru", "Chennai", "Hyderabad", "Pune", "Kochi"],
        "US": ["New York", "San Francisco", "Chicago"],
        "GB": ["London", "Manchester"],
        "CN": ["Shanghai"],
    }
    peak_scores = [rng.randint(10, 45) for _ in range(47)] + [rng.randint(71, 89) for _ in range(10)] + [
        rng.randint(91, 98) for _ in range(3)
    ]
    stepup_outcomes = ["passed"] * 8 + ["failed"] * 2 + ["timeout"] * 2
    sessions = []
    for index in range(60):
        user = users[index % 30]
        user_devices = [device for device in devices if device.user_id == user.id]
        device = user_devices[0] if user_devices else None
        started_at = _random_datetime_within(90, rng)
        is_active = index >= 55
        ended_at = None if is_active else started_at + timedelta(minutes=rng.randint(8, 240))
        stepup_triggered = index < 12
        peak = peak_scores[index]
        initial = rng.randint(10, 40)
        final = max(5, peak - rng.randint(0, 25)) if stepup_triggered else min(peak, initial + rng.randint(0, 12))
        country = countries[index]
        city = rng.choice(cities_by_country[country])
        session_record = SessionRecord(
            user_id=user.id,
            device_id=device.id if device else None,
            institution_id=horizon.id,
            ip_address=f"49.36.{rng.randint(1, 254)}.0",
            ip_country=country,
            ip_city=city,
            channel=channels[index],
            session_token_hash=_sha256(f"session:{index}:{user.id}"),
            risk_score_initial=initial,
            risk_score_peak=peak,
            risk_score_final=final,
            stepup_triggered=stepup_triggered,
            stepup_outcome=stepup_outcomes[index] if stepup_triggered else "none",
            started_at=started_at,
            ended_at=ended_at,
            is_flagged=index in {7, 19, 48, 59},
        )
        sessions.append(session_record)
    db.session.add_all(sessions)
    db.session.flush()

    event_types = ["login"] * 15 + ["transaction"] * 10 + ["page_nav"] * 8 + ["data_export"] * 4 + ["step_up"] * 3
    actions = ["allow"] * 25 + ["monitor"] * 8 + ["stepup"] * 5 + ["block"] * 2
    risk_events = []
    for index in range(40):
        session_record = sessions[index % 20]
        before = rng.randint(10, 75)
        after = min(100, before + rng.randint(-8, 32))
        factors = {
            "device_trust": rng.randint(5, 90),
            "geo_anomaly": rng.randint(0, 75),
            "network_risk": rng.randint(0, 50),
            "behavioural_deviation": rng.randint(0, 85),
            "transaction_anomaly": rng.randint(0, 70),
            "time_pattern": rng.randint(0, 35),
        }
        event = RiskEvent(
            session_id=session_record.id,
            institution_id=horizon.id,
            event_type=event_types[index],
            risk_score_before=before,
            risk_score_after=after,
            contributing_factors=json.dumps(factors),
            cre_response_action=actions[index],
            event_metadata=json.dumps(
                {
                    "channel": session_record.channel,
                    "city": session_record.ip_city,
                    "amount_inr": rng.randint(500, 250000)
                    if event_types[index] == "transaction"
                    else None,
                }
            ),
            evaluated_at=session_record.started_at + timedelta(minutes=rng.randint(0, 60)),
            processing_ms=rng.randint(20, 180),
        )
        risk_events.append(event)
    db.session.add_all(risk_events)
    db.session.flush()

    alert_type_distribution = (
        ["ato_attempt"] * 20
        + ["insider_anomaly"] * 15
        + ["new_device"] * 12
        + ["impossible_travel"] * 10
        + ["suspicious_behaviour"] * 8
        + ["bulk_export"] * 8
        + ["kyc_fraud"] * 5
        + ["credential_stuffing"] * 2
    )
    severity_distribution = ["critical"] * 5 + ["high"] * 20 + ["medium"] * 35 + ["low"] * 20
    status_distribution = (
        ["open"] * 20
        + ["investigating"] * 10
        + ["resolved"] * 30
        + ["dismissed"] * 15
        + ["false_positive"] * 5
    )
    alert_templates = {
        "ato_attempt": (
            "Account takeover pattern detected after repeated failed logins",
            "The risk engine detected failed authentication attempts followed by a successful login from a new network.",
        ),
        "insider_anomaly": (
            "Employee accessed sensitive customer records outside normal pattern",
            "Privileged activity exceeded the employee baseline and requires analyst review.",
        ),
        "new_device": (
            "New device registered during account recovery flow",
            "A previously unseen device was linked to an account during a sensitive recovery event.",
        ),
        "impossible_travel": (
            "Login from impossible travel location detected",
            "The account appeared in geographically distant locations within an unrealistic travel window.",
        ),
        "suspicious_behaviour": (
            "Behavioural biometric deviation exceeded policy threshold",
            "Typing cadence and interaction timing were inconsistent with the trusted profile.",
        ),
        "bulk_export": (
            "Bulk customer data export outside business hours",
            "A large export volume was observed from an internal banking system after regular business hours.",
        ),
        "kyc_fraud": (
            "KYC application shows document and liveness risk",
            "Document authenticity and applicant liveness signals indicate elevated onboarding fraud risk.",
        ),
        "credential_stuffing": (
            "Credential stuffing pattern detected from new IP cluster",
            "Multiple accounts received login attempts from the same network fingerprint in a short period.",
        ),
    }
    analyst_notes = [
        "Reviewed device history and confirmed this was a known corporate VPN user.",
        "Customer completed step up verification and no further suspicious activity was observed.",
        "Branch manager confirmed the access was part of a scheduled audit request.",
        "Blocked the session and notified the relationship manager for customer outreach.",
    ]
    alerts = []
    for index in range(80):
        alert_type = alert_type_distribution[index]
        severity = severity_distribution[index]
        status = status_distribution[index]
        title, description = alert_templates[alert_type]
        created_at = (
            now - timedelta(hours=rng.randint(1, 23), minutes=rng.randint(0, 59))
            if status == "open" and index < 15
            else _random_datetime_within(45, rng)
        )
        resolved_at = None
        notes = None
        assigned_to = None
        if status == "investigating":
            assigned_to = priya.id
        elif status in {"resolved", "dismissed", "false_positive"}:
            resolved_at = now - timedelta(days=rng.randint(0, 7), hours=rng.randint(0, 23))
            notes = rng.choice(analyst_notes)
        alert = Alert(
            institution_id=horizon.id,
            session_id=sessions[index % len(sessions)].id,
            user_id=users[index % len(users)].id,
            alert_type=alert_type,
            severity=severity,
            ml_priority_score=_priority_for_severity(severity, rng),
            status=status,
            assigned_to=assigned_to,
            auto_action_taken="block" if severity == "critical" else "stepup" if severity == "high" else "none",
            title=title,
            description=description,
            analyst_notes=notes,
            resolved_at=resolved_at,
            created_at=created_at,
        )
        alerts.append(alert)
    db.session.add_all(alerts)
    db.session.flush()

    applicant_names = [
        "Amit Chaudhary",
        "Bhavana Rao",
        "Charu Kapadia",
        "Deepak Menon",
        "Esha Trivedi",
        "Gaurav Suri",
        "Harini Iyer",
        "Imran Sheikh",
        "Jahnavi Reddy",
        "Kunal Mehra",
        "Lavanya Nair",
        "Mohit Batra",
        "Nisha Thomas",
        "Omkar Kulkarni",
        "Parul Shah",
    ]
    document_types = ["pan"] * 8 + ["aadhaar"] * 4 + ["passport"] * 2 + ["driving_licence"]
    onboarding_profiles = (
        [(0.96, 0.95, 0.92, 0.05, False)] * 7
        + [(0.55, 0.60, 0.45, 0.45, False)] * 5
        + [(0.35, 0.30, 0.20, 0.80, True)] * 3
    )
    onboarding_applications = []
    for index in range(15):
        live, doc, behaviour, synthetic, watchlist = onboarding_profiles[index]
        submitted_at = _random_datetime_within(30, rng)
        application = OnboardingApplication(
            institution_id=horizon.id,
            application_ref=f"APP-2026-{index + 100001:06d}",
            applicant_name=applicant_names[index],
            document_type=document_types[index],
            document_number_hash=_sha256(f"document:{index}:horizon"),
            liveness_score=round(max(min(live + rng.uniform(-0.03, 0.03), 0.99), 0.1), 2),
            document_authenticity_score=round(max(min(doc + rng.uniform(-0.03, 0.03), 0.99), 0.1), 2),
            onboarding_behaviour_score=round(max(min(behaviour + rng.uniform(-0.03, 0.03), 0.99), 0.1), 2),
            watchlist_match=watchlist and index in {12, 13},
            watchlist_match_detail=json.dumps(
                {
                    "list": "Sanctions screening",
                    "match_strength": "Potential name and date of birth match",
                    "review_required": True,
                }
            )
            if watchlist and index in {12, 13}
            else None,
            synthetic_identity_risk=synthetic,
            reviewer_id=priya.id if index >= 7 else None,
            reviewer_notes="Manual review completed with document verification follow up."
            if index >= 7
            else None,
            submitted_at=submitted_at,
            decided_at=submitted_at + timedelta(hours=rng.randint(2, 72)) if index != 8 else None,
        )
        application.compute_composite_score()
        onboarding_applications.append(application)
    db.session.add_all(onboarding_applications)
    db.session.flush()

    employee_users = [user for user in users if user.user_type == "employee"]
    roles = [
        "Relationship Manager",
        "System Administrator",
        "Database Admin",
        "Branch Manager",
        "Audit Officer",
    ]
    privilege_levels = ["standard"] * 6 + ["elevated"] * 4 + ["admin"] * 2
    systems = ["CBS-Core", "CRM-System", "Reporting-DB", "Admin-Portal", "Backup-Server"]
    privileged_sessions = []
    for index in range(12):
        anomalous = index in {10, 11}
        started_at = _random_datetime_within(30, rng)
        session_record = PrivilegedSession(
            employee_user_id=employee_users[index % len(employee_users)].id,
            institution_id=horizon.id,
            role=roles[index % len(roles)],
            privilege_level=privilege_levels[index],
            system_accessed=systems[index % len(systems)],
            actions_count=rng.randint(200, 420) if anomalous else rng.randint(5, 50),
            data_records_accessed=rng.randint(1000, 2400) if anomalous else rng.randint(1, 100),
            export_volume_kb=rng.randint(15000, 26000) if index == 11 else rng.randint(0, 500),
            anomaly_flags=json.dumps(
                {"bulk_export": 0.92, "off_hours_access": 0.75, "peer_group_deviation": 0.81}
            )
            if anomalous
            else json.dumps({}),
            risk_score=rng.randint(70, 95) if anomalous else rng.randint(5, 25),
            alert_generated=anomalous,
            started_at=started_at,
            ended_at=None if index in {2, 7, 11} else started_at + timedelta(hours=rng.randint(1, 8)),
        )
        privileged_sessions.append(session_record)
    db.session.add_all(privileged_sessions)
    db.session.flush()

    action_counts = [
        ("login.success", 8),
        ("login.fail", 3),
        ("alert.dismiss", 5),
        ("alert.resolve", 4),
        ("alert.escalate", 2),
        ("policy.update", 1),
        ("user.suspend", 2),
        ("device.remove", 3),
        ("onboarding.approve", 4),
        ("onboarding.reject", 2),
        ("report.generate", 3),
        ("settings.update", 1),
        ("api_key.regenerate", 1),
        ("user.force_stepup", 1),
    ]
    actions = [action for action, count in action_counts for _ in range(count)]
    actor_types = ["admin_user"] * 25 + ["system"] * 10 + ["api"] * 5
    audit_entries = []
    indian_ips = ["49.36.12.0", "103.21.58.0", "106.51.74.0", "122.167.88.0", "157.49.132.0"]
    for index, action in enumerate(actions):
        actor_type = actor_types[index]
        actor = admin_users[index % len(admin_users)] if actor_type == "admin_user" else None
        target_alert = alerts[index % len(alerts)]
        details = {
            "action_index": index + 1,
            "alert_id": target_alert.id if action.startswith("alert.") else None,
            "reason": "False positive for known VPN user" if action == "alert.dismiss" else None,
            "previous_status": "open" if action.startswith("alert.") else None,
        }
        entry = AuditLog(
            institution_id=horizon.id if index % 3 != 0 else None,
            actor_type=actor_type,
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else None,
            action=action,
            target_type="alert"
            if action.startswith("alert.")
            else "user"
            if action.startswith("user.")
            else "policy"
            if action.startswith("policy.")
            else "institution"
            if action.startswith("api_key.")
            else "system",
            target_id=target_alert.id if action.startswith("alert.") else users[index % len(users)].id,
            details=json.dumps(details),
            ip_address=indian_ips[index % len(indian_ips)],
            user_agent="TrustSphere Admin Console",
            created_at=_random_datetime_within(45, rng),
        )
        audit_entries.append(entry)
    db.session.add_all(audit_entries)

    db.session.commit()

    print("[Seed] 2 Institutions")
    print(
        "[Seed] 5 Admin Users "
        f"(Super Admin: {current_app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@trustsphere.com')} / "
        f"{current_app.config.get('DEFAULT_ADMIN_PASSWORD', 'Admin@TrustSphere2026')})"
    )
    print("[Seed] 50 Users")
    print("[Seed] 5 Behavioural Profiles")
    print("[Seed] 35 Devices")
    print("[Seed] 60 Sessions")
    print("[Seed] 40 Risk Events")
    print("[Seed] 80 Alerts")
    print("[Seed] 15 Onboarding Applications")
    print("[Seed] 12 Privileged Sessions")
    print("[Seed] 1 Risk Policy")
    print("[Seed] 40 Audit Log Entries")
    print("[Seed] TrustSphere is ready.")
    print("[Seed] Admin Login: http://localhost:5000/auth/login")
    print(f"[Seed] Email   : {current_app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@trustsphere.com')}")
    print(f"[Seed] Password: {current_app.config.get('DEFAULT_ADMIN_PASSWORD', 'Admin@TrustSphere2026')}")
