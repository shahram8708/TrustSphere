"""TrustSphere seed data - development environment bootstrap."""

from datetime import datetime, timedelta
import hashlib
import json
import math
import uuid

from werkzeug.security import generate_password_hash

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


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _uid():
    return str(uuid.uuid4())


def _sha(text):
    return hashlib.sha256(str(text).encode()).hexdigest()


def _pw(password):
    return generate_password_hash(password, method="pbkdf2:sha256")


def _j(obj):
    return json.dumps(obj)


def _cre_action(score):
    if score <= 30:
        return "allow"
    if score <= 60:
        return "monitor"
    if score <= 80:
        return "stepup"
    return "block"


def _kyc_composite(das, ls, obs, wm, sir):
    """Exact formula from OnboardingApplication.compute_composite_score."""
    s = (
        (1 - das) * 35
        + (1 - ls) * 30
        + (1 - obs) * 20
        + (15 if wm else 0)
    )
    s += sir * 15
    return int(round(min(s, 100)))


def _kyc_decision(score):
    if score < 40:
        return "approve"
    if score <= 70:
        return "manual_review"
    return "reject"


def _unit_norm(vec):
    mag = math.sqrt(sum(v * v for v in vec))
    if mag == 0:
        return vec
    return [round(v / mag, 6) for v in vec]


def _normal_typing_vec():
    base = [150.0, 28.0, 82.0, 95.0, 0.048, 2.4, 1.05, 805.0, 1.48, 0.52]
    vec = [round(base[i % len(base)] + (i % 13) * 0.38, 3) for i in range(50)]
    return _unit_norm(vec)


def _anomalous_typing_vec():
    base = [310.0, 5.5, 220.0, 12.0, 0.55, 9.2, 4.1, 180.0, 0.18, 3.4]
    vec = [round(base[i % len(base)] * (2.8 if i % 2 == 0 else 0.18), 3) for i in range(50)]
    return _unit_norm(vec)


def _normal_mouse_vec():
    base = [0.35, 0.62, 0.18, 0.45, 0.72, 0.28, 0.51, 0.39]
    vec = [round(base[i % len(base)] + (i % 5) * 0.011, 3) for i in range(40)]
    return _unit_norm(vec)


def _normal_touch_vec():
    base = [0.41, 0.55, 0.32, 0.67, 0.48, 0.22, 0.78, 0.35]
    vec = [round(base[i % len(base)] + (i % 7) * 0.008, 3) for i in range(40)]
    return _unit_norm(vec)


def _normal_interaction_vec():
    base = [0.25, 0.48, 0.61, 0.33, 0.57, 0.42]
    vec = [round(base[i % len(base)] + (i % 4) * 0.014, 3) for i in range(30)]
    return _unit_norm(vec)


def _factors_for_score(score, ev_type="page_nav"):
    r = score / 100.0
    return {
        "device_trust": round(min(100.0, r * 100 * 0.26 + 2.0), 2),
        "behavioural_deviation": round(min(100.0, r * 100 * 0.21 + 1.5), 2),
        "geo_velocity": round(min(100.0, r * 100 * 0.16 + 1.0), 2),
        "network_reputation": round(min(100.0, r * 100 * 0.15 + 1.0), 2),
        "transaction_anomaly": round(min(100.0, r * 100 * 0.14 + 1.0) if ev_type == "transaction" else 0.0, 2),
        "time_pattern": round(min(100.0, r * 100 * 0.08 + 0.5), 2),
    }


def _write_audit(institution_id, actor_type, actor_id, actor_email,
                 action, target_type, target_id, details, ip, ua, ts):
    """Create and immediately commit a single immutable audit log entry."""
    AuditLog.log(
        actor_type=actor_type,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        institution_id=institution_id,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        details=details if isinstance(details, dict) else {},
        ip_address=ip,
        user_agent=ua,
    )


UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
UA_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
UA_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
UA_ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
UA_SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"


# ---------------------------------------------------------------------------
# seed_database
# ---------------------------------------------------------------------------

def seed_database():
    """Populate the database with realistic demo data. Idempotent."""
    if Institution.query.count() > 0:
        return

    NOW = datetime.utcnow()

    # ======================================================================
    # PHASE 1 - Institutions
    # ======================================================================

    HFB_RAW_KEY = "hfb_live_sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    AFS_RAW_KEY = "afs_live_sk_z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4"
    NDB_RAW_KEY = "ndb_live_sk_b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8"

    hfb_id = _uid()
    afs_id = _uid()
    ndb_id = _uid()

    hfb = Institution(
        id=hfb_id,
        name="Horizon Federal Bank",
        domain="horizonfederal.in",
        api_key_hash=_sha(HFB_RAW_KEY),
        plan_tier="starter",
        is_active=True,
        config_json=_j({
            "max_users": 5000,
            "features": ["risk_scoring", "kyc", "alerts"],
            "alert_email": "security@horizonfederal.in",
            "timezone": "Asia/Kolkata",
            "report_frequency": "weekly",
        }),
        created_at=NOW - timedelta(days=87),
        updated_at=NOW - timedelta(days=2),
    )

    afs = Institution(
        id=afs_id,
        name="Apex Fintech Solutions",
        domain="apexfintech.in",
        api_key_hash=_sha(AFS_RAW_KEY),
        plan_tier="growth",
        is_active=True,
        config_json=_j({
            "max_users": 25000,
            "features": ["risk_scoring", "kyc", "alerts", "pam", "reports"],
            "alert_email": "soc@apexfintech.in",
            "timezone": "Asia/Kolkata",
            "ml_model_version": "v2.4",
            "report_frequency": "daily",
        }),
        created_at=NOW - timedelta(days=74),
        updated_at=NOW - timedelta(days=1),
    )

    ndb = Institution(
        id=ndb_id,
        name="NovaPay Digital Bank",
        domain="novapay.in",
        api_key_hash=_sha(NDB_RAW_KEY),
        plan_tier="enterprise",
        is_active=True,
        config_json=_j({
            "max_users": 500000,
            "features": [
                "risk_scoring", "kyc", "alerts", "pam",
                "reports", "behavioural_biometrics", "compliance",
            ],
            "alert_email": "security-ops@novapay.in",
            "timezone": "Asia/Kolkata",
            "ml_model_version": "v3.1",
            "siem_integration": True,
            "report_frequency": "realtime",
        }),
        created_at=NOW - timedelta(days=61),
        updated_at=NOW - timedelta(hours=3),
    )

    db.session.add_all([hfb, afs, ndb])
    db.session.commit()

    # ======================================================================
    # PHASE 2 - Admin Users
    # ======================================================================

    super_admin_id = _uid()
    super_admin = AdminUser(
        id=super_admin_id,
        institution_id=None,
        email="admin@trustsphere.com",
        password_hash=_pw("Admin@TrustSphere2026"),
        role="super_admin",
        mfa_enabled=True,
        mfa_secret="JBSWY3DPEHPK3PXP",
        last_login_at=NOW - timedelta(hours=2, minutes=14),
        login_ip_last="103.21.244.12",
        failed_login_count=0,
        created_at=NOW - timedelta(days=120),
    )
    super_admin._is_active = True
    db.session.add(super_admin)

    # Horizon Federal Bank admins
    hfb_analyst1_id = _uid()
    hfb_analyst2_id = _uid()
    hfb_compliance_id = _uid()
    hfb_itadmin_id = _uid()
    hfb_readonly_id = _uid()

    def _admin(uid, inst_id, email, pw, role, mfa, mfa_sec, last_login_h, last_login_m, ip, created_days):
        a = AdminUser(
            id=uid,
            institution_id=inst_id,
            email=email,
            password_hash=_pw(pw),
            role=role,
            mfa_enabled=mfa,
            mfa_secret=mfa_sec,
            last_login_at=NOW - timedelta(hours=last_login_h, minutes=last_login_m),
            login_ip_last=ip,
            failed_login_count=0,
            created_at=NOW - timedelta(days=created_days),
        )
        a._is_active = True
        return a

    hfb_analyst1 = _admin(hfb_analyst1_id, hfb_id, "aryan.mehta@horizonfederal.in", "Analyst@HFB2026", "security_analyst", True, "MFRGGZDFMZTWQ2LK", 1, 38, "103.87.4.21", 55)
    hfb_analyst2 = _admin(hfb_analyst2_id, hfb_id, "neha.srivastava@horizonfederal.in", "Analyst2@HFB2026", "security_analyst", False, None, 3, 52, "103.87.4.22", 48)
    hfb_compliance = _admin(hfb_compliance_id, hfb_id, "rajan.pillai@horizonfederal.in", "Compliance@HFB2026", "compliance_officer", False, None, 4, 17, "103.87.4.23", 52)
    hfb_itadmin = _admin(hfb_itadmin_id, hfb_id, "vikram.nair@horizonfederal.in", "ITAdmin@HFB2026", "it_admin", False, None, 5, 8, "103.87.4.24", 50)
    hfb_readonly = _admin(hfb_readonly_id, hfb_id, "sunita.verma@horizonfederal.in", "ReadOnly@HFB2026", "read_only", False, None, 5, 55, "103.87.4.25", 45)

    db.session.add_all([hfb_analyst1, hfb_analyst2, hfb_compliance, hfb_itadmin, hfb_readonly])

    # Apex Fintech Solutions admins
    afs_analyst1_id = _uid()
    afs_analyst2_id = _uid()
    afs_compliance_id = _uid()
    afs_itadmin_id = _uid()
    afs_readonly_id = _uid()

    afs_analyst1 = _admin(afs_analyst1_id, afs_id, "kiran.reddy@apexfintech.in", "Analyst@AFS2026", "security_analyst", False, None, 2, 45, "49.32.18.5", 42)
    afs_analyst2 = _admin(afs_analyst2_id, afs_id, "smita.joshi@apexfintech.in", "Analyst2@AFS2026", "security_analyst", True, "GEZDGNBVGY3TQOJQ", 1, 12, "49.32.18.6", 38)
    afs_compliance = _admin(afs_compliance_id, afs_id, "anil.kumar@apexfintech.in", "Compliance@AFS2026", "compliance_officer", False, None, 3, 33, "49.32.18.7", 35)
    afs_itadmin = _admin(afs_itadmin_id, afs_id, "pradeep.krishnan@apexfintech.in", "ITAdmin@AFS2026", "it_admin", False, None, 4, 47, "49.32.18.8", 33)
    afs_readonly = _admin(afs_readonly_id, afs_id, "meena.patel@apexfintech.in", "ReadOnly@AFS2026", "read_only", False, None, 5, 22, "49.32.18.9", 30)

    db.session.add_all([afs_analyst1, afs_analyst2, afs_compliance, afs_itadmin, afs_readonly])

    # NovaPay Digital Bank admins
    ndb_analyst1_id = _uid()
    ndb_analyst2_id = _uid()
    ndb_compliance_id = _uid()
    ndb_itadmin_id = _uid()
    ndb_readonly_id = _uid()

    ndb_analyst1 = _admin(ndb_analyst1_id, ndb_id, "rohit.sharma@novapay.in", "Analyst@NDB2026", "security_analyst", False, None, 2, 5, "117.96.12.41", 40)
    ndb_analyst2 = _admin(ndb_analyst2_id, ndb_id, "deepika.iyer@novapay.in", "Analyst2@NDB2026", "security_analyst", False, None, 1, 48, "117.96.12.42", 37)
    ndb_compliance = _admin(ndb_compliance_id, ndb_id, "suresh.venkataraman@novapay.in", "Compliance@NDB2026", "compliance_officer", True, "MNQWC3BANFXHG5DF", 3, 28, "117.96.12.43", 35)
    ndb_itadmin = _admin(ndb_itadmin_id, ndb_id, "alok.bose@novapay.in", "ITAdmin@NDB2026", "it_admin", False, None, 4, 15, "117.96.12.44", 32)
    ndb_readonly = _admin(ndb_readonly_id, ndb_id, "kavita.malhotra@novapay.in", "ReadOnly@NDB2026", "read_only", False, None, 5, 38, "117.96.12.45", 28)

    db.session.add_all([ndb_analyst1, ndb_analyst2, ndb_compliance, ndb_itadmin, ndb_readonly])
    db.session.commit()

    # ======================================================================
    # PHASE 3 - Risk Policies
    # ======================================================================

    STEPUP_RULES = _j([
        {"risk_min": 41, "risk_max": 60, "channel": "all", "verification_method": "push_notification"},
        {"risk_min": 61, "risk_max": 80, "channel": "all", "verification_method": "otp"},
        {"risk_min": 81, "risk_max": 100, "channel": "all", "verification_method": "video_kyc"},
    ])
    STRICT_STEPUP_RULES = _j([
        {"risk_min": 36, "risk_max": 55, "channel": "all", "verification_method": "otp"},
        {"risk_min": 56, "risk_max": 75, "channel": "all", "verification_method": "otp"},
        {"risk_min": 76, "risk_max": 100, "channel": "all", "verification_method": "video_kyc"},
    ])
    CHANNEL_POLICIES = _j({
        "web_browser": {"session_timeout_minutes": 30, "max_stepup_attempts": 3},
        "mobile_app": {"session_timeout_minutes": 60, "biometric_preferred": True},
        "api": {"stepup_always": False, "jwt_expiry_minutes": 60},
        "atm": {"stepup_on_high_amount": True, "high_amount_threshold_inr": 25000},
    })
    HFB_ML = _j({"device_trust": 0.26, "behavioural_deviation": 0.21, "geo_velocity": 0.16, "network_reputation": 0.15, "transaction_anomaly": 0.14, "time_pattern": 0.08})
    AFS_ML = _j({"device_trust": 0.24, "behavioural_deviation": 0.23, "geo_velocity": 0.16, "network_reputation": 0.15, "transaction_anomaly": 0.13, "time_pattern": 0.09})
    NDB_ML = _j({"device_trust": 0.25, "behavioural_deviation": 0.22, "geo_velocity": 0.15, "network_reputation": 0.14, "transaction_anomaly": 0.15, "time_pattern": 0.09})

    hfb_policy1_id = _uid()
    hfb_policy2_id = _uid()
    afs_policy1_id = _uid()
    afs_policy2_id = _uid()
    ndb_policy1_id = _uid()
    ndb_policy2_id = _uid()

    policies = [
        RiskPolicy(id=hfb_policy1_id, institution_id=hfb_id, policy_name="HFB Standard Risk Policy v2", threshold_low=30, threshold_medium=60, threshold_high=80, stepup_rules=STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=HFB_ML, is_active=True, created_by=hfb_itadmin_id, created_at=NOW - timedelta(days=45), activated_at=NOW - timedelta(days=44)),
        RiskPolicy(id=hfb_policy2_id, institution_id=hfb_id, policy_name="HFB High Security Policy v3 (Draft)", threshold_low=25, threshold_medium=55, threshold_high=75, stepup_rules=STRICT_STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=HFB_ML, is_active=False, created_by=hfb_itadmin_id, created_at=NOW - timedelta(days=3), activated_at=None),
        RiskPolicy(id=afs_policy1_id, institution_id=afs_id, policy_name="AFS Adaptive Risk Policy v1", threshold_low=30, threshold_medium=60, threshold_high=80, stepup_rules=STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=AFS_ML, is_active=True, created_by=afs_itadmin_id, created_at=NOW - timedelta(days=38), activated_at=NOW - timedelta(days=37)),
        RiskPolicy(id=afs_policy2_id, institution_id=afs_id, policy_name="AFS Zero Trust Experimental (Draft)", threshold_low=20, threshold_medium=50, threshold_high=70, stepup_rules=STRICT_STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=AFS_ML, is_active=False, created_by=afs_itadmin_id, created_at=NOW - timedelta(days=5), activated_at=None),
        RiskPolicy(id=ndb_policy1_id, institution_id=ndb_id, policy_name="NovaPay Enterprise Risk Engine Policy v3", threshold_low=30, threshold_medium=60, threshold_high=80, stepup_rules=STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=NDB_ML, is_active=True, created_by=ndb_itadmin_id, created_at=NOW - timedelta(days=35), activated_at=NOW - timedelta(days=34)),
        RiskPolicy(id=ndb_policy2_id, institution_id=ndb_id, policy_name="NovaPay DPDP Compliance Policy (Draft)", threshold_low=28, threshold_medium=58, threshold_high=78, stepup_rules=STEPUP_RULES, channel_policies=CHANNEL_POLICIES, ml_weight_config=NDB_ML, is_active=False, created_by=ndb_itadmin_id, created_at=NOW - timedelta(days=1), activated_at=None),
    ]
    db.session.add_all(policies)
    db.session.commit()

    # ======================================================================
    # PHASE 4 - Users
    # ======================================================================

    def _make_user(uid, inst_id, ext_id, utype, name, email, phone, risk, created_days,
                   last_active_h=None, suspended=False, locked_minutes=None):
        lu = NOW - timedelta(hours=last_active_h) if last_active_h is not None else None
        lk = NOW + timedelta(minutes=locked_minutes) if locked_minutes else None
        u = User(
            id=uid,
            institution_id=inst_id,
            external_user_id=ext_id,
            user_type=utype,
            display_name=name,
            email=email,
            phone=phone,
            password_hash=_pw("User@Password2026"),
            risk_score_current=risk,
            risk_score_updated_at=NOW - timedelta(hours=1),
            failed_login_count=0,
            locked_until=lk,
            post_lock_verification_required=bool(locked_minutes),
            is_suspended=suspended,
            config_json=_j({"preferred_channel": "web_browser", "notifications_enabled": True}),
            behavioural_profile_id=None,
            created_at=NOW - timedelta(days=created_days),
            last_active_at=lu,
        )
        return u

    # ----- HFB Users -----
    hfb_u = {}
    hfb_cust_specs = [
        ("CUST-0000001", "customer", "Rajesh Kumar Sharma",    "rajesh.sharma@gmail.com",      "+917891234501", 12,  58, 1,    False, None),
        ("CUST-0000002", "customer", "Priya Suresh Nair",      "priya.nair@gmail.com",         "+919812345602", 18,  52, 0,    False, None),
        ("CUST-0000003", "customer", "Vikram Mehta",           "vikram.mehta@yahoo.in",        "+918923456703", 22,  45, 2,    False, None),
        ("CUST-0000004", "customer", "Ananya Iyer",            "ananya.iyer@gmail.com",        "+917834567804", 15,  40, 3,    False, None),
        ("CUST-0000005", "customer", "Suresh Patel",           "suresh.patel@gmail.com",       "+918945678905", 25,  37, 5,    False, None),
        ("CUST-0000006", "customer", "Deepa Krishnan",         "deepa.krishnan@outlook.com",   "+919756789006", 28,  35, 4,    False, None),
        ("CUST-0000007", "customer", "Rahul Gupta",            "rahul.gupta@gmail.com",        "+918667890107", 20,  30, 6,    False, None),
        ("CUST-0000008", "customer", "Meera Bose",             "meera.bose@gmail.com",         "+917778901208", 24,  28, 8,    False, None),
        ("CUST-0000009", "customer", "Aakash Bhatia",          "aakash.bhatia@hotmail.com",    "+919889012309", 30,  25, 7,    False, None),
        ("CUST-0000010", "customer", "Tanvi Joshi",            "tanvi.joshi@gmail.com",        "+918690123410", 27,  22, 10,   False, None),
        ("CUST-0000011", "customer", "Sanjay Malhotra",        "sanjay.malhotra@gmail.com",    "+917801234511", 45,  20, 4,    False, None),
        ("CUST-0000012", "customer", "Nisha Agarwal",          "nisha.agarwal@gmail.com",      "+919612345612", 52,  18, 3,    False, None),
        ("CUST-0000013", "customer", "Rohan Verma",            "rohan.verma@gmail.com",        "+918423456713", 38,  15, 5,    False, None),
        ("CUST-0000014", "customer", "Pooja Dubey",            "pooja.dubey@yahoo.in",         "+917934567814", 58,  12, 2,    False, None),
        ("CUST-0000015", "customer", "Abhishek Singh",         "abhishek.singh@gmail.com",     "+918845678915", 72,  10, None, False, 45),
        ("CUST-0000016", "customer", "Neha Kapoor",            "neha.kapoor@gmail.com",        "+919956789016", 65,  8,  None, True,  None),
        ("CUST-0000017", "customer", "Siddharth Rao",          "siddharth.rao@gmail.com",      "+917867890117", 88,  6,  1,    False, None),
    ]
    hfb_emp_specs = [
        ("EMP-0000001", "employee", "Nikhil Saxena",   "nikhil.saxena@horizonfederal.in",   "+917812340001", 15, 60, 2,  False, None),
        ("EMP-0000002", "employee", "Amita Desai",     "amita.desai@horizonfederal.in",     "+918923450002", 22, 55, 5,  False, None),
        ("EMP-0000003", "employee", "Ravi Kumar",      "ravi.kumar@horizonfederal.in",      "+919734560003", 28, 50, 6,  False, None),
        ("EMP-0000004", "employee", "Sunita Patel",    "sunita.patel@horizonfederal.in",    "+918645670004", 35, 45, 1,  False, None),
        ("EMP-0000005", "employee", "Arun Tiwari",     "arun.tiwari@horizonfederal.in",     "+917856780005", 18, 40, 8,  False, None),
        ("EMP-0000006", "employee", "Bhavana Nair",    "bhavana.nair@horizonfederal.in",    "+919867890006", 72, 38, 3,  False, None),
    ]
    hfb_users_to_add = []
    for spec in hfb_cust_specs + hfb_emp_specs:
        uid = _uid()
        hfb_u[spec[0]] = uid
        hfb_users_to_add.append(_make_user(uid, hfb_id, spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7], spec[8], spec[9]))
    db.session.add_all(hfb_users_to_add)
    db.session.commit()

    # ----- AFS Users -----
    afs_u = {}
    afs_cust_specs = [
        ("CUST-0000018", "customer", "Kiran Aditi Reddy",     "kiran.reddy@gmail.com",         "+916712345018", 14,  55, 2,    False, None),
        ("CUST-0000019", "customer", "Preethi Narayanan",     "preethi.narayanan@gmail.com",   "+919923456019", 19,  50, 1,    False, None),
        ("CUST-0000020", "customer", "Aditya Patel",          "aditya.patel@gmail.com",        "+918634567020", 23,  47, 3,    False, None),
        ("CUST-0000021", "customer", "Lakshmi Sundaram",      "lakshmi.sundaram@gmail.com",    "+917745678021", 17,  43, 4,    False, None),
        ("CUST-0000022", "customer", "Ganesh Babu",           "ganesh.babu@yahoo.in",          "+918856789022", 26,  39, 5,    False, None),
        ("CUST-0000023", "customer", "Kavya Srinivasan",      "kavya.srinivasan@gmail.com",    "+919667890023", 29,  36, 6,    False, None),
        ("CUST-0000024", "customer", "Arjun Sharma",          "arjun.sharma@gmail.com",        "+916778901024", 21,  32, 7,    False, None),
        ("CUST-0000025", "customer", "Divya Menon",           "divya.menon@gmail.com",         "+917889012025", 16,  29, 9,    False, None),
        ("CUST-0000026", "customer", "Vivek Mishra",          "vivek.mishra@gmail.com",        "+918690123026", 30,  26, 8,    False, None),
        ("CUST-0000027", "customer", "Shruti Desai",          "shruti.desai@outlook.com",      "+919901234027", 28,  23, 11,   False, None),
        ("CUST-0000028", "customer", "Harsh Vardhan",         "harsh.vardhan@gmail.com",       "+916812345028", 47,  20, 3,    False, None),
        ("CUST-0000029", "customer", "Archana Kulkarni",      "archana.kulkarni@gmail.com",    "+917723456029", 55,  18, 2,    False, None),
        ("CUST-0000030", "customer", "Manoj Tiwari",          "manoj.tiwari@gmail.com",        "+918634567030", 42,  16, 4,    False, None),
        ("CUST-0000031", "customer", "Pallavi Deshpande",     "pallavi.deshpande@gmail.com",   "+919545678031", 60,  13, 1,    False, None),
        ("CUST-0000032", "customer", "Vinod Hegde",           "vinod.hegde@gmail.com",         "+916656789032", 68,  11, None, False, 30),
        ("CUST-0000033", "customer", "Padmavathi Rao",        "padmavathi.rao@gmail.com",      "+917767890033", 75,  9,  None, True,  None),
        ("CUST-0000034", "customer", "Rithvik Pillai",        "rithvik.pillai@gmail.com",      "+918878901034", 91,  7,  0,    False, None),
    ]
    afs_emp_specs = [
        ("EMP-0000007", "employee", "Suresh Balakrishnan",  "suresh.balakrishnan@apexfintech.in", "+916712340007", 18, 58, 3, False, None),
        ("EMP-0000008", "employee", "Geetha Subramanian",   "geetha.subramanian@apexfintech.in",  "+917823450008", 24, 52, 5, False, None),
        ("EMP-0000009", "employee", "Praveen Nair",         "praveen.nair@apexfintech.in",         "+918934560009", 32, 47, 7, False, None),
        ("EMP-0000010", "employee", "Shwetha Rao",          "shwetha.rao@apexfintech.in",          "+919745670010", 20, 43, 2, False, None),
        ("EMP-0000011", "employee", "Sandeep Kumar",        "sandeep.kumar@apexfintech.in",        "+916656780011", 16, 40, 9, False, None),
        ("EMP-0000012", "employee", "Jyothi Iyer",          "jyothi.iyer@apexfintech.in",          "+917767890012", 78, 36, 4, False, None),
    ]
    afs_users_to_add = []
    for spec in afs_cust_specs + afs_emp_specs:
        uid = _uid()
        afs_u[spec[0]] = uid
        afs_users_to_add.append(_make_user(uid, afs_id, spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7], spec[8], spec[9]))
    db.session.add_all(afs_users_to_add)
    db.session.commit()

    # ----- NDB Users -----
    ndb_u = {}
    ndb_cust_specs = [
        ("CUST-0000035", "customer", "Rohit Rajesh Sharma",    "rohit.sharma@gmail.com",         "+919912345035", 11,  53, 1,    False, None),
        ("CUST-0000036", "customer", "Deepika Krishnamurthy",  "deepika.krishna@gmail.com",      "+918823456036", 16,  49, 2,    False, None),
        ("CUST-0000037", "customer", "Suresh Nambiar",         "suresh.nambiar@gmail.com",       "+917734567037", 20,  46, 3,    False, None),
        ("CUST-0000038", "customer", "Alok Chatterjee",        "alok.chatterjee@gmail.com",      "+916645678038", 24,  42, 4,    False, None),
        ("CUST-0000039", "customer", "Kavita Deshpande",       "kavita.deshpande@gmail.com",     "+919756789039", 13,  38, 5,    False, None),
        ("CUST-0000040", "customer", "Sushant Yadav",          "sushant.yadav@gmail.com",        "+918867890040", 27,  34, 6,    False, None),
        ("CUST-0000041", "customer", "Ramya Venkatesh",        "ramya.venkatesh@gmail.com",      "+917778901041", 18,  30, 7,    False, None),
        ("CUST-0000042", "customer", "Nilesh Patil",           "nilesh.patil@gmail.com",         "+916689012042", 22,  27, 8,    False, None),
        ("CUST-0000043", "customer", "Jaya Prabhu",            "jaya.prabhu@gmail.com",          "+919900123043", 29,  24, 10,   False, None),
        ("CUST-0000044", "customer", "Manish Agnihotri",       "manish.agnihotri@gmail.com",     "+918811234044", 25,  21, 11,   False, None),
        ("CUST-0000045", "customer", "Bhavesh Modi",           "bhavesh.modi@gmail.com",         "+917722345045", 44,  19, 3,    False, None),
        ("CUST-0000046", "customer", "Rekha Nataraj",          "rekha.nataraj@gmail.com",        "+916633456046", 53,  17, 2,    False, None),
        ("CUST-0000047", "customer", "Prasad Hegde",           "prasad.hegde@gmail.com",         "+919544567047", 40,  15, 4,    False, None),
        ("CUST-0000048", "customer", "Swati Bhatt",            "swati.bhatt@gmail.com",          "+918455678048", 57,  12, 1,    False, None),
        ("CUST-0000049", "customer", "Chiranjeevi Rao",        "chiranjeevi.rao@gmail.com",      "+917366789049", 70,  10, None, False, 25),
        ("CUST-0000050", "customer", "Namita Gokhale",         "namita.gokhale@gmail.com",       "+916877890050", 77,  8,  None, True,  None),
        ("CUST-0000051", "customer", "Rishi Kapoor",           "rishi.kapoor777@gmail.com",      "+919988901051", 93,  6,  0,    False, None),
    ]
    ndb_emp_specs = [
        ("EMP-0000013", "employee", "Varun Reddy",      "varun.reddy@novapay.in",      "+919912340013", 12, 57, 2, False, None),
        ("EMP-0000014", "employee", "Snehal Joshi",     "snehal.joshi@novapay.in",     "+918823450014", 26, 52, 4, False, None),
        ("EMP-0000015", "employee", "Karthik Rajan",    "karthik.rajan@novapay.in",    "+917734560015", 31, 48, 6, False, None),
        ("EMP-0000016", "employee", "Madhuri Desai",    "madhuri.desai@novapay.in",    "+916645670016", 22, 44, 8, False, None),
        ("EMP-0000017", "employee", "Devesh Misra",     "devesh.misra@novapay.in",     "+919756780017", 19, 40, 3, False, None),
        ("EMP-0000018", "employee", "Poornima Shetty",  "poornima.shetty@novapay.in",  "+918867890018", 81, 35, 5, False, None),
    ]
    ndb_users_to_add = []
    for spec in ndb_cust_specs + ndb_emp_specs:
        uid = _uid()
        ndb_u[spec[0]] = uid
        ndb_users_to_add.append(_make_user(uid, ndb_id, spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7], spec[8], spec[9]))
    db.session.add_all(ndb_users_to_add)
    db.session.commit()

    # ======================================================================
    # PHASE 5 - Behavioural Profiles (create then back-link)
    # ======================================================================

    def _make_profile(pid, user_id, sess_count, is_anomalous=False):
        confidence = "low" if sess_count < 5 else ("medium" if sess_count <= 20 else "high")
        tv = _anomalous_typing_vec() if is_anomalous else _normal_typing_vec()
        return BehaviouralProfile(
            id=pid,
            user_id=user_id,
            profile_version=2 if sess_count > 10 else 1,
            typing_rhythm_vector=_j(tv),
            mouse_pattern_vector=_j(_normal_mouse_vec()),
            touch_pattern_vector=_j(_normal_touch_vec()),
            interaction_timing_vector=_j(_normal_interaction_vec()),
            training_sessions_count=sess_count,
            confidence_level=confidence,
            is_active=True,
            created_at=NOW - timedelta(days=30),
            updated_at=NOW - timedelta(hours=2),
        )

    # Profile config: external_id -> (sess_count, anomalous)
    hfb_pc = {
        "CUST-0000001": (35, False), "CUST-0000002": (28, False), "CUST-0000003": (22, False),
        "CUST-0000004": (18, False), "CUST-0000005": (25, False), "CUST-0000006": (30, False),
        "CUST-0000007": (15, False), "CUST-0000008": (20, False), "CUST-0000009": (12, False),
        "CUST-0000010": (9,  False), "CUST-0000011": (14, False), "CUST-0000012": (11, False),
        "CUST-0000013": (7,  False), "CUST-0000014": (5,  False),
        "CUST-0000015": (3,  True),  "CUST-0000016": (2,  True),  "CUST-0000017": (8,  True),
        "EMP-0000001":  (40, False), "EMP-0000002":  (32, False), "EMP-0000003":  (27, False),
        "EMP-0000004":  (21, False), "EMP-0000005":  (16, False), "EMP-0000006":  (4,  True),
    }
    afs_pc = {
        "CUST-0000018": (42, False), "CUST-0000019": (36, False), "CUST-0000020": (25, False),
        "CUST-0000021": (19, False), "CUST-0000022": (30, False), "CUST-0000023": (22, False),
        "CUST-0000024": (17, False), "CUST-0000025": (14, False), "CUST-0000026": (10, False),
        "CUST-0000027": (8,  False), "CUST-0000028": (13, False), "CUST-0000029": (9,  False),
        "CUST-0000030": (6,  False), "CUST-0000031": (4,  False),
        "CUST-0000032": (2,  True),  "CUST-0000033": (3,  True),  "CUST-0000034": (7,  True),
        "EMP-0000007":  (38, False), "EMP-0000008":  (29, False), "EMP-0000009":  (24, False),
        "EMP-0000010":  (18, False), "EMP-0000011":  (11, False), "EMP-0000012":  (5,  True),
    }
    ndb_pc = {
        "CUST-0000035": (45, False), "CUST-0000036": (38, False), "CUST-0000037": (28, False),
        "CUST-0000038": (21, False), "CUST-0000039": (33, False), "CUST-0000040": (26, False),
        "CUST-0000041": (19, False), "CUST-0000042": (15, False), "CUST-0000043": (11, False),
        "CUST-0000044": (8,  False), "CUST-0000045": (16, False), "CUST-0000046": (12, False),
        "CUST-0000047": (7,  False), "CUST-0000048": (5,  False),
        "CUST-0000049": (3,  True),  "CUST-0000050": (2,  True),  "CUST-0000051": (9,  True),
        "EMP-0000013":  (44, False), "EMP-0000014":  (34, False), "EMP-0000015":  (27, False),
        "EMP-0000016":  (21, False), "EMP-0000017":  (14, False), "EMP-0000018":  (4,  True),
    }

    for u_map, pc in [(hfb_u, hfb_pc), (afs_u, afs_pc), (ndb_u, ndb_pc)]:
        profs = []
        pid_map = {}
        for ext_id, (sc, anom) in pc.items():
            pid = _uid()
            uid = u_map[ext_id]
            pid_map[uid] = pid
            profs.append(_make_profile(pid, uid, sc, anom))
        db.session.add_all(profs)
        db.session.commit()
        for uid, pid in pid_map.items():
            user_obj = User.query.get(uid)
            if user_obj:
                user_obj.behavioural_profile_id = pid
                db.session.add(user_obj)
        db.session.commit()

    # ======================================================================
    # PHASE 6 - Devices
    # ======================================================================

    # user_uid -> [device_id, ...]
    u_devs = {}

    def _make_device(uid, inst_id, name, dtype, os_fam, browser, trust, rooted, emulator, first_days, last_hours):
        did = _uid()
        first_seen = NOW - timedelta(days=first_days)
        last_seen = NOW - timedelta(hours=last_hours)
        if last_seen < first_seen:
            last_seen = first_seen + timedelta(hours=2)
        return did, Device(
            id=did, user_id=uid, institution_id=inst_id,
            device_fingerprint_hash=_sha(f"fp:{uid}:{name}:{dtype}"),
            device_name=name, device_type=dtype, os_family=os_fam, browser_family=browser,
            trust_level=trust, is_rooted=rooted, is_emulator=emulator,
            first_seen_at=first_seen, last_seen_at=last_seen, is_removed=False,
        )

    all_devs = []

    # Each entry: ext_id -> [(name, type, os, browser, trust, rooted, emul, first_days, last_hours)]
    hfb_dev_specs = {
        "CUST-0000001": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 55, 1)],
        "CUST-0000002": [("iPhone 14",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 48, 0), ("Chrome on MacBook", "desktop", "macOS", "Chrome", "known", False, False, 20, 3)],
        "CUST-0000003": [("Samsung Galaxy S23",       "mobile",  "Android", "Chrome",  "trusted",    False, False, 42, 2)],
        "CUST-0000004": [("Firefox on Windows",       "desktop", "Windows", "Firefox", "trusted",    False, False, 38, 3), ("iPad Pro",          "tablet",  "iOS",     "Safari",  "known", False, False, 15, 6)],
        "CUST-0000005": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 35, 5)],
        "CUST-0000006": [("iPhone 13",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 33, 4), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "known", False, False, 10, 8)],
        "CUST-0000007": [("Chrome on MacBook",        "desktop", "macOS",   "Chrome",  "trusted",    False, False, 28, 6)],
        "CUST-0000008": [("Android Pixel 7",          "mobile",  "Android", "Chrome",  "trusted",    False, False, 25, 7)],
        "CUST-0000009": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 22, 5), ("Edge on Windows",   "desktop", "Windows", "Edge",    "new",  False, False,  2, 1)],
        "CUST-0000010": [("iPhone 12",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 20, 9)],
        "CUST-0000011": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 18, 3)],
        "CUST-0000012": [("Samsung Galaxy A54",       "mobile",  "Android", "Chrome",  "known",      False, False, 16, 2), ("Firefox on Ubuntu", "desktop", "Linux",   "Firefox", "new",  False, False,  1, 0)],
        "CUST-0000013": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 13, 4)],
        "CUST-0000014": [("iPhone 15",                "mobile",  "iOS",     "Safari",  "known",      False, False, 10, 1)],
        "CUST-0000015": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "suspicious", False, False,  8, 2), ("Unknown Android",   "mobile",  "Android", "Chrome",  "suspicious", True, False, 3, 0)],
        "CUST-0000016": [("iPhone 11 (Emulator)",     "mobile",  "iOS",     "Safari",  "suspicious", False, True,   6, 12)],
        "CUST-0000017": [("Rooted Galaxy S20",        "mobile",  "Android", "Chrome",  "suspicious", True,  False,  5, 1), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "new",  False, False,  1, 0)],
        "EMP-0000001":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 58, 2)],
        "EMP-0000002":  [("MacBook Safari",           "desktop", "macOS",   "Safari",  "trusted",    False, False, 52, 5)],
        "EMP-0000003":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 48, 6)],
        "EMP-0000004":  [("iPhone 14 Pro",            "mobile",  "iOS",     "Safari",  "trusted",    False, False, 43, 1)],
        "EMP-0000005":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 38, 8)],
        "EMP-0000006":  [("Unknown Mobile Device",    "mobile",  "Android", "Chrome",  "suspicious", False, False,  5, 3), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "known", False, False, 15, 6)],
    }
    afs_dev_specs = {
        "CUST-0000018": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 53, 2)],
        "CUST-0000019": [("iPhone 14",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 48, 1), ("Chrome on MacBook", "desktop", "macOS", "Chrome", "known", False, False, 18, 4)],
        "CUST-0000020": [("Samsung Galaxy A53",       "mobile",  "Android", "Chrome",  "trusted",    False, False, 45, 3)],
        "CUST-0000021": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 41, 4)],
        "CUST-0000022": [("Firefox on Windows",       "desktop", "Windows", "Firefox", "trusted",    False, False, 37, 5), ("Android Pixel 6",   "mobile",  "Android", "Chrome",  "known", False, False, 12, 7)],
        "CUST-0000023": [("iPhone 13 Pro",            "mobile",  "iOS",     "Safari",  "trusted",    False, False, 34, 6)],
        "CUST-0000024": [("Chrome on MacBook",        "desktop", "macOS",   "Chrome",  "known",      False, False, 30, 7)],
        "CUST-0000025": [("Samsung Galaxy M32",       "mobile",  "Android", "Chrome",  "trusted",    False, False, 27, 8)],
        "CUST-0000026": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 24, 6), ("Edge on Windows",   "desktop", "Windows", "Edge",    "new",  False, False,  3, 2)],
        "CUST-0000027": [("iPhone 12 Mini",           "mobile",  "iOS",     "Safari",  "trusted",    False, False, 21, 10)],
        "CUST-0000028": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 18, 3)],
        "CUST-0000029": [("Samsung Galaxy S21",       "mobile",  "Android", "Chrome",  "known",      False, False, 16, 2)],
        "CUST-0000030": [("Firefox on Windows",       "desktop", "Windows", "Firefox", "known",      False, False, 14, 4)],
        "CUST-0000031": [("iPhone 15 Pro",            "mobile",  "iOS",     "Safari",  "known",      False, False, 11, 1)],
        "CUST-0000032": [("Android Emulator (Dev)",   "mobile",  "Android", "Chrome",  "suspicious", False, True,   7, 15), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "new",  False, False,  2, 1)],
        "CUST-0000033": [("Rooted Android Device",    "mobile",  "Android", "Chrome",  "suspicious", True,  False,  8, 12)],
        "CUST-0000034": [("iPhone 14 (Jailbroken)",   "mobile",  "iOS",     "Safari",  "suspicious", True,  False,  6,  0), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "new",  False, False,  1, 0)],
        "EMP-0000007":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 56, 3)],
        "EMP-0000008":  [("MacBook Safari",           "desktop", "macOS",   "Safari",  "trusted",    False, False, 50, 5)],
        "EMP-0000009":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 45, 7)],
        "EMP-0000010":  [("iPhone 13",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 41, 2)],
        "EMP-0000011":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 38, 9)],
        "EMP-0000012":  [("Unknown Mobile Device",    "mobile",  "Android", "Chrome",  "suspicious", False, False,  4, 4), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "known", False, False, 14, 7)],
    }
    ndb_dev_specs = {
        "CUST-0000035": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 51, 1)],
        "CUST-0000036": [("iPhone 14",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 46, 2), ("Chrome on MacBook", "desktop", "macOS", "Chrome", "known", False, False, 19, 4)],
        "CUST-0000037": [("Samsung Galaxy S22",       "mobile",  "Android", "Chrome",  "trusted",    False, False, 44, 3)],
        "CUST-0000038": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 40, 4)],
        "CUST-0000039": [("Firefox on Windows",       "desktop", "Windows", "Firefox", "trusted",    False, False, 36, 5)],
        "CUST-0000040": [("iPhone 13",                "mobile",  "iOS",     "Safari",  "trusted",    False, False, 32, 6), ("iPad Air",          "tablet",  "iOS",     "Safari",  "known", False, False, 10, 9)],
        "CUST-0000041": [("Chrome on MacBook",        "desktop", "macOS",   "Chrome",  "known",      False, False, 28, 7)],
        "CUST-0000042": [("Android Pixel 7a",         "mobile",  "Android", "Chrome",  "trusted",    False, False, 25, 8)],
        "CUST-0000043": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 22, 9), ("Edge on Windows",   "desktop", "Windows", "Edge",    "new",  False, False,  4, 3)],
        "CUST-0000044": [("iPhone 12",                "mobile",  "iOS",     "Safari",  "known",      False, False, 19, 10)],
        "CUST-0000045": [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "known",      False, False, 17, 3)],
        "CUST-0000046": [("Samsung Galaxy A33",       "mobile",  "Android", "Chrome",  "known",      False, False, 15, 2)],
        "CUST-0000047": [("Firefox on Ubuntu",        "desktop", "Linux",   "Firefox", "known",      False, False, 13, 4)],
        "CUST-0000048": [("iPhone 15",                "mobile",  "iOS",     "Safari",  "known",      False, False, 10, 1)],
        "CUST-0000049": [("Unknown Android",          "mobile",  "Android", "Chrome",  "suspicious", False, False,  8, 14), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "new",  False, False,  2, 2)],
        "CUST-0000050": [("Rooted Android (Banking)", "mobile",  "Android", "Chrome",  "suspicious", True,  False,  7, 11)],
        "CUST-0000051": [("Android Emulator v2",      "mobile",  "Android", "Chrome",  "suspicious", False, True,   5,  0), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "new",  False, False,  1, 0)],
        "EMP-0000013":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 55, 2)],
        "EMP-0000014":  [("MacBook Safari",           "desktop", "macOS",   "Safari",  "trusted",    False, False, 50, 4)],
        "EMP-0000015":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 46, 6)],
        "EMP-0000016":  [("iPhone 13 Pro",            "mobile",  "iOS",     "Safari",  "trusted",    False, False, 42, 8)],
        "EMP-0000017":  [("Chrome on Windows",        "desktop", "Windows", "Chrome",  "trusted",    False, False, 38, 3)],
        "EMP-0000018":  [("Unknown Mobile Device",    "mobile",  "Android", "Chrome",  "suspicious", False, False,  6, 5), ("Chrome on Windows", "desktop", "Windows", "Chrome",  "known", False, False, 16, 8)],
    }

    for u_map, dev_specs, inst_id in [
        (hfb_u, hfb_dev_specs, hfb_id),
        (afs_u, afs_dev_specs, afs_id),
        (ndb_u, ndb_dev_specs, ndb_id),
    ]:
        for ext_id, specs in dev_specs.items():
            uid = u_map[ext_id]
            u_devs[uid] = []
            for spec in specs:
                did, dev = _make_device(uid, inst_id, *spec)
                u_devs[uid].append(did)
                all_devs.append(dev)

    db.session.add_all(all_devs)
    db.session.commit()

    # ======================================================================
    # PHASE 7 + 8 - Sessions and Risk Events (combined)
    # ======================================================================

    def _get_dev(u_map, ext_id, idx=0):
        uid = u_map[ext_id]
        devs = u_devs.get(uid, [])
        if not devs:
            return None
        return devs[idx] if idx < len(devs) else devs[0]

    def _sess_tok(uid, ts):
        return _sha(f"tok:{uid}:{ts.isoformat()}")

    def _build_events(sess_id, inst_id, started_at, ended_at, chain):
        """
        chain: list of (event_type, score_before, score_after)
        Final entry's score_after must equal session.risk_score_final.
        """
        n = len(chain)
        dur = (ended_at - started_at).total_seconds() if ended_at else (NOW - started_at).total_seconds()
        evs = []
        for i, (etype, sb, sa) in enumerate(chain):
            t_off = dur * (i + 1) / (n + 1)
            ev_ts = started_at + timedelta(seconds=t_off)

            if etype == "step_up":
                action = "stepup"
            elif sa > 80:
                action = "block"
            else:
                action = _cre_action(sa)

            ev = RiskEvent(
                id=_uid(), session_id=sess_id, institution_id=inst_id,
                event_type=etype, risk_score_before=sb, risk_score_after=sa,
                contributing_factors=_j(_factors_for_score(sa, etype)),
                cre_response_action=action,
                event_metadata=_j({"event_source": "cre", "seq": i}),
                evaluated_at=ev_ts, processing_ms=8 + (i * 7 % 38),
            )
            evs.append(ev)
        db.session.add_all(evs)
        db.session.commit()

    def _create_session(sid, u_map, ext_id, dev_idx, inst_id, ip, country, city,
                        channel, ri, rp, rf, stepup, outcome, flagged, start, end, chain):
        uid = u_map[ext_id]
        dev_id = _get_dev(u_map, ext_id, dev_idx)
        sess = SessionRecord(
            id=sid, user_id=uid, device_id=dev_id, institution_id=inst_id,
            ip_address=ip, ip_country=country, ip_city=city, channel=channel,
            session_token_hash=_sess_tok(uid, start),
            risk_score_initial=ri, risk_score_peak=rp, risk_score_final=rf,
            stepup_triggered=stepup, stepup_outcome=outcome,
            started_at=start, ended_at=end, is_flagged=flagged,
        )
        db.session.add(sess)
        db.session.commit()
        _build_events(sid, inst_id, start, end, chain)
        return sess

    # ----------------------------------------------------------------
    # HFB Sessions (35 total: 6 active + 29 closed)
    # ----------------------------------------------------------------

    hfb_s = {}  # key -> session_id for later alert references

    # Active sessions
    sa1 = _uid(); hfb_s["active_low_1"] = sa1
    _create_session(sa1, hfb_u, "CUST-0000001", 0, hfb_id, "103.21.88.12", "IN", "Mumbai", "web_browser", 12, 14, 14, False, "none", False, NOW - timedelta(hours=1, minutes=32), None, [("login", 12, 12), ("page_nav", 12, 13), ("behaviour_sample", 13, 14)])

    sa2 = _uid(); hfb_s["active_low_2"] = sa2
    _create_session(sa2, hfb_u, "CUST-0000002", 0, hfb_id, "117.22.44.15", "IN", "Bengaluru", "mobile_app", 18, 20, 20, False, "none", False, NOW - timedelta(minutes=48), None, [("login", 18, 18), ("behaviour_sample", 18, 19), ("page_nav", 19, 20)])

    sa3 = _uid(); hfb_s["active_medium_1"] = sa3
    _create_session(sa3, hfb_u, "CUST-0000011", 0, hfb_id, "103.78.33.21", "IN", "Delhi", "web_browser", 42, 52, 48, False, "none", False, NOW - timedelta(hours=1, minutes=18), None, [("login", 42, 44), ("page_nav", 44, 48), ("behaviour_sample", 48, 50), ("transaction", 50, 52), ("page_nav", 52, 48)])

    sa4 = _uid(); hfb_s["active_emp_1"] = sa4
    _create_session(sa4, hfb_u, "EMP-0000001", 0, hfb_id, "103.87.4.210", "IN", "Mumbai", "web_browser", 15, 17, 17, False, "none", False, NOW - timedelta(minutes=35), None, [("login", 15, 15), ("page_nav", 15, 16), ("behaviour_sample", 16, 17)])

    sa5 = _uid(); hfb_s["active_medium_2"] = sa5
    _create_session(sa5, hfb_u, "CUST-0000012", 0, hfb_id, "182.64.22.18", "IN", "Pune", "mobile_app", 48, 56, 52, False, "none", False, NOW - timedelta(hours=1, minutes=5), None, [("login", 48, 50), ("behaviour_sample", 50, 53), ("transaction", 53, 56), ("page_nav", 56, 52)])

    sa6 = _uid(); hfb_s["active_critical_1"] = sa6
    _create_session(sa6, hfb_u, "CUST-0000017", 0, hfb_id, "45.83.17.42", "RU", "Moscow", "web_browser", 75, 92, 88, True, "failed", True, NOW - timedelta(hours=1, minutes=52), None, [("login", 75, 78), ("behaviour_sample", 78, 84), ("step_up", 84, 90), ("behaviour_sample", 90, 92), ("page_nav", 92, 88)])

    # Closed sessions - low risk batch
    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000003", "103.45.67.89",  "Chennai",   "web_browser", 18, 22, 20, 24, 45),
        ("CUST-0000004", "49.36.88.12",   "Hyderabad", "web_browser", 15, 18, 16, 20, 32),
        ("CUST-0000005", "103.21.44.55",  "Mumbai",    "web_browser", 22, 26, 24, 18, 38),
        ("CUST-0000006", "117.18.9.3",    "Bengaluru", "mobile_app",  25, 28, 26, 16, 28),
        ("CUST-0000007", "182.74.55.22",  "Kolkata",   "web_browser", 19, 21, 20, 14, 42),
        ("CUST-0000008", "103.88.12.45",  "Delhi",     "web_browser", 22, 25, 23, 12, 35),
        ("CUST-0000009", "49.64.22.11",   "Ahmedabad", "mobile_app",  28, 30, 29, 10, 25),
        ("CUST-0000010", "103.55.33.44",  "Jaipur",    "web_browser", 25, 28, 26,  8, 30),
        ("CUST-0000001", "103.21.88.44",  "Mumbai",    "web_browser", 11, 14, 12,  6, 22),
        ("CUST-0000002", "117.22.44.16",  "Bengaluru", "mobile_app",  16, 19, 17,  4, 28),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago)
        se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, hfb_u, ext_id, 0, hfb_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 1), ("behaviour_sample", ri + 1, mid), ("page_nav", mid, rf)])

    # Closed sessions - medium risk batch
    sc_med1 = _uid(); hfb_s["med_sess_1"] = sc_med1
    ss = NOW - timedelta(hours=22); se = ss + timedelta(minutes=55)
    _create_session(sc_med1, hfb_u, "CUST-0000013", 0, hfb_id, "103.33.88.21", "IN", "Bangalore", "web_browser", 35, 42, 38, False, "none", False, ss, se, [("login", 35, 37), ("behaviour_sample", 37, 40), ("transaction", 40, 42), ("page_nav", 42, 38)])

    sc_med2 = _uid(); hfb_s["med_sess_2"] = sc_med2
    ss = NOW - timedelta(hours=17); se = ss + timedelta(minutes=40)
    _create_session(sc_med2, hfb_u, "CUST-0000014", 0, hfb_id, "49.18.44.77", "IN", "Pune", "mobile_app", 52, 60, 55, False, "none", False, ss, se, [("login", 52, 54), ("transaction", 54, 58), ("behaviour_sample", 58, 60), ("page_nav", 60, 55)])

    sc_med3 = _uid(); hfb_s["atm_sess_1"] = sc_med3
    ss = NOW - timedelta(hours=7); se = ss + timedelta(minutes=18)
    _create_session(sc_med3, hfb_u, "CUST-0000004", 0, hfb_id, "103.99.44.2", "IN", "Hyderabad", "atm", 15, 35, 28, False, "none", False, ss, se, [("login", 15, 20), ("transaction", 20, 35), ("page_nav", 35, 28)])

    sc_med4 = _uid(); hfb_s["api_sess_1"] = sc_med4
    ss = NOW - timedelta(hours=31); se = ss + timedelta(minutes=42)
    _create_session(sc_med4, hfb_u, "CUST-0000005", 0, hfb_id, "103.155.34.8", "IN", "Delhi", "api", 20, 28, 25, False, "none", False, ss, se, [("login", 20, 22), ("transaction", 22, 28), ("page_nav", 28, 25)])

    # Stepup session 1 - passed
    sc_su1 = _uid(); hfb_s["stepup_passed_1"] = sc_su1
    ss = NOW - timedelta(hours=13); se = ss + timedelta(minutes=52)
    _create_session(sc_su1, hfb_u, "CUST-0000012", 0, hfb_id, "103.22.55.44", "IN", "Mumbai", "web_browser", 45, 65, 48, True, "passed", False, ss, se, [("login", 45, 48), ("behaviour_sample", 48, 55), ("transaction", 55, 62), ("step_up", 62, 65), ("page_nav", 65, 55), ("behaviour_sample", 55, 48)])

    # Stepup session 2 - passed
    sc_su2 = _uid(); hfb_s["stepup_passed_2"] = sc_su2
    ss = NOW - timedelta(hours=35); se = ss + timedelta(minutes=38)
    _create_session(sc_su2, hfb_u, "CUST-0000014", 0, hfb_id, "103.22.88.55", "IN", "Chennai", "web_browser", 55, 74, 42, True, "passed", False, ss, se, [("login", 55, 58), ("behaviour_sample", 58, 65), ("transaction", 65, 72), ("step_up", 72, 74), ("page_nav", 74, 55), ("behaviour_sample", 55, 42)])

    # Stepup session 3 - failed, flagged
    sc_su3 = _uid(); hfb_s["stepup_failed_flagged"] = sc_su3
    ss = NOW - timedelta(hours=28); se = ss + timedelta(minutes=15)
    _create_session(sc_su3, hfb_u, "CUST-0000017", 1, hfb_id, "185.220.100.42", "NL", "Amsterdam", "web_browser", 80, 85, 85, True, "failed", True, ss, se, [("login", 80, 83), ("behaviour_sample", 83, 85), ("step_up", 85, 85), ("page_nav", 85, 85)])

    # Flagged session - timeout, suspicious IP
    sc_fl1 = _uid(); hfb_s["flagged_ato_1"] = sc_fl1
    ss = NOW - timedelta(hours=41); se = ss + timedelta(minutes=22)
    _create_session(sc_fl1, hfb_u, "CUST-0000016", 0, hfb_id, "89.187.179.12", "SG", "Singapore", "web_browser", 72, 91, 88, True, "timeout", True, ss, se, [("login", 72, 76), ("behaviour_sample", 76, 82), ("step_up", 82, 88), ("transaction", 88, 91), ("behaviour_sample", 91, 88)])

    # Additional varied closed sessions
    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000001", "103.21.88.14", "Mumbai",    "web_browser", 11, 15, 13, 44, 33),
        ("CUST-0000003", "103.45.67.91", "Chennai",   "web_browser", 18, 24, 21, 38, 28),
        ("CUST-0000006", "117.18.9.5",   "Bengaluru", "mobile_app",  24, 30, 27, 32, 22),
        ("CUST-0000007", "182.74.55.25", "Kolkata",   "web_browser", 19, 22, 20, 27, 18),
        ("CUST-0000008", "103.88.12.47", "Delhi",     "web_browser", 21, 26, 24, 22, 35),
        ("CUST-0000013", "49.88.33.12",  "Bangalore", "web_browser", 33, 40, 36, 15, 40),
        ("EMP-0000002",  "103.87.4.215", "Mumbai",    "web_browser", 20, 24, 22, 11, 28),
        ("EMP-0000003",  "103.87.4.220", "Mumbai",    "web_browser", 25, 28, 26,  9, 32),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago)
        se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, hfb_u, ext_id, 0, hfb_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 2), ("behaviour_sample", ri + 2, mid), ("page_nav", mid, rf)])

    # ----------------------------------------------------------------
    # AFS Sessions (35 total: 6 active + 29 closed)
    # ----------------------------------------------------------------

    afs_s = {}

    sa7 = _uid(); afs_s["active_low_1"] = sa7
    _create_session(sa7, afs_u, "CUST-0000018", 0, afs_id, "49.32.44.11", "IN", "Hyderabad", "web_browser", 14, 16, 16, False, "none", False, NOW - timedelta(hours=1, minutes=28), None, [("login", 14, 14), ("page_nav", 14, 15), ("behaviour_sample", 15, 16)])

    sa8 = _uid(); afs_s["active_low_2"] = sa8
    _create_session(sa8, afs_u, "CUST-0000019", 0, afs_id, "117.55.22.33", "IN", "Chennai", "mobile_app", 19, 21, 21, False, "none", False, NOW - timedelta(minutes=55), None, [("login", 19, 19), ("behaviour_sample", 19, 20), ("page_nav", 20, 21)])

    sa9 = _uid(); afs_s["active_medium_1"] = sa9
    _create_session(sa9, afs_u, "CUST-0000028", 0, afs_id, "49.88.44.21", "IN", "Mumbai", "web_browser", 44, 54, 49, False, "none", False, NOW - timedelta(hours=1, minutes=14), None, [("login", 44, 46), ("behaviour_sample", 46, 50), ("transaction", 50, 54), ("page_nav", 54, 49)])

    sa10 = _uid(); afs_s["active_emp_1"] = sa10
    _create_session(sa10, afs_u, "EMP-0000007", 0, afs_id, "49.32.18.100", "IN", "Hyderabad", "web_browser", 18, 20, 20, False, "none", False, NOW - timedelta(minutes=42), None, [("login", 18, 18), ("page_nav", 18, 19), ("behaviour_sample", 19, 20)])

    sa11 = _uid(); afs_s["active_medium_2"] = sa11
    _create_session(sa11, afs_u, "CUST-0000029", 0, afs_id, "103.45.88.12", "IN", "Bengaluru", "mobile_app", 50, 58, 54, False, "none", False, NOW - timedelta(hours=1, minutes=8), None, [("login", 50, 52), ("behaviour_sample", 52, 55), ("transaction", 55, 58), ("page_nav", 58, 54)])

    sa12 = _uid(); afs_s["active_critical_1"] = sa12
    _create_session(sa12, afs_u, "CUST-0000034", 0, afs_id, "45.83.65.12", "RU", "Saint Petersburg", "web_browser", 78, 94, 91, True, "failed", True, NOW - timedelta(hours=1, minutes=45), None, [("login", 78, 81), ("behaviour_sample", 81, 87), ("step_up", 87, 91), ("behaviour_sample", 91, 94), ("page_nav", 94, 91)])

    # AFS closed sessions
    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000020", "103.22.55.11", "Pune",       "web_browser", 20, 24, 22, 23, 38),
        ("CUST-0000021", "117.33.66.22", "Delhi",      "web_browser", 15, 18, 16, 19, 30),
        ("CUST-0000022", "49.44.88.33",  "Mumbai",     "web_browser", 24, 28, 26, 17, 35),
        ("CUST-0000023", "103.55.22.44", "Bengaluru",  "mobile_app",  27, 30, 28, 15, 25),
        ("CUST-0000024", "182.88.44.55", "Kolkata",    "web_browser", 19, 22, 21, 13, 32),
        ("CUST-0000025", "103.66.11.22", "Ahmedabad",  "mobile_app",  14, 17, 15, 11, 22),
        ("CUST-0000026", "49.77.33.11",  "Pune",       "web_browser", 28, 32, 30,  9, 28),
        ("CUST-0000027", "117.44.55.66", "Chennai",    "web_browser", 25, 29, 27,  7, 24),
        ("CUST-0000018", "49.32.44.14",  "Hyderabad",  "web_browser", 12, 16, 14,  5, 20),
        ("CUST-0000019", "117.55.22.35", "Chennai",    "mobile_app",  17, 21, 19,  3, 18),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago); se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, afs_u, ext_id, 0, afs_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 1), ("behaviour_sample", ri + 1, mid), ("page_nav", mid, rf)])

    afs_med1 = _uid(); afs_s["med_sess_1"] = afs_med1
    ss = NOW - timedelta(hours=21); se = ss + timedelta(minutes=50)
    _create_session(afs_med1, afs_u, "CUST-0000030", 0, afs_id, "103.44.88.22", "IN", "Delhi", "web_browser", 38, 48, 42, False, "none", False, ss, se, [("login", 38, 40), ("behaviour_sample", 40, 44), ("transaction", 44, 48), ("page_nav", 48, 42)])

    afs_med2 = _uid(); afs_s["med_sess_2"] = afs_med2
    ss = NOW - timedelta(hours=16); se = ss + timedelta(minutes=42)
    _create_session(afs_med2, afs_u, "CUST-0000031", 0, afs_id, "49.55.22.11", "IN", "Pune", "mobile_app", 55, 63, 58, False, "none", False, ss, se, [("login", 55, 57), ("transaction", 57, 60), ("behaviour_sample", 60, 63), ("page_nav", 63, 58)])

    afs_atm = _uid(); afs_s["atm_sess_1"] = afs_atm
    ss = NOW - timedelta(hours=8); se = ss + timedelta(minutes=15)
    _create_session(afs_atm, afs_u, "CUST-0000022", 0, afs_id, "103.99.55.3", "IN", "Mumbai", "atm", 22, 38, 30, False, "none", False, ss, se, [("login", 22, 26), ("transaction", 26, 38), ("page_nav", 38, 30)])

    afs_api = _uid(); afs_s["api_sess_1"] = afs_api
    ss = NOW - timedelta(hours=30); se = ss + timedelta(minutes=38)
    _create_session(afs_api, afs_u, "CUST-0000020", 0, afs_id, "49.44.22.8", "IN", "Pune", "api", 18, 26, 22, False, "none", False, ss, se, [("login", 18, 20), ("transaction", 20, 26), ("page_nav", 26, 22)])

    afs_su1 = _uid(); afs_s["stepup_passed_1"] = afs_su1
    ss = NOW - timedelta(hours=12); se = ss + timedelta(minutes=48)
    _create_session(afs_su1, afs_u, "CUST-0000029", 0, afs_id, "103.55.66.33", "IN", "Bengaluru", "web_browser", 48, 68, 44, True, "passed", False, ss, se, [("login", 48, 51), ("behaviour_sample", 51, 58), ("transaction", 58, 64), ("step_up", 64, 68), ("page_nav", 68, 55), ("behaviour_sample", 55, 44)])

    afs_su2 = _uid(); afs_s["stepup_passed_2"] = afs_su2
    ss = NOW - timedelta(hours=34); se = ss + timedelta(minutes=35)
    _create_session(afs_su2, afs_u, "CUST-0000031", 0, afs_id, "103.44.77.55", "IN", "Mumbai", "web_browser", 58, 76, 40, True, "passed", False, ss, se, [("login", 58, 61), ("behaviour_sample", 61, 68), ("transaction", 68, 73), ("step_up", 73, 76), ("page_nav", 76, 58), ("behaviour_sample", 58, 40)])

    afs_su3 = _uid(); afs_s["stepup_failed_flagged"] = afs_su3
    ss = NOW - timedelta(hours=27); se = ss + timedelta(minutes=14)
    _create_session(afs_su3, afs_u, "CUST-0000034", 0, afs_id, "185.220.101.15", "DE", "Frankfurt", "web_browser", 82, 88, 88, True, "failed", True, ss, se, [("login", 82, 84), ("behaviour_sample", 84, 87), ("step_up", 87, 88), ("page_nav", 88, 88)])

    afs_fl1 = _uid(); afs_s["flagged_ato_1"] = afs_fl1
    ss = NOW - timedelta(hours=40); se = ss + timedelta(minutes=20)
    _create_session(afs_fl1, afs_u, "CUST-0000033", 0, afs_id, "89.187.180.33", "SG", "Singapore", "web_browser", 70, 89, 86, True, "timeout", True, ss, se, [("login", 70, 74), ("behaviour_sample", 74, 80), ("step_up", 80, 86), ("transaction", 86, 89), ("behaviour_sample", 89, 86)])

    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000020", "103.22.55.13", "Pune",      "web_browser", 18, 22, 20, 43, 32),
        ("CUST-0000022", "49.44.88.35",  "Mumbai",    "mobile_app",  22, 26, 24, 36, 25),
        ("CUST-0000024", "182.88.44.57", "Kolkata",   "web_browser", 17, 21, 19, 29, 22),
        ("EMP-0000008",  "49.32.18.105", "Hyderabad", "web_browser", 22, 26, 24, 18, 28),
        ("EMP-0000009",  "49.32.18.110", "Hyderabad", "web_browser", 28, 32, 30, 14, 32),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago); se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, afs_u, ext_id, 0, afs_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 2), ("behaviour_sample", ri + 2, mid), ("page_nav", mid, rf)])

    # ----------------------------------------------------------------
    # NDB Sessions (35 total: 6 active + 29 closed)
    # ----------------------------------------------------------------

    ndb_s = {}

    sa13 = _uid(); ndb_s["active_low_1"] = sa13
    _create_session(sa13, ndb_u, "CUST-0000035", 0, ndb_id, "117.96.44.11", "IN", "Mumbai", "web_browser", 11, 13, 13, False, "none", False, NOW - timedelta(hours=1, minutes=25), None, [("login", 11, 11), ("page_nav", 11, 12), ("behaviour_sample", 12, 13)])

    sa14 = _uid(); ndb_s["active_low_2"] = sa14
    _create_session(sa14, ndb_u, "CUST-0000036", 0, ndb_id, "103.21.88.22", "IN", "Bengaluru", "mobile_app", 16, 18, 18, False, "none", False, NOW - timedelta(minutes=52), None, [("login", 16, 16), ("behaviour_sample", 16, 17), ("page_nav", 17, 18)])

    sa15 = _uid(); ndb_s["active_medium_1"] = sa15
    _create_session(sa15, ndb_u, "CUST-0000045", 0, ndb_id, "49.55.44.11", "IN", "Delhi", "web_browser", 41, 50, 46, False, "none", False, NOW - timedelta(hours=1, minutes=20), None, [("login", 41, 43), ("behaviour_sample", 43, 46), ("transaction", 46, 50), ("page_nav", 50, 46)])

    sa16 = _uid(); ndb_s["active_emp_1"] = sa16
    _create_session(sa16, ndb_u, "EMP-0000013", 0, ndb_id, "117.96.12.120", "IN", "Mumbai", "web_browser", 12, 14, 14, False, "none", False, NOW - timedelta(minutes=38), None, [("login", 12, 12), ("page_nav", 12, 13), ("behaviour_sample", 13, 14)])

    sa17 = _uid(); ndb_s["active_medium_2"] = sa17
    _create_session(sa17, ndb_u, "CUST-0000046", 0, ndb_id, "182.55.44.33", "IN", "Hyderabad", "mobile_app", 49, 57, 52, False, "none", False, NOW - timedelta(hours=1, minutes=10), None, [("login", 49, 51), ("behaviour_sample", 51, 54), ("transaction", 54, 57), ("page_nav", 57, 52)])

    sa18 = _uid(); ndb_s["active_critical_1"] = sa18
    _create_session(sa18, ndb_u, "CUST-0000051", 0, ndb_id, "45.83.22.88", "PK", "Karachi", "web_browser", 80, 95, 93, True, "failed", True, NOW - timedelta(hours=1, minutes=48), None, [("login", 80, 83), ("behaviour_sample", 83, 88), ("step_up", 88, 92), ("transaction", 92, 95), ("behaviour_sample", 95, 93)])

    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000037", "103.55.88.22", "Chennai",   "web_browser", 18, 22, 20, 23, 36),
        ("CUST-0000038", "49.66.44.33",  "Kolkata",   "web_browser", 22, 26, 24, 19, 30),
        ("CUST-0000039", "117.77.55.44", "Pune",      "web_browser", 11, 14, 12, 17, 28),
        ("CUST-0000040", "103.88.66.55", "Delhi",     "mobile_app",  25, 29, 27, 15, 24),
        ("CUST-0000041", "49.99.77.66",  "Bengaluru", "web_browser", 16, 20, 18, 13, 32),
        ("CUST-0000042", "182.11.88.77", "Hyderabad", "mobile_app",  20, 24, 22, 11, 22),
        ("CUST-0000043", "103.22.99.88", "Mumbai",    "web_browser", 27, 31, 29,  9, 28),
        ("CUST-0000044", "49.33.11.99",  "Jaipur",    "web_browser", 23, 27, 25,  7, 24),
        ("CUST-0000035", "117.96.44.14", "Mumbai",    "web_browser", 10, 14, 12,  5, 20),
        ("CUST-0000036", "103.21.88.25", "Bengaluru", "mobile_app",  14, 18, 16,  3, 18),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago); se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, ndb_u, ext_id, 0, ndb_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 1), ("behaviour_sample", ri + 1, mid), ("page_nav", mid, rf)])

    ndb_med1 = _uid(); ndb_s["med_sess_1"] = ndb_med1
    ss = NOW - timedelta(hours=22); se = ss + timedelta(minutes=45)
    _create_session(ndb_med1, ndb_u, "CUST-0000047", 0, ndb_id, "103.44.55.33", "IN", "Bengaluru", "web_browser", 36, 46, 40, False, "none", False, ss, se, [("login", 36, 38), ("behaviour_sample", 38, 42), ("transaction", 42, 46), ("page_nav", 46, 40)])

    ndb_med2 = _uid(); ndb_s["med_sess_2"] = ndb_med2
    ss = NOW - timedelta(hours=15); se = ss + timedelta(minutes=40)
    _create_session(ndb_med2, ndb_u, "CUST-0000048", 0, ndb_id, "49.55.66.44", "IN", "Delhi", "mobile_app", 52, 60, 56, False, "none", False, ss, se, [("login", 52, 54), ("transaction", 54, 58), ("behaviour_sample", 58, 60), ("page_nav", 60, 56)])

    ndb_atm = _uid(); ndb_s["atm_sess_1"] = ndb_atm
    ss = NOW - timedelta(hours=9); se = ss + timedelta(minutes=14)
    _create_session(ndb_atm, ndb_u, "CUST-0000040", 0, ndb_id, "103.99.66.4", "IN", "Delhi", "atm", 22, 36, 28, False, "none", False, ss, se, [("login", 22, 26), ("transaction", 26, 36), ("page_nav", 36, 28)])

    ndb_api = _uid(); ndb_s["api_sess_1"] = ndb_api
    ss = NOW - timedelta(hours=32); se = ss + timedelta(minutes=35)
    _create_session(ndb_api, ndb_u, "CUST-0000037", 0, ndb_id, "117.77.22.9", "IN", "Chennai", "api", 18, 24, 21, False, "none", False, ss, se, [("login", 18, 20), ("transaction", 20, 24), ("page_nav", 24, 21)])

    ndb_su1 = _uid(); ndb_s["stepup_passed_1"] = ndb_su1
    ss = NOW - timedelta(hours=11); se = ss + timedelta(minutes=46)
    _create_session(ndb_su1, ndb_u, "CUST-0000046", 0, ndb_id, "103.66.44.22", "IN", "Hyderabad", "web_browser", 46, 66, 42, True, "passed", False, ss, se, [("login", 46, 49), ("behaviour_sample", 49, 56), ("transaction", 56, 62), ("step_up", 62, 66), ("page_nav", 66, 54), ("behaviour_sample", 54, 42)])

    ndb_su2 = _uid(); ndb_s["stepup_passed_2"] = ndb_su2
    ss = NOW - timedelta(hours=33); se = ss + timedelta(minutes=36)
    _create_session(ndb_su2, ndb_u, "CUST-0000048", 0, ndb_id, "103.55.33.22", "IN", "Mumbai", "web_browser", 55, 73, 40, True, "passed", False, ss, se, [("login", 55, 58), ("behaviour_sample", 58, 64), ("transaction", 64, 70), ("step_up", 70, 73), ("page_nav", 73, 54), ("behaviour_sample", 54, 40)])

    ndb_su3 = _uid(); ndb_s["stepup_failed_flagged"] = ndb_su3
    ss = NOW - timedelta(hours=26); se = ss + timedelta(minutes=12)
    _create_session(ndb_su3, ndb_u, "CUST-0000051", 0, ndb_id, "185.220.102.8", "DE", "Berlin", "web_browser", 83, 90, 90, True, "failed", True, ss, se, [("login", 83, 85), ("behaviour_sample", 85, 88), ("step_up", 88, 90), ("page_nav", 90, 90)])

    ndb_fl1 = _uid(); ndb_s["flagged_ato_1"] = ndb_fl1
    ss = NOW - timedelta(hours=39); se = ss + timedelta(minutes=22)
    _create_session(ndb_fl1, ndb_u, "CUST-0000050", 0, ndb_id, "89.187.181.44", "SG", "Singapore", "web_browser", 74, 92, 90, True, "timeout", True, ss, se, [("login", 74, 78), ("behaviour_sample", 78, 83), ("step_up", 83, 88), ("transaction", 88, 92), ("behaviour_sample", 92, 90)])

    for ext_id, ip, city, ch, ri, rp, rf, h_ago, dur_m in [
        ("CUST-0000037", "103.55.88.24", "Chennai",   "web_browser", 16, 20, 18, 42, 30),
        ("CUST-0000040", "103.88.66.57", "Delhi",     "mobile_app",  23, 27, 25, 35, 24),
        ("CUST-0000043", "103.22.99.90", "Mumbai",    "web_browser", 25, 29, 27, 28, 22),
        ("EMP-0000014",  "117.96.12.125", "Mumbai",   "web_browser", 24, 28, 26, 17, 28),
        ("EMP-0000015",  "117.96.12.130", "Mumbai",   "web_browser", 29, 33, 31, 13, 32),
    ]:
        sid = _uid()
        ss = NOW - timedelta(hours=h_ago); se = ss + timedelta(minutes=dur_m)
        mid = (ri + rp) // 2
        _create_session(sid, ndb_u, ext_id, 0, ndb_id, ip, "IN", city, ch, ri, rp, rf, False, "none", False, ss, se, [("login", ri, ri + 2), ("behaviour_sample", ri + 2, mid), ("page_nav", mid, rf)])

    # ======================================================================
    # PHASE 9 - Alerts
    # ======================================================================

    def _alert(inst_id, user_u_map, user_ext, session_id, atype, severity, priority,
               status, assigned_id, auto_action, title, desc, notes, created_h_ago,
               resolved_h_after=None):
        aid = _uid()
        created_ts = NOW - timedelta(hours=created_h_ago)
        resolved_ts = created_ts + timedelta(hours=resolved_h_after) if resolved_h_after else None
        a = Alert(
            id=aid,
            institution_id=inst_id,
            session_id=session_id,
            user_id=user_u_map[user_ext],
            alert_type=atype,
            severity=severity,
            ml_priority_score=priority,
            status=status,
            assigned_to=assigned_id,
            auto_action_taken=auto_action,
            title=title,
            description=desc,
            analyst_notes=notes,
            resolved_at=resolved_ts,
            created_at=created_ts,
        )
        db.session.add(a)
        db.session.commit()
        return aid

    # HFB Alerts (12 alerts: 4 open, 2 investigating, 2 resolved, 2 dismissed, 1 false_positive, 1 open-critical)
    a_hfb1 = _alert(hfb_id, hfb_u, "CUST-0000017", hfb_s["active_critical_1"], "ato_attempt", "critical", 0.96, "open", hfb_analyst1_id, "block", "Critical ATO Attempt - Siddharth Rao Login from Moscow (RU)", "User CUST-0000017 attempted login from IP 45.83.17.42 (Moscow, RU), a known VPN exit node. Risk score escalated to 92 during session. Step-up verification triggered but user failed to complete OTP within the allowed window. Session is currently active. Immediate account review required.", None, 1, None)
    a_hfb2 = _alert(hfb_id, hfb_u, "CUST-0000016", hfb_s["flagged_ato_1"], "impossible_travel", "high", 0.82, "open", hfb_analyst2_id, "stepup", "Impossible Travel - Neha Kapoor Login from Singapore (SG)", "User CUST-0000016 (Bengaluru-registered) appeared in Singapore within a timeframe inconsistent with normal travel. IP 89.187.179.12 is flagged as a known proxy. Step-up timeout recorded. Account is currently suspended pending investigation.", None, 3, None)
    a_hfb3 = _alert(hfb_id, hfb_u, "CUST-0000017", hfb_s["stepup_failed_flagged"], "session_hijacking", "high", 0.79, "investigating", hfb_analyst1_id, "block", "Possible Session Hijacking - Siddharth Rao Session from Amsterdam", "Session originating from IP 185.220.100.42 (Tor exit node, Amsterdam, NL) for user CUST-0000017. Step-up verification failed. Session risk remained at 85 throughout. Possible credential replay attack. Analyst has begun reviewing prior session history.", None, 6, None)
    a_hfb4 = _alert(hfb_id, hfb_u, "CUST-0000015", None, "suspicious_behaviour", "high", 0.71, "investigating", hfb_analyst2_id, "monitor", "Suspicious Behaviour Pattern - Abhishek Singh Account", "User CUST-0000015 has triggered 3 locked-account events in 10 days. Current risk score is 72. Device fingerprint registered from an unrooted Android device that matches known credential-stuffing tool signatures. Further behaviour analysis in progress.", None, 8, None)
    a_hfb5 = _alert(hfb_id, hfb_u, "CUST-0000012", hfb_s["stepup_passed_1"], "new_device", "medium", 0.48, "open", hfb_analyst1_id, "monitor", "New Device Login - Nisha Agarwal Step-Up Passed", "User CUST-0000012 accessed from a new Firefox/Ubuntu device (first seen today). Step-up OTP verification passed. Risk score peaked at 65. No prior sessions from this device fingerprint. Flagged for 48-hour monitoring window.", None, 5, None)
    a_hfb6 = _alert(hfb_id, hfb_u, "CUST-0000014", hfb_s["med_sess_2"], "suspicious_behaviour", "medium", 0.44, "open", hfb_analyst2_id, "monitor", "Unusual Transaction Timing - Pooja Dubey Late-Night Activity", "User CUST-0000014 performed 3 fund transfers via mobile app between 02:15–03:40 IST, outside typical usage window. Risk score reached 60. No step-up triggered as score stayed within monitor threshold. Recommend analyst review of transaction amounts.", None, 4, None)
    a_hfb7 = _alert(hfb_id, hfb_u, "CUST-0000011", hfb_s["active_medium_1"], "suspicious_behaviour", "medium", 0.41, "open", hfb_analyst1_id, "monitor", "Elevated Risk Score During Active Session - Sanjay Malhotra", "User CUST-0000011 risk score escalated from 42 to 52 in current session. Behavioural deviation signals are elevated (score: 38.2). Transaction anomaly contributes 12 points. Session is active. Monitoring in place.", None, 1, None)
    a_hfb8 = _alert(hfb_id, hfb_u, "EMP-0000006", None, "insider_anomaly", "critical", 0.94, "open", hfb_analyst2_id, "investigate", "PAM Insider Anomaly - Bhavana Nair Admin Portal Access with Bulk Record Export", "Employee EMP-0000006 (Bhavana Nair) accessed Admin-Portal system - a restricted critical system outside her standard role permissions. During a 30-minute session, 720 records were accessed and 5,500 KB exported. High-action-velocity flag triggered (145 actions in 30 min). Anomaly flags: unauthorized_system_access (0.90), bulk_record_access (0.86), high_action_velocity (0.85). Immediate escalation required.", None, 2, None)
    a_hfb9 = _alert(hfb_id, hfb_u, "EMP-0000005", None, "bulk_export", "high", 0.77, "open", hfb_analyst1_id, "monitor", "Large Data Export Alert - Arun Tiwari Reporting-DB Access", "Employee EMP-0000005 (Arun Tiwari) accessed Reporting-DB (a critical system) and exported 18,000 KB of data in a single session. Export volume exceeds the 10 MB threshold. Anomaly flags: unauthorized_system_access, large_data_export. Risk score: 71. Review in progress.", None, 2, None)
    a_hfb10 = _alert(hfb_id, hfb_u, "CUST-0000002", hfb_s["stepup_passed_2"], "new_device", "low", 0.22, "resolved", hfb_compliance_id, "none", "New Device Registration - Priya Nair iPhone 14", "User CUST-0000002 registered a new iPhone 14 device. Step-up verification passed successfully. Device fingerprint is clean. No VPN or proxy detected. Resolved after user confirmed device ownership via registered email.", "User confirmed device ownership via registered email. Step-up OTP verified successfully. No further action required. Device marked as trusted.", 18, 2)
    a_hfb11 = _alert(hfb_id, hfb_u, "CUST-0000009", None, "credential_stuffing", "medium", 0.39, "dismissed", hfb_analyst2_id, "none", "Credential Stuffing Detection - Aakash Bhatia Multiple Failed Logins", "5 failed login attempts from 3 different IPs within 2 hours for user CUST-0000009. Pattern matches known credential-stuffing tool behaviour. No successful login. Account was temporarily locked.", "Confirmed automated scan from threat intelligence - credential stuffing pattern. User account locked for 15 minutes. Password reset notification sent. No successful compromise. Dismissed after user reset password and confirmed via MFA.", 20, 3)
    a_hfb12 = _alert(hfb_id, hfb_u, "CUST-0000003", None, "new_device", "low", 0.18, "false_positive", hfb_analyst1_id, "none", "New Device Flag - Vikram Mehta Samsung Galaxy S23", "New mobile device detected for CUST-0000003. Initial alert raised by automated system.", "User confirmed new Samsung Galaxy S23 purchase and device transfer. Risk score remains low at 22. Behaviour profile consistent. Marked as false positive after confirmation call on 10-Jun-2026.", 36, 4)

    # AFS Alerts (11 alerts)
    a_afs1 = _alert(afs_id, afs_u, "CUST-0000034", afs_s["active_critical_1"], "ato_attempt", "critical", 0.97, "open", afs_analyst1_id, "block", "Critical ATO Attempt - Rithvik Pillai Login from Saint Petersburg (RU)", "User CUST-0000034 attempting login from IP 45.83.65.12 (Saint Petersburg, RU) - listed as a known VPN/proxy exit node in Apex threat intelligence feed. Risk score 94. Step-up triggered but verification failed. Active session under monitoring.", None, 1, None)
    a_afs2 = _alert(afs_id, afs_u, "CUST-0000033", afs_s["flagged_ato_1"], "impossible_travel", "high", 0.81, "open", afs_analyst2_id, "stepup", "Impossible Travel Alert - Padmavathi Rao Login from Singapore", "User CUST-0000033 (Bengaluru-resident) flagged for impossible travel: previous session from Bengaluru 6 hours prior, new session from Singapore IP 89.187.180.33. Risk 89. Account suspended pending verification.", None, 3, None)
    a_afs3 = _alert(afs_id, afs_u, "CUST-0000034", afs_s["stepup_failed_flagged"], "session_hijacking", "high", 0.78, "investigating", afs_analyst1_id, "block", "Session Hijacking Suspected - Rithvik Pillai Tor Exit Node Session", "Session from Tor exit node IP 185.220.101.15 (Frankfurt, DE) failed step-up. Risk stayed at 88. Prior session 1 hour earlier from India. Possible credential replay scenario. Analyst reviewing.", None, 5, None)
    a_afs4 = _alert(afs_id, afs_u, "CUST-0000032", None, "suspicious_behaviour", "high", 0.72, "investigating", afs_analyst2_id, "monitor", "Emulator Device Detected - Vinod Hegde Account Access", "User CUST-0000032 accessed account from a detected Android emulator device (fingerprint matches common testing framework). Risk score 68. Device marked suspicious. Multiple login attempts from the same emulator within 30 minutes.", None, 7, None)
    a_afs5 = _alert(afs_id, afs_u, "CUST-0000029", afs_s["stepup_passed_1"], "new_device", "medium", 0.46, "open", afs_analyst1_id, "monitor", "New Device Step-Up - Archana Kulkarni Access from New IP Range", "User CUST-0000029 connected from IP 103.55.66.33 - new /24 subnet not seen in prior 60 days. Step-up passed. Risk peaked at 68. Profile confidence medium.", None, 4, None)
    a_afs6 = _alert(afs_id, afs_u, "CUST-0000031", afs_s["med_sess_2"], "suspicious_behaviour", "medium", 0.43, "open", afs_analyst2_id, "monitor", "Multiple High-Value Transactions - Pallavi Deshpande", "User CUST-0000031 initiated 4 transactions totalling ₹88,000 in a single session. Session risk reached 63. Behaviour deviation score elevated. No step-up triggered per policy threshold.", None, 3, None)
    a_afs7 = _alert(afs_id, afs_u, "EMP-0000012", None, "insider_anomaly", "critical", 0.93, "open", afs_analyst1_id, "investigate", "PAM Insider Anomaly - Jyothi Iyer Admin Portal Access", "Employee EMP-0000012 (Jyothi Iyer) accessed Admin-Portal outside standard permissions. 680 records accessed, 5,200 KB exported in a 35-minute window. Anomaly flags triggered. Risk score 75. Escalated to compliance officer.", None, 2, None)
    a_afs8 = _alert(afs_id, afs_u, "EMP-0000011", None, "bulk_export", "high", 0.74, "open", afs_analyst2_id, "monitor", "Large Data Export - Sandeep Kumar Reporting-DB Session", "EMP-0000011 accessed Reporting-DB and exported 17,500 KB. Exceeds 10 MB threshold. Anomaly flags: unauthorized_system_access, large_data_export. Risk score 69. Pending review.", None, 2, None)
    a_afs9 = _alert(afs_id, afs_u, "CUST-0000019", None, "account_recovery_abuse", "low", 0.21, "resolved", afs_compliance_id, "none", "Account Recovery Request - Preethi Narayanan OTP Resend Limit Reached", "User CUST-0000019 requested account recovery OTP 5 times within 10 minutes. No successful breach. User authenticated via alternate verification.", "User confirmed forgotten password scenario. Guided through recovery via registered mobile OTP. No breach detected. Marked resolved.", 22, 2)
    a_afs10 = _alert(afs_id, afs_u, "CUST-0000025", None, "new_device", "low", 0.19, "dismissed", afs_analyst2_id, "none", "New Device Login - Divya Menon Samsung Galaxy M32", "CUST-0000025 accessed from new Samsung Galaxy M32. Step-up passed. No other anomalies.", "User confirmed device purchase. Device fingerprint clean. Step-up verified. Dismissed as benign new device registration.", 28, 3)
    a_afs11 = _alert(afs_id, afs_u, "CUST-0000023", None, "suspicious_behaviour", "medium", 0.37, "false_positive", afs_analyst1_id, "none", "Unusual Session Length - Kavya Srinivasan 4-Hour Web Session", "Session exceeded 4 hours - automated alert raised by policy rule for extended sessions.", "User is a premium customer working from home. Extended session due to tax filing activity. Behaviour profile consistent throughout. Confirmed false positive.", 32, 5)

    # NDB Alerts (12 alerts)
    a_ndb1 = _alert(ndb_id, ndb_u, "CUST-0000051", ndb_s["active_critical_1"], "ato_attempt", "critical", 0.97, "open", ndb_analyst1_id, "block", "Critical ATO - Rishi Kapoor Session from Karachi (PK)", "User CUST-0000051 session originates from IP 45.83.22.88 (Karachi, PK), a flagged proxy address in NovaPay's threat feed. Risk score 95. Step-up triggered but failed. Session active. Immediate freeze recommended.", None, 1, None)
    a_ndb2 = _alert(ndb_id, ndb_u, "CUST-0000050", ndb_s["flagged_ato_1"], "impossible_travel", "high", 0.83, "open", ndb_analyst2_id, "stepup", "Impossible Travel - Namita Gokhale Singapore Session", "User CUST-0000050 logged in from Singapore (IP 89.187.181.44) within 2 hours of a Mumbai session. Travel time infeasible. Step-up timeout. Account suspended.", None, 3, None)
    a_ndb3 = _alert(ndb_id, ndb_u, "CUST-0000051", ndb_s["stepup_failed_flagged"], "session_hijacking", "high", 0.80, "investigating", ndb_analyst1_id, "block", "Session Hijacking Risk - Rishi Kapoor Berlin Tor Node Session", "Session from Tor exit node in Berlin (IP 185.220.102.8). Step-up failed. Risk peaked at 90. Session from India seen 3 hours earlier. Investigating possible account takeover chain.", None, 5, None)
    a_ndb4 = _alert(ndb_id, ndb_u, "CUST-0000049", None, "suspicious_behaviour", "high", 0.73, "investigating", ndb_analyst2_id, "monitor", "High Risk Score Escalation - Chiranjeevi Rao Account", "CUST-0000049 risk score reached 70 with account currently locked. Rooted Android device flagged suspicious. Three failed logins in last 6 hours. Analyst reviewing device and location history.", None, 6, None)
    a_ndb5 = _alert(ndb_id, ndb_u, "CUST-0000046", ndb_s["stepup_passed_1"], "new_device", "medium", 0.47, "open", ndb_analyst1_id, "monitor", "New Device Step-Up Passed - Rekha Nataraj Hyderabad Session", "User CUST-0000046 logged in from new device subnet. Step-up OTP passed. Risk peaked at 66. Profile confidence medium. 48-hour watch period initiated.", None, 4, None)
    a_ndb6 = _alert(ndb_id, ndb_u, "CUST-0000048", ndb_s["med_sess_2"], "suspicious_behaviour", "medium", 0.44, "open", ndb_analyst2_id, "monitor", "Late-Night Transactions - Swati Bhatt Mobile App Activity", "CUST-0000048 conducted 3 transfers after 01:00 IST from mobile app. Risk score 60. Behaviour deviation elevated. Transaction anomaly signal at 12.4.", None, 3, None)
    a_ndb7 = _alert(ndb_id, ndb_u, "CUST-0000047", ndb_s["med_sess_1"], "suspicious_behaviour", "medium", 0.40, "open", ndb_analyst1_id, "monitor", "Unusual Geo-Access - Prasad Hegde Firefox on Linux Session", "CUST-0000047 accessed from a Linux/Firefox environment for the first time. IP is a new /24 block (103.44.55.33). Risk 46. No step-up triggered. Session monitoring active.", None, 2, None)
    a_ndb8 = _alert(ndb_id, ndb_u, "EMP-0000018", None, "insider_anomaly", "critical", 0.95, "open", ndb_analyst2_id, "investigate", "PAM Insider Anomaly - Poornima Shetty Admin Portal Bulk Access", "EMP-0000018 (Poornima Shetty) accessed Admin-Portal - a critical restricted system - with risk score 81. 700 records accessed, 5,800 KB exported in a 28-minute session. Anomaly flags: unauthorized_system_access (0.92), bulk_record_access (0.88), high_action_velocity (0.87).", None, 2, None)
    a_ndb9 = _alert(ndb_id, ndb_u, "EMP-0000017", None, "bulk_export", "high", 0.76, "open", ndb_analyst1_id, "monitor", "Large Export - Devesh Misra Reporting-DB Data Exfiltration Risk", "EMP-0000017 accessed Reporting-DB and exported 16,800 KB exceeding the 10 MB policy threshold. Anomaly: large_data_export (0.91). Risk score 70. Analyst reviewing export contents.", None, 2, None)
    a_ndb10 = _alert(ndb_id, ndb_u, "CUST-0000036", None, "account_recovery_abuse", "low", 0.20, "resolved", ndb_compliance_id, "none", "Account Recovery OTP Abuse - Deepika Krishnamurthy", "CUST-0000036 requested recovery OTP 4 times within 8 minutes.", "User confirmed phone was switched off during OTP window. Recovery completed via email OTP backup. No breach. Resolved.", 24, 2)
    a_ndb11 = _alert(ndb_id, ndb_u, "CUST-0000042", None, "new_device", "low", 0.17, "dismissed", ndb_analyst2_id, "none", "New Device Alert - Nilesh Patil Android Pixel 7a", "CUST-0000042 first access from Android Pixel 7a. Device fingerprint clean.", "User confirmed new device purchase. Step-up OTP verified. Dismissed as benign.", 30, 3)
    a_ndb12 = _alert(ndb_id, ndb_u, "CUST-0000039", None, "suspicious_behaviour", "medium", 0.36, "false_positive", ndb_analyst1_id, "none", "Extended Inactivity Timeout - Kavita Deshpande Session Anomaly", "Automated alert for 3 rapid logins within 5 minutes. Triggered by policy threshold.", "Customer confirmed back-to-back login attempts due to slow network at home. Behaviour profile normal. Confirmed false positive.", 33, 5)

    # ======================================================================
    # PHASE 10 - Privileged Sessions (PAM)
    # ======================================================================

    def _pam(pid, emp_ext, u_map, inst_id, role, priv_level, system, actions, records, export_kb,
             flags_dict, risk, alert_gen, start, end=None):
        ps = PrivilegedSession(
            id=pid,
            employee_user_id=u_map[emp_ext],
            institution_id=inst_id,
            role=role,
            privilege_level=priv_level,
            system_accessed=system,
            actions_count=actions,
            data_records_accessed=records,
            export_volume_kb=export_kb,
            anomaly_flags=_j(flags_dict),
            risk_score=risk,
            alert_generated=alert_gen,
            started_at=start,
            ended_at=end,
        )
        db.session.add(ps)
        db.session.commit()
        return ps

    # HFB PAM sessions (7)
    _pam(_uid(), "EMP-0000001", hfb_u, hfb_id, "Senior DB Administrator", "elevated", "Core-Banking-DB", 48, 130, 2048, {}, 16, False, NOW - timedelta(hours=9), NOW - timedelta(hours=7))
    _pam(_uid(), "EMP-0000002", hfb_u, hfb_id, "Customer Service Manager", "standard", "Customer-Records", 32, 88, 512, {}, 11, False, NOW - timedelta(hours=6), NOW - timedelta(hours=4))
    _pam(_uid(), "EMP-0000003", hfb_u, hfb_id, "Internal Auditor", "elevated", "Audit-Portal", 24, 52, 128, {}, 9, False, NOW - timedelta(hours=11), NOW - timedelta(hours=9, minutes=30))
    _pam(_uid(), "EMP-0000006", hfb_u, hfb_id, "Operations Analyst", "standard", "Admin-Portal", 145, 720, 5500, {"unauthorized_system_access": 0.90, "bulk_record_access": 0.86, "high_action_velocity": 0.85}, 69, True, NOW - timedelta(hours=4), NOW - timedelta(hours=3, minutes=30))
    _pam(_uid(), "EMP-0000005", hfb_u, hfb_id, "Reporting Analyst", "standard", "Reporting-DB", 88, 385, 18000, {"unauthorized_system_access": 0.90, "large_data_export": 0.91}, 71, True, NOW - timedelta(hours=3), NOW - timedelta(hours=2))
    _pam(_uid(), "EMP-0000004", hfb_u, hfb_id, "IT Operations Specialist", "standard", "Customer-Records", 19, 48, 256, {}, 10, False, NOW - timedelta(hours=1, minutes=28), None)
    _pam(_uid(), "EMP-0000001", hfb_u, hfb_id, "Senior DB Administrator", "elevated", "Core-Banking-DB", 35, 90, 1024, {"off_hours_access": 0.65}, 32, False, NOW - timedelta(hours=23), NOW - timedelta(hours=21, minutes=30))

    # AFS PAM sessions (7)
    _pam(_uid(), "EMP-0000007", afs_u, afs_id, "Senior Database Administrator", "elevated", "Core-Banking-DB", 52, 145, 2560, {}, 17, False, NOW - timedelta(hours=8), NOW - timedelta(hours=6))
    _pam(_uid(), "EMP-0000008", afs_u, afs_id, "Customer Records Analyst", "standard", "Customer-Records", 35, 92, 640, {}, 12, False, NOW - timedelta(hours=5), NOW - timedelta(hours=3, minutes=30))
    _pam(_uid(), "EMP-0000009", afs_u, afs_id, "Internal Auditor", "elevated", "Audit-Portal", 28, 58, 192, {}, 10, False, NOW - timedelta(hours=10), NOW - timedelta(hours=8, minutes=30))
    _pam(_uid(), "EMP-0000012", afs_u, afs_id, "IT Operations Analyst", "standard", "Admin-Portal", 138, 680, 5200, {"unauthorized_system_access": 0.89, "bulk_record_access": 0.85, "high_action_velocity": 0.84}, 75, True, NOW - timedelta(hours=4, minutes=30), NOW - timedelta(hours=4))
    _pam(_uid(), "EMP-0000011", afs_u, afs_id, "Data Analyst", "standard", "Reporting-DB", 82, 360, 17500, {"unauthorized_system_access": 0.89, "large_data_export": 0.91}, 69, True, NOW - timedelta(hours=3, minutes=30), NOW - timedelta(hours=2, minutes=30))
    _pam(_uid(), "EMP-0000010", afs_u, afs_id, "Fraud Investigation Analyst", "standard", "Customer-Records", 22, 55, 320, {}, 11, False, NOW - timedelta(hours=1, minutes=35), None)
    _pam(_uid(), "EMP-0000007", afs_u, afs_id, "Senior Database Administrator", "elevated", "Core-Banking-DB", 40, 105, 1280, {"off_hours_access": 0.65}, 35, False, NOW - timedelta(hours=22, minutes=30), NOW - timedelta(hours=21))

    # NDB PAM sessions (7)
    _pam(_uid(), "EMP-0000013", ndb_u, ndb_id, "Principal Database Engineer", "admin", "Core-Banking-DB", 55, 160, 3072, {}, 18, False, NOW - timedelta(hours=7), NOW - timedelta(hours=5))
    _pam(_uid(), "EMP-0000014", ndb_u, ndb_id, "Customer Operations Lead", "standard", "Customer-Records", 38, 95, 768, {}, 13, False, NOW - timedelta(hours=5, minutes=30), NOW - timedelta(hours=3, minutes=30))
    _pam(_uid(), "EMP-0000015", ndb_u, ndb_id, "Compliance Auditor", "elevated", "Audit-Portal", 30, 62, 256, {}, 11, False, NOW - timedelta(hours=10, minutes=30), NOW - timedelta(hours=8, minutes=30))
    _pam(_uid(), "EMP-0000018", ndb_u, ndb_id, "Platform Operations Analyst", "standard", "Admin-Portal", 152, 700, 5800, {"unauthorized_system_access": 0.92, "bulk_record_access": 0.88, "high_action_velocity": 0.87}, 81, True, NOW - timedelta(hours=4, minutes=45), NOW - timedelta(hours=4, minutes=17))
    _pam(_uid(), "EMP-0000017", ndb_u, ndb_id, "Business Intelligence Analyst", "standard", "Reporting-DB", 78, 345, 16800, {"unauthorized_system_access": 0.88, "large_data_export": 0.91}, 70, True, NOW - timedelta(hours=3, minutes=45), NOW - timedelta(hours=2, minutes=45))
    _pam(_uid(), "EMP-0000016", ndb_u, ndb_id, "Risk Operations Specialist", "standard", "Customer-Records", 25, 60, 384, {}, 12, False, NOW - timedelta(hours=1, minutes=40), None)
    _pam(_uid(), "EMP-0000013", ndb_u, ndb_id, "Principal Database Engineer", "admin", "Core-Banking-DB", 42, 110, 1536, {"off_hours_access": 0.65}, 36, False, NOW - timedelta(hours=23, minutes=30), NOW - timedelta(hours=22))

    # ======================================================================
    # PHASE 11 - Onboarding Applications
    # ======================================================================

    def _kyc(inst_id, ref, name, doc_type, doc_num_seed, ls, das, obs, wm, wm_detail, sir,
             reviewer_id, notes, submitted_h_ago, decided_h_after=None):
        score = _kyc_composite(das, ls, obs, wm, sir)
        decision = _kyc_decision(score) if reviewer_id else "pending"
        submitted = NOW - timedelta(hours=submitted_h_ago)
        decided = submitted + timedelta(hours=decided_h_after) if decided_h_after else None
        app = OnboardingApplication(
            id=_uid(),
            institution_id=inst_id,
            application_ref=ref,
            applicant_name=name,
            document_type=doc_type,
            document_number_hash=_sha(f"doc:{doc_num_seed}"),
            liveness_score=ls,
            document_authenticity_score=das,
            onboarding_behaviour_score=obs,
            watchlist_match=wm,
            watchlist_match_detail=_j(wm_detail) if wm_detail else None,
            synthetic_identity_risk=sir,
            composite_risk_score=score,
            decision=decision,
            reviewer_id=reviewer_id,
            reviewer_notes=notes,
            submitted_at=submitted,
            decided_at=decided,
        )
        db.session.add(app)
        db.session.commit()

    # HFB onboarding (11 applications)
    # Approve group (5)
    _kyc(hfb_id, "KYC-2025-00001", "Aarti Mehrotra",       "aadhaar",          "AADHAAR-9812345670", 0.95, 0.93, 0.88, False, None, 0.03, hfb_compliance_id, "All checks passed. Document authentic, liveness clear, no watchlist match. Approved.", 36, 3)
    _kyc(hfb_id, "KYC-2025-00002", "Sunil Tiwari",         "pan",              "BCTPT1234A",         0.89, 0.91, 0.92, False, None, 0.04, hfb_compliance_id, "PAN card verified via NSDL. Liveness biometric passed 3/3 checks. Approved.", 30, 2)
    _kyc(hfb_id, "KYC-2025-00003", "Kavya Srinivasan",     "passport",         "J1234567",           0.91, 0.88, 0.85, False, None, 0.05, hfb_analyst2_id,   "Passport MRZ verified. Liveness passed. No synthetic identity risk. Approved.", 24, 4)
    _kyc(hfb_id, "KYC-2025-00004", "Ranjit Singh Kaur",    "driving_licence",  "DL-PB-1234567890",   0.85, 0.87, 0.90, False, None, 0.02, hfb_compliance_id, "Driving licence hologram verified. Behaviour pattern natural. Approved.", 20, 2)
    _kyc(hfb_id, "KYC-2025-00005", "Priya Ganesh Iyer",    "aadhaar",          "AADHAAR-8734521096", 0.92, 0.90, 0.87, False, None, 0.03, hfb_analyst2_id,   "UIDAI OTP verification successful. Document authentic. Approved.", 15, 3)
    # Manual review (3)
    _kyc(hfb_id, "KYC-2025-00006", "Dhruv Agarwal",        "aadhaar",          "AADHAAR-7623451087", 0.52, 0.58, 0.57, False, None, 0.28, hfb_compliance_id, "Liveness borderline pass. Document quality low (blurred corners). Synthetic identity risk flag at 0.28. Sent for secondary review.", 18, 6)
    _kyc(hfb_id, "KYC-2025-00007", "Fatima Mirza",         "pan",              "ABCFM1234K",         0.48, 0.52, 0.55, False, None, 0.30, hfb_analyst2_id,   "Document score low. Applicant blinked excessively during liveness. Risk flags raised. Manual review initiated.", 12, 5)
    _kyc(hfb_id, "KYC-2025-00008", "Harish Taneja",        "passport",         "M9876543",           0.54, 0.60, 0.58, False, None, 0.25, hfb_compliance_id, "Passport photo slightly mismatched from liveness capture. Score within manual review range. Secondary verification recommended.", 8, None)
    # Reject (2)
    _kyc(hfb_id, "KYC-2025-00009", "Ramzan Khan",          "aadhaar",          "AADHAAR-0001234567", 0.22, 0.18, 0.25, True,  {"list": "OFAC-SDN", "match_score": 0.91, "name": "Ramzan Khan", "alias": "R. Khan"}, 0.75, hfb_compliance_id, "Liveness failed (score 0.22 < 0.30 threshold). Document authenticity very low. OFAC-SDN watchlist match at 91% confidence. Application rejected.", 10, 2)
    _kyc(hfb_id, "KYC-2025-00010", "Vishal Gambhir",       "driving_licence",  "DL-HR-9876543210",   0.20, 0.15, 0.22, True,  {"list": "INTERPOL-NOTICE", "match_score": 0.87, "name": "V. Gambhir"}, 0.80, hfb_analyst2_id,   "Document authenticity critically low (0.15). Liveness failed. Interpol notice match. High synthetic identity risk. Rejected.", 6, 1)
    # Pending (1)
    _kyc(hfb_id, "KYC-2025-00011", "Meenakshi Pillai",     "aadhaar",          "AADHAAR-5544332211", 0.80, 0.78, 0.82, False, None, 0.06, None, None, 2, None)

    # AFS onboarding (10 applications)
    _kyc(afs_id, "KYC-2025-00012", "Akash Sharma",         "pan",              "AXKPS2345B",         0.94, 0.92, 0.90, False, None, 0.03, afs_compliance_id, "Clean application. PAN verified. Liveness excellent. Approved.", 34, 3)
    _kyc(afs_id, "KYC-2025-00013", "Lalita Venkatesh",     "aadhaar",          "AADHAAR-6612345780", 0.88, 0.90, 0.86, False, None, 0.04, afs_compliance_id, "UIDAI verified. Document authentic. Behaviour natural. Approved.", 28, 2)
    _kyc(afs_id, "KYC-2025-00014", "Saurabh Jain",         "passport",         "K2345678",           0.90, 0.87, 0.88, False, None, 0.05, afs_analyst2_id,   "Passport MRZ clear. No watchlist. Liveness passed. Approved.", 22, 4)
    _kyc(afs_id, "KYC-2025-00015", "Nandini Krishnaswamy", "driving_licence",  "DL-KA-2345678901",   0.86, 0.88, 0.91, False, None, 0.02, afs_compliance_id, "Licence hologram verified. OCR match confirmed. Approved.", 16, 2)
    _kyc(afs_id, "KYC-2025-00016", "Gaurav Mishra",        "aadhaar",          "AADHAAR-7745321096", 0.55, 0.56, 0.58, False, None, 0.27, afs_analyst1_id,   "Liveness borderline. Low contrast document image. Synthetic identity flag 0.27. Manual review required.", 14, 5)
    _kyc(afs_id, "KYC-2025-00017", "Rekha Bhaskar",        "pan",              "ARJRB5678C",         0.50, 0.53, 0.52, False, None, 0.32, afs_compliance_id, "Document partially obscured. Liveness failed twice. Manual review recommended.", 10, 4)
    _kyc(afs_id, "KYC-2025-00018", "Suraj Prakash",        "aadhaar",          "AADHAAR-9900112233", 0.19, 0.16, 0.23, True,  {"list": "UN-SANCTIONS", "match_score": 0.89, "name": "Suraj Prakash"}, 0.78, afs_compliance_id, "Multiple verification failures. UN sanctions watchlist match. Rejected.", 8, 1)
    _kyc(afs_id, "KYC-2025-00019", "Madhavi Goswami",      "passport",         "N3456789",           0.17, 0.14, 0.20, True,  {"list": "INTERPOL-NOTICE", "match_score": 0.85, "name": "M. Goswami"}, 0.82, afs_analyst1_id,   "Liveness and document both failed. Interpol match. Rejected.", 5, 1)
    _kyc(afs_id, "KYC-2025-00020", "Devaki Raghunathan",   "aadhaar",          "AADHAAR-1122334455", 0.82, 0.80, 0.83, False, None, 0.05, None, None, 3, None)
    _kyc(afs_id, "KYC-2025-00021", "Anirudh Balasubramanian", "pan",           "AXANB7890D",         0.78, 0.75, 0.80, False, None, 0.07, None, None, 1, None)

    # NDB onboarding (11 applications)
    _kyc(ndb_id, "KYC-2025-00022", "Pavan Kumar Reddy",    "aadhaar",          "AADHAAR-3344556677", 0.96, 0.94, 0.91, False, None, 0.02, ndb_compliance_id, "Perfect biometrics. UIDAI verified instantly. No risk flags. Approved.", 32, 2)
    _kyc(ndb_id, "KYC-2025-00023", "Savitha Nair",         "pan",              "BXKPN3456E",         0.90, 0.93, 0.88, False, None, 0.03, ndb_analyst2_id,   "PAN NSDL verified. Liveness clear. Behaviour pattern natural. Approved.", 26, 3)
    _kyc(ndb_id, "KYC-2025-00024", "Aryan Khanna",         "passport",         "P4567890",           0.89, 0.87, 0.86, False, None, 0.05, ndb_compliance_id, "Passport MRZ check passed. No watchlist. Approved.", 20, 3)
    _kyc(ndb_id, "KYC-2025-00025", "Usha Krishnamurthy",   "driving_licence",  "DL-TN-3456789012",   0.87, 0.90, 0.89, False, None, 0.02, ndb_compliance_id, "Licence authentic. OCR match. Approved.", 16, 2)
    _kyc(ndb_id, "KYC-2025-00026", "Rajesh Balaji",        "aadhaar",          "AADHAAR-8855443322", 0.91, 0.88, 0.90, False, None, 0.03, ndb_analyst1_id,   "All biometrics passed. Document clean. Approved.", 12, 2)
    _kyc(ndb_id, "KYC-2025-00027", "Varsha Kulkarni",      "pan",              "BVTPK6789F",         0.54, 0.57, 0.56, False, None, 0.26, ndb_compliance_id, "Document partially illegible. Liveness borderline. Secondary review initiated.", 14, 5)
    _kyc(ndb_id, "KYC-2025-00028", "Shyam Sundar Das",     "aadhaar",          "AADHAAR-4455667788", 0.51, 0.55, 0.53, False, None, 0.31, ndb_analyst1_id,   "Low biometric match confidence. Manual verification required.", 10, 4)
    _kyc(ndb_id, "KYC-2025-00029", "Ibrahim Shaikh",       "aadhaar",          "AADHAAR-0011223344", 0.21, 0.17, 0.24, True,  {"list": "OFAC-SDN", "match_score": 0.93, "name": "Ibrahim Shaikh"}, 0.77, ndb_compliance_id, "OFAC-SDN match at 93% confidence. Liveness failed. Document not authentic. Rejected.", 7, 1)
    _kyc(ndb_id, "KYC-2025-00030", "Kalpana Rajput",       "passport",         "Q5678901",           0.18, 0.13, 0.21, True,  {"list": "UN-SANCTIONS", "match_score": 0.88, "name": "K. Rajput"}, 0.81, ndb_analyst2_id,   "UN sanctions match. All biometrics failed. High synthetic identity risk. Rejected.", 4, 1)
    _kyc(ndb_id, "KYC-2025-00031", "Girish Nagarajan",     "aadhaar",          "AADHAAR-7766554433", 0.83, 0.81, 0.84, False, None, 0.05, None, None, 4, None)
    _kyc(ndb_id, "KYC-2025-00032", "Sheela Kamath",        "pan",              "CXKPK8901G",         0.77, 0.74, 0.79, False, None, 0.08, None, None, 2, None)

    # ======================================================================
    # PHASE 12 - Audit Log
    # ======================================================================

    SYSTEM_IP = "10.0.0.1"
    SYSTEM_UA = "TrustSphere-Internal/1.0"

    # Helper to get admin email by id
    admin_emails = {
        super_admin_id: "admin@trustsphere.com",
        hfb_analyst1_id: "aryan.mehta@horizonfederal.in",
        hfb_analyst2_id: "neha.srivastava@horizonfederal.in",
        hfb_compliance_id: "rajan.pillai@horizonfederal.in",
        hfb_itadmin_id: "vikram.nair@horizonfederal.in",
        hfb_readonly_id: "sunita.verma@horizonfederal.in",
        afs_analyst1_id: "kiran.reddy@apexfintech.in",
        afs_analyst2_id: "smita.joshi@apexfintech.in",
        afs_compliance_id: "anil.kumar@apexfintech.in",
        afs_itadmin_id: "pradeep.krishnan@apexfintech.in",
        afs_readonly_id: "meena.patel@apexfintech.in",
        ndb_analyst1_id: "rohit.sharma@novapay.in",
        ndb_analyst2_id: "deepika.iyer@novapay.in",
        ndb_compliance_id: "suresh.venkataraman@novapay.in",
        ndb_itadmin_id: "alok.bose@novapay.in",
        ndb_readonly_id: "kavita.malhotra@novapay.in",
    }

    def _al(inst_id, atype, aid, aemail, action, ttype, tid, details, ip, ua, ts):
        _write_audit(inst_id, atype, aid, aemail, action, ttype, tid, details, ip, ua, ts)

    def _sys(inst_id, action, ttype, tid, details, ts):
        _al(inst_id, "system", None, None, action, ttype, tid, details, SYSTEM_IP, SYSTEM_UA, ts)

    def _adm(inst_id, admin_id, action, ttype, tid, details, ip, ts):
        _al(inst_id, "admin", admin_id, admin_emails.get(admin_id), action, ttype, tid, details, ip, UA_CHROME, ts)

    # Institution creation (system)
    _sys(hfb_id, "policy.created",    "institution", hfb_id, {"name": "Horizon Federal Bank", "plan": "starter"},  NOW - timedelta(days=87))
    _sys(afs_id, "policy.created",    "institution", afs_id, {"name": "Apex Fintech Solutions", "plan": "growth"}, NOW - timedelta(days=74))
    _sys(ndb_id, "policy.created",    "institution", ndb_id, {"name": "NovaPay Digital Bank", "plan": "enterprise"}, NOW - timedelta(days=61))

    # Policy activations
    _adm(hfb_id, hfb_itadmin_id, "policy.activated", "policy", hfb_policy1_id, {"policy_name": "HFB Standard Risk Policy v2"}, "103.87.4.24", NOW - timedelta(days=44))
    _adm(afs_id, afs_itadmin_id, "policy.activated", "policy", afs_policy1_id, {"policy_name": "AFS Adaptive Risk Policy v1"}, "49.32.18.8", NOW - timedelta(days=37))
    _adm(ndb_id, ndb_itadmin_id, "policy.activated", "policy", ndb_policy1_id, {"policy_name": "NovaPay Enterprise Risk Engine Policy v3"}, "117.96.12.44", NOW - timedelta(days=34))

    # Draft policy creations
    _adm(hfb_id, hfb_itadmin_id, "policy.created", "policy", hfb_policy2_id, {"policy_name": "HFB High Security Policy v3 (Draft)", "status": "draft"}, "103.87.4.24", NOW - timedelta(days=3))
    _adm(afs_id, afs_itadmin_id, "policy.created", "policy", afs_policy2_id, {"policy_name": "AFS Zero Trust Experimental (Draft)", "status": "draft"}, "49.32.18.8",  NOW - timedelta(days=5))
    _adm(ndb_id, ndb_itadmin_id, "policy.created", "policy", ndb_policy2_id, {"policy_name": "NovaPay DPDP Compliance Policy (Draft)", "status": "draft"}, "117.96.12.44", NOW - timedelta(days=1))

    # Admin logins (last 6 hours)
    for admin_id, ip, ts_h, ts_m in [
        (super_admin_id,  "103.21.244.12", 2, 14),
        (hfb_analyst1_id, "103.87.4.21",   1, 38),
        (hfb_analyst2_id, "103.87.4.22",   3, 52),
        (hfb_compliance_id, "103.87.4.23", 4, 17),
        (hfb_itadmin_id,  "103.87.4.24",   5, 8),
        (afs_analyst1_id, "49.32.18.5",    2, 45),
        (afs_analyst2_id, "49.32.18.6",    1, 12),
        (afs_compliance_id, "49.32.18.7",  3, 33),
        (ndb_analyst1_id, "117.96.12.41",  2, 5),
        (ndb_analyst2_id, "117.96.12.42",  1, 48),
        (ndb_compliance_id, "117.96.12.43", 3, 28),
    ]:
        inst = None if admin_id == super_admin_id else (hfb_id if "hfb" in admin_emails.get(admin_id, "") or "horizonfederal" in admin_emails.get(admin_id, "") else (afs_id if "apexfintech" in admin_emails.get(admin_id, "") else ndb_id))
        _al(inst, "admin", admin_id, admin_emails.get(admin_id), "admin.login", "admin_user", admin_id, {"login_method": "password_mfa" if admin_id in [super_admin_id, hfb_analyst1_id, afs_analyst2_id, ndb_compliance_id] else "password"}, ip, UA_CHROME, NOW - timedelta(hours=ts_h, minutes=ts_m))

    # MFA verifications for MFA-enabled admins
    _al(hfb_id, "admin", hfb_analyst1_id, admin_emails[hfb_analyst1_id], "admin.mfa_verified", "admin_user", hfb_analyst1_id, {"method": "totp"}, "103.87.4.21", UA_CHROME, NOW - timedelta(hours=1, minutes=37))
    _al(afs_id, "admin", afs_analyst2_id, admin_emails[afs_analyst2_id], "admin.mfa_verified", "admin_user", afs_analyst2_id, {"method": "totp"}, "49.32.18.6",  UA_CHROME, NOW - timedelta(hours=1, minutes=11))
    _al(ndb_id, "admin", ndb_compliance_id, admin_emails[ndb_compliance_id], "admin.mfa_verified", "admin_user", ndb_compliance_id, {"method": "totp"}, "117.96.12.43", UA_CHROME, NOW - timedelta(hours=3, minutes=27))

    # Alert creation events (system)
    _sys(hfb_id, "alert.created", "alert", a_hfb1, {"alert_type": "ato_attempt", "severity": "critical", "user_id": hfb_u["CUST-0000017"]}, NOW - timedelta(hours=1))
    _sys(hfb_id, "alert.created", "alert", a_hfb2, {"alert_type": "impossible_travel", "severity": "high"}, NOW - timedelta(hours=3))
    _sys(hfb_id, "alert.created", "alert", a_hfb3, {"alert_type": "session_hijacking", "severity": "high"}, NOW - timedelta(hours=6))
    _sys(hfb_id, "alert.created", "alert", a_hfb4, {"alert_type": "suspicious_behaviour", "severity": "high"}, NOW - timedelta(hours=8))
    _sys(hfb_id, "alert.created", "alert", a_hfb8, {"alert_type": "insider_anomaly", "severity": "critical"}, NOW - timedelta(hours=2))
    _sys(hfb_id, "alert.created", "alert", a_hfb9, {"alert_type": "bulk_export", "severity": "high"}, NOW - timedelta(hours=2))
    _sys(afs_id, "alert.created", "alert", a_afs1, {"alert_type": "ato_attempt", "severity": "critical"}, NOW - timedelta(hours=1))
    _sys(afs_id, "alert.created", "alert", a_afs2, {"alert_type": "impossible_travel", "severity": "high"}, NOW - timedelta(hours=3))
    _sys(afs_id, "alert.created", "alert", a_afs7, {"alert_type": "insider_anomaly", "severity": "critical"}, NOW - timedelta(hours=2))
    _sys(ndb_id, "alert.created", "alert", a_ndb1, {"alert_type": "ato_attempt", "severity": "critical"}, NOW - timedelta(hours=1))
    _sys(ndb_id, "alert.created", "alert", a_ndb2, {"alert_type": "impossible_travel", "severity": "high"}, NOW - timedelta(hours=3))
    _sys(ndb_id, "alert.created", "alert", a_ndb8, {"alert_type": "insider_anomaly", "severity": "critical"}, NOW - timedelta(hours=2))

    # Alert resolution events
    _adm(hfb_id, hfb_compliance_id, "alert.resolve", "alert", a_hfb10, {"status": "resolved", "notes": "Device ownership confirmed"}, "103.87.4.23", NOW - timedelta(hours=16))
    _adm(hfb_id, hfb_analyst2_id,   "alert.dismiss", "alert", a_hfb11, {"status": "dismissed", "notes": "Credential stuffing confirmed, password reset sent"}, "103.87.4.22", NOW - timedelta(hours=17))
    _adm(hfb_id, hfb_analyst1_id,   "alert.false_positive", "alert", a_hfb12, {"status": "false_positive"}, "103.87.4.21", NOW - timedelta(hours=32))
    _adm(afs_id, afs_compliance_id,  "alert.resolve", "alert", a_afs9,  {"status": "resolved"}, "49.32.18.7", NOW - timedelta(hours=20))
    _adm(afs_id, afs_analyst2_id,    "alert.dismiss", "alert", a_afs10, {"status": "dismissed"}, "49.32.18.6", NOW - timedelta(hours=25))
    _adm(afs_id, afs_analyst1_id,    "alert.false_positive", "alert", a_afs11, {"status": "false_positive"}, "49.32.18.5", NOW - timedelta(hours=27))
    _adm(ndb_id, ndb_compliance_id,  "alert.resolve", "alert", a_ndb10, {"status": "resolved"}, "117.96.12.43", NOW - timedelta(hours=22))
    _adm(ndb_id, ndb_analyst2_id,    "alert.dismiss", "alert", a_ndb11, {"status": "dismissed"}, "117.96.12.42", NOW - timedelta(hours=27))
    _adm(ndb_id, ndb_analyst1_id,    "alert.false_positive", "alert", a_ndb12, {"status": "false_positive"}, "117.96.12.41", NOW - timedelta(hours=28))

    # Escalation events
    _adm(hfb_id, hfb_analyst2_id, "alert.escalate", "alert", a_hfb3, {"escalated_to": hfb_analyst1_id, "previous_status": "open"}, "103.87.4.22", NOW - timedelta(hours=5, minutes=30))
    _adm(afs_id, afs_analyst2_id, "alert.escalate", "alert", a_afs3, {"escalated_to": afs_analyst1_id}, "49.32.18.6", NOW - timedelta(hours=4, minutes=30))
    _adm(ndb_id, ndb_analyst2_id, "alert.escalate", "alert", a_ndb3, {"escalated_to": ndb_analyst1_id}, "117.96.12.42", NOW - timedelta(hours=4, minutes=30))

    # User lifecycle events
    _sys(hfb_id, "user.risk_flagged", "user", hfb_u["CUST-0000017"], {"risk_score": 88, "category": "Critical"}, NOW - timedelta(hours=2))
    _sys(hfb_id, "user.suspended",    "user", hfb_u["CUST-0000016"], {"reason": "Impossible travel alert", "alert_id": a_hfb2}, NOW - timedelta(hours=3))
    _sys(hfb_id, "user.locked",       "user", hfb_u["CUST-0000015"], {"reason": "Repeated failed logins", "duration_minutes": 45}, NOW - timedelta(hours=5))
    _sys(afs_id, "user.risk_flagged", "user", afs_u["CUST-0000034"], {"risk_score": 91, "category": "Critical"}, NOW - timedelta(hours=2))
    _sys(afs_id, "user.suspended",    "user", afs_u["CUST-0000033"], {"reason": "Impossible travel alert", "alert_id": a_afs2}, NOW - timedelta(hours=3))
    _sys(afs_id, "user.locked",       "user", afs_u["CUST-0000032"], {"reason": "Emulator device detected", "duration_minutes": 30}, NOW - timedelta(hours=6))
    _sys(ndb_id, "user.risk_flagged", "user", ndb_u["CUST-0000051"], {"risk_score": 93, "category": "Critical"}, NOW - timedelta(hours=2))
    _sys(ndb_id, "user.suspended",    "user", ndb_u["CUST-0000050"], {"reason": "Impossible travel alert", "alert_id": a_ndb2}, NOW - timedelta(hours=3))
    _sys(ndb_id, "user.locked",       "user", ndb_u["CUST-0000049"], {"reason": "Rooted device + failed logins", "duration_minutes": 25}, NOW - timedelta(hours=5))

    # Session flagged events
    _sys(hfb_id, "session.flagged", "session", hfb_s["active_critical_1"],    {"reason": "block_action", "risk_peak": 92}, NOW - timedelta(hours=1, minutes=45))
    _sys(hfb_id, "session.flagged", "session", hfb_s["stepup_failed_flagged"], {"reason": "block_action", "risk_peak": 85}, NOW - timedelta(hours=27, minutes=50))
    _sys(hfb_id, "session.flagged", "session", hfb_s["flagged_ato_1"],         {"reason": "stepup_timeout", "risk_peak": 91}, NOW - timedelta(hours=40, minutes=55))
    _sys(afs_id, "session.flagged", "session", afs_s["active_critical_1"],    {"reason": "block_action", "risk_peak": 94}, NOW - timedelta(hours=1, minutes=40))
    _sys(ndb_id, "session.flagged", "session", ndb_s["active_critical_1"],    {"reason": "block_action", "risk_peak": 95}, NOW - timedelta(hours=1, minutes=42))

    # Device registration events
    _sys(hfb_id, "device.registered", "device", u_devs[hfb_u["CUST-0000012"]][1] if len(u_devs.get(hfb_u["CUST-0000012"], [])) > 1 else u_devs[hfb_u["CUST-0000012"]][0], {"device_name": "Firefox on Ubuntu", "trust_level": "new"}, NOW - timedelta(days=1))
    _sys(hfb_id, "device.registered", "device", u_devs[hfb_u["CUST-0000017"]][1] if len(u_devs.get(hfb_u["CUST-0000017"], [])) > 1 else u_devs[hfb_u["CUST-0000017"]][0], {"device_name": "Chrome on Windows", "trust_level": "new"}, NOW - timedelta(days=1))
    _sys(afs_id, "device.registered", "device", u_devs[afs_u["CUST-0000026"]][1] if len(u_devs.get(afs_u["CUST-0000026"], [])) > 1 else u_devs[afs_u["CUST-0000026"]][0], {"device_name": "Edge on Windows", "trust_level": "new"}, NOW - timedelta(days=3))
    _sys(ndb_id, "device.registered", "device", u_devs[ndb_u["CUST-0000043"]][1] if len(u_devs.get(ndb_u["CUST-0000043"], [])) > 1 else u_devs[ndb_u["CUST-0000043"]][0], {"device_name": "Edge on Windows", "trust_level": "new"}, NOW - timedelta(days=4))

    # PAM session events
    _sys(hfb_id, "pam.session.start", "privileged_session", "EMP-0000006", {"role": "Operations Analyst", "system": "Admin-Portal"}, NOW - timedelta(hours=4))
    _sys(hfb_id, "pam.anomaly.detected", "privileged_session", "EMP-0000006", {"flags": ["unauthorized_system_access", "bulk_record_access", "high_action_velocity"], "risk_score": 69}, NOW - timedelta(hours=3, minutes=45))
    _sys(hfb_id, "pam.session.end",   "privileged_session", "EMP-0000006", {"duration_hours": 0.5, "actions_count": 145, "records_accessed": 720}, NOW - timedelta(hours=3, minutes=30))
    _sys(hfb_id, "pam.session.start", "privileged_session", "EMP-0000005", {"role": "Reporting Analyst", "system": "Reporting-DB"}, NOW - timedelta(hours=3))
    _sys(hfb_id, "pam.anomaly.detected", "privileged_session", "EMP-0000005", {"flags": ["unauthorized_system_access", "large_data_export"], "risk_score": 71}, NOW - timedelta(hours=2, minutes=30))
    _sys(afs_id, "pam.session.start", "privileged_session", "EMP-0000012", {"role": "IT Operations Analyst", "system": "Admin-Portal"}, NOW - timedelta(hours=4, minutes=30))
    _sys(afs_id, "pam.anomaly.detected", "privileged_session", "EMP-0000012", {"flags": ["unauthorized_system_access", "bulk_record_access", "high_action_velocity"], "risk_score": 75}, NOW - timedelta(hours=4, minutes=15))
    _sys(ndb_id, "pam.session.start", "privileged_session", "EMP-0000018", {"role": "Platform Operations Analyst", "system": "Admin-Portal"}, NOW - timedelta(hours=4, minutes=45))
    _sys(ndb_id, "pam.anomaly.detected", "privileged_session", "EMP-0000018", {"flags": ["unauthorized_system_access", "bulk_record_access", "high_action_velocity"], "risk_score": 81}, NOW - timedelta(hours=4, minutes=30))

    # Onboarding decision events
    for ref, inst_id, admin_id, ip, decision_str, h_ago in [
        ("KYC-2025-00001", hfb_id, hfb_compliance_id, "103.87.4.23", "approve",        33),
        ("KYC-2025-00002", hfb_id, hfb_compliance_id, "103.87.4.23", "approve",        28),
        ("KYC-2025-00003", hfb_id, hfb_analyst2_id,   "103.87.4.22", "approve",        20),
        ("KYC-2025-00009", hfb_id, hfb_compliance_id, "103.87.4.23", "reject",          8),
        ("KYC-2025-00010", hfb_id, hfb_analyst2_id,   "103.87.4.22", "reject",          5),
        ("KYC-2025-00012", afs_id, afs_compliance_id, "49.32.18.7",  "approve",        31),
        ("KYC-2025-00013", afs_id, afs_compliance_id, "49.32.18.7",  "approve",        26),
        ("KYC-2025-00018", afs_id, afs_compliance_id, "49.32.18.7",  "reject",          7),
        ("KYC-2025-00022", ndb_id, ndb_compliance_id, "117.96.12.43", "approve",       30),
        ("KYC-2025-00023", ndb_id, ndb_analyst2_id,   "117.96.12.42", "approve",       23),
        ("KYC-2025-00029", ndb_id, ndb_compliance_id, "117.96.12.43", "reject",         6),
    ]:
        _adm(inst_id, admin_id, "onboarding.decision", "onboarding_application", ref, {"decision": decision_str, "ref": ref}, ip, NOW - timedelta(hours=h_ago))

    # Risk score updates
    _sys(hfb_id, "risk.score_updated", "user", hfb_u["CUST-0000017"], {"old_score": 82, "new_score": 88, "trigger": "session_evaluation"}, NOW - timedelta(hours=1, minutes=50))
    _sys(hfb_id, "risk.score_updated", "user", hfb_u["CUST-0000016"], {"old_score": 58, "new_score": 65, "trigger": "impossible_travel_alert"}, NOW - timedelta(hours=3))
    _sys(afs_id, "risk.score_updated", "user", afs_u["CUST-0000034"], {"old_score": 85, "new_score": 91, "trigger": "session_evaluation"}, NOW - timedelta(hours=1, minutes=45))
    _sys(ndb_id, "risk.score_updated", "user", ndb_u["CUST-0000051"], {"old_score": 88, "new_score": 93, "trigger": "session_evaluation"}, NOW - timedelta(hours=1, minutes=48))

    # System daily report & auto-prioritisation events
    _sys(hfb_id, "system.daily_report",           "institution", hfb_id, {"report_type": "daily_risk_summary", "open_alerts": 9,  "sessions_today": 18}, NOW - timedelta(hours=7))
    _sys(afs_id, "system.daily_report",           "institution", afs_id, {"report_type": "daily_risk_summary", "open_alerts": 8,  "sessions_today": 19}, NOW - timedelta(hours=7))
    _sys(ndb_id, "system.daily_report",           "institution", ndb_id, {"report_type": "daily_risk_summary", "open_alerts": 9,  "sessions_today": 20}, NOW - timedelta(hours=7))
    _sys(hfb_id, "system.alert_prioritisation",   "institution", hfb_id, {"updated_count": 6,  "method": "ml_priority_refresh"}, NOW - timedelta(hours=6))
    _sys(afs_id, "system.alert_prioritisation",   "institution", afs_id, {"updated_count": 5,  "method": "ml_priority_refresh"}, NOW - timedelta(hours=6))
    _sys(ndb_id, "system.alert_prioritisation",   "institution", ndb_id, {"updated_count": 6,  "method": "ml_priority_refresh"}, NOW - timedelta(hours=6))
    _sys(hfb_id, "system.device_trust_decay",     "institution", hfb_id, {"decayed_count": 2, "reason": "inactivity_7d"}, NOW - timedelta(hours=12))
    _sys(afs_id, "system.device_trust_decay",     "institution", afs_id, {"decayed_count": 2, "reason": "inactivity_7d"}, NOW - timedelta(hours=12))
    _sys(ndb_id, "system.device_trust_decay",     "institution", ndb_id, {"decayed_count": 3, "reason": "inactivity_7d"}, NOW - timedelta(hours=12))

    # Force step-up events by analysts
    _adm(hfb_id, hfb_analyst1_id, "user.force_stepup", "user", hfb_u["CUST-0000017"], {"reason": "Manual review initiated for critical risk score", "triggered_by": "analyst"}, "103.87.4.21", NOW - timedelta(hours=1, minutes=30))
    _adm(afs_id, afs_analyst1_id, "user.force_stepup", "user", afs_u["CUST-0000034"], {"reason": "ATO alert - manual step-up override", "triggered_by": "analyst"}, "49.32.18.5", NOW - timedelta(hours=1, minutes=28))
    _adm(ndb_id, ndb_analyst1_id, "user.force_stepup", "user", ndb_u["CUST-0000051"], {"reason": "Critical session from foreign IP - analyst override", "triggered_by": "analyst"}, "117.96.12.41", NOW - timedelta(hours=1, minutes=30))

    # Session evaluation events
    _sys(hfb_id, "risk.session_evaluated", "session", hfb_s["active_critical_1"],    {"risk_peak": 92, "events_count": 5, "action": "block"}, NOW - timedelta(hours=1, minutes=40))
    _sys(afs_id, "risk.session_evaluated", "session", afs_s["active_critical_1"],    {"risk_peak": 94, "events_count": 5, "action": "block"}, NOW - timedelta(hours=1, minutes=38))
    _sys(ndb_id, "risk.session_evaluated", "session", ndb_s["active_critical_1"],    {"risk_peak": 95, "events_count": 5, "action": "block"}, NOW - timedelta(hours=1, minutes=42))

    # Auto-alert task processed events
    _sys(hfb_id, "alert.created_task_processed", "alert", a_hfb8, {"processing_time_ms": 142, "queue": "celery_alerts"}, NOW - timedelta(hours=1, minutes=58))
    _sys(afs_id, "alert.created_task_processed", "alert", a_afs7, {"processing_time_ms": 138, "queue": "celery_alerts"}, NOW - timedelta(hours=1, minutes=58))
    _sys(ndb_id, "alert.created_task_processed", "alert", a_ndb8, {"processing_time_ms": 145, "queue": "celery_alerts"}, NOW - timedelta(hours=1, minutes=55))

    # Analyst note updates / assignments for investigating alerts
    _adm(hfb_id, hfb_analyst1_id, "alert.assigned", "alert", a_hfb3, {"assigned_to": hfb_analyst1_id, "note": "Taking over investigation"}, "103.87.4.21", NOW - timedelta(hours=5, minutes=45))
    _adm(afs_id, afs_analyst1_id, "alert.assigned", "alert", a_afs3, {"assigned_to": afs_analyst1_id, "note": "Escalated - reviewing session history"}, "49.32.18.5", NOW - timedelta(hours=4, minutes=50))
    _adm(ndb_id, ndb_analyst1_id, "alert.assigned", "alert", a_ndb3, {"assigned_to": ndb_analyst1_id, "note": "Assigning to self for deep-dive"}, "117.96.12.41", NOW - timedelta(hours=4, minutes=45))

    # Auto-prioritisation of existing open alerts
    _sys(hfb_id, "alert.auto_prioritise", "alert", a_hfb1, {"old_priority": 0.92, "new_priority": 0.96, "reason": "active_session_user"}, NOW - timedelta(hours=1))
    _sys(afs_id, "alert.auto_prioritise", "alert", a_afs1, {"old_priority": 0.93, "new_priority": 0.97, "reason": "active_session_user"}, NOW - timedelta(hours=1))
    _sys(ndb_id, "alert.auto_prioritise", "alert", a_ndb1, {"old_priority": 0.94, "new_priority": 0.97, "reason": "active_session_user"}, NOW - timedelta(hours=1))

    # End of seed - all data committed successfully