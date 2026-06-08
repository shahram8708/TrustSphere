"""Public marketing routes for TrustSphere."""

from __future__ import annotations

from datetime import datetime

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.exceptions import NotFound

from app.forms import ContactForm, DemoRequestForm
from app.services import AuditLogger
from app.extensions import limiter


public_bp = Blueprint("public", __name__)


def _features():
    return [
        {
            "id": 1,
            "icon": "bi-cpu-fill",
            "name": "Continuous Risk Engine",
            "tagline": "Real time identity confidence scoring for every session event.",
            "description": "The Continuous Risk Engine combines device, behaviour, network, session, transaction, and account context into a normalised score from 0 to 100. It helps banking teams respond proportionately instead of interrupting every customer with the same static challenge.",
            "why_it_exists": "Static authentication treats a session as trusted after login, even when the device, network, or behaviour changes minutes later. Continuous scoring keeps trust current throughout the session.",
            "user_workflow_steps": [
                "Collect passive signals when a customer or employee begins a session.",
                "Weight each signal according to the active institutional policy.",
                "Normalise the composite score and classify the current risk tier.",
                "Return an allow, monitor, step up, or block recommendation.",
            ],
            "data_inputs": ["Device fingerprint", "Network risk", "Behavioural deviation", "Transaction context", "Policy thresholds"],
            "outputs": ["Risk score", "Risk tier", "Recommended action", "Contributing factors"],
            "technical_details": "Risk is calculated as a weighted ensemble of signal families and passed through sigmoid normalisation to keep scores stable at the edges. Low scores allow silent completion, medium scores increase monitoring, high scores trigger step up checks, and critical scores can block or quarantine the session.",
        },
        {
            "id": 2,
            "icon": "bi-fingerprint",
            "name": "Behavioural Biometrics Engine",
            "tagline": "Passive verification through interaction patterns that are difficult to copy.",
            "description": "TrustSphere builds anonymised behavioural baselines from typing rhythm, pointer movement, touch pressure, scroll cadence, and interaction timing. The platform stores feature vectors rather than raw biometric content.",
            "why_it_exists": "Passwords, OTPs, and devices can be stolen, but the way a legitimate user interacts with a banking interface is much harder to replicate at scale.",
            "user_workflow_steps": [
                "Observe interaction timing during normal authenticated activity.",
                "Update the behavioural profile only when confidence is sufficient.",
                "Compare current vectors with the stored baseline in real time.",
                "Feed deviation scores to the Continuous Risk Engine.",
            ],
            "data_inputs": ["Typing vector", "Mouse vector", "Touch vector", "Timing vector", "Profile confidence"],
            "outputs": ["Similarity score", "Deviation score", "Profile confidence", "Risk contribution"],
            "technical_details": "Current interaction vectors are compared with the stored baseline using cosine similarity. Low similarity increases the behavioural deviation component, while low confidence profiles contribute less to the final score.",
        },
        {
            "id": 3,
            "icon": "bi-phone-vibrate",
            "name": "Device Intelligence & Fingerprinting",
            "tagline": "Persistent device trust without relying on a single browser cookie.",
            "description": "The device module evaluates stable hardware and software traits, root or emulator indicators, browser family, operating system family, and device history. It assigns trust levels such as new, known, trusted, or suspicious.",
            "why_it_exists": "Account takeover often begins from a new browser, a cloned device, an emulator, or a compromised mobile environment. Device intelligence gives the risk engine an early signal before money movement or profile changes occur.",
            "user_workflow_steps": [
                "Generate a privacy preserving device fingerprint hash.",
                "Compare the fingerprint against known devices for the user and institution.",
                "Detect rooted, jailbroken, emulated, or unstable environments.",
                "Update the device trust level after successful low risk usage.",
            ],
            "data_inputs": ["Fingerprint hash", "Operating system", "Browser family", "Root indicators", "Device history"],
            "outputs": ["Device trust level", "Device risk score", "New device alert", "Root or emulator flag"],
            "technical_details": "Fuzzy fingerprinting tolerates small browser and operating system changes while still identifying meaningful device drift. Trusted devices reduce friction, new devices increase monitoring, and suspicious devices can require stronger verification.",
        },
        {
            "id": 4,
            "icon": "bi-person-check",
            "name": "KYC Onboarding Risk Assessment",
            "tagline": "Risk scored onboarding before account activation.",
            "description": "TrustSphere evaluates document authenticity, liveness, onboarding behaviour, watchlist matches, and synthetic identity indicators. The output is a composite onboarding score with approve, manual review, or reject recommendations.",
            "why_it_exists": "Synthetic identities, scripted applications, document tampering, and deepfake assisted onboarding can enter the banking lifecycle before ordinary transaction monitoring sees any activity.",
            "user_workflow_steps": [
                "Receive document, liveness, and onboarding telemetry from the bank workflow.",
                "Calculate a composite score from authenticity, liveness, behaviour, watchlist, and synthetic identity signals.",
                "Assign a decision tier for approval, review, or rejection.",
                "Preserve the decision evidence in the audit trail.",
            ],
            "data_inputs": ["Document score", "Liveness score", "Behaviour score", "Watchlist result", "Synthetic identity signal"],
            "outputs": ["Composite onboarding score", "Decision tier", "Risk flags", "Reviewer evidence"],
            "technical_details": "The composite formula weights document authenticity, liveness, onboarding behaviour, watchlist status, and synthetic identity likelihood. Scores below 40 can be approved, scores from 40 to 70 require review, and scores above 70 are high risk.",
        },
        {
            "id": 5,
            "icon": "bi-key-fill",
            "name": "Account Recovery Risk Shield",
            "tagline": "Recovery flows that adapt to identity risk.",
            "description": "The recovery shield evaluates the risk of reset and account recovery requests before allowing email, SMS, help desk, or video based recovery paths. Higher risk requests require stronger channels.",
            "why_it_exists": "Attackers frequently bypass login controls by abusing recovery journeys, social engineering support teams, or redirecting OTP based flows.",
            "user_workflow_steps": [
                "Score recovery requests using device, location, account age, and behavioural context.",
                "Select a recovery channel that matches the current risk level.",
                "Require stronger proof for high risk or anomalous recovery attempts.",
                "Log every recovery decision for audit and compliance review.",
            ],
            "data_inputs": ["Account age", "Known device status", "Location novelty", "Recent failures", "Recovery channel"],
            "outputs": ["Recovery risk tier", "Allowed channel", "Step up requirement", "Recovery audit event"],
            "technical_details": "Low risk recovery can use standard verified channels. Medium risk can require additional OTP or device confirmation. High risk can route to assisted review, video KYC, or temporary account protection.",
        },
        {
            "id": 6,
            "icon": "bi-shield-lock",
            "name": "Privileged Access Monitoring",
            "tagline": "Continuous insider threat detection for sensitive employee actions.",
            "description": "TrustSphere monitors employee access to privileged systems, records viewed, export volume, action frequency, timing, and behavioural drift. It prioritises sessions that show unusual or excessive activity.",
            "why_it_exists": "Insider misuse and compromised employee accounts are often invisible to customer fraud systems because the activity occurs through authorised internal channels.",
            "user_workflow_steps": [
                "Start monitoring when an employee opens a privileged session.",
                "Compare activity volume and access patterns against the employee baseline.",
                "Flag anomalous exports, unusual systems, or excessive records viewed.",
                "Generate alerts for analyst investigation when thresholds are crossed.",
            ],
            "data_inputs": ["Privilege level", "System accessed", "Action count", "Records accessed", "Export volume"],
            "outputs": ["PAM risk score", "Anomaly flags", "Insider alert", "Session evidence"],
            "technical_details": "Threshold based anomaly detection compares current privileged activity against role, user, and institution baselines. Multiple moderate anomalies can combine into a high priority insider risk alert.",
        },
        {
            "id": 7,
            "icon": "bi-shield-check",
            "name": "Real Time Step Up Verification Orchestrator",
            "tagline": "The right verification method for the exact risk level.",
            "description": "The orchestrator chooses OTP, device confirmation, biometric challenge, video review, or temporary block based on policy, channel, user history, and risk score.",
            "why_it_exists": "A single step up method creates unnecessary friction for good users and insufficient protection for serious attacks. TrustSphere applies the minimum effective intervention.",
            "user_workflow_steps": [
                "Receive the current risk score and action context from the CRE.",
                "Read institution policy for channel specific thresholds.",
                "Select the strongest method required by the current risk tier.",
                "Return the outcome to the session and update risk accordingly.",
            ],
            "data_inputs": ["Risk score", "Channel", "Policy rules", "Available methods", "User history"],
            "outputs": ["Verification method", "Challenge status", "Risk update", "Final decision"],
            "technical_details": "Method selection is policy driven. Low risk actions proceed silently, medium risk can request OTP or push confirmation, high risk can require biometric or assisted checks, and critical risk can block.",
        },
        {
            "id": 8,
            "icon": "bi-speedometer2",
            "name": "Security Operations Dashboard",
            "tagline": "Analyst ready visibility for identity risk and compliance evidence.",
            "description": "The SOC dashboard consolidates alerts, user risk profiles, session history, onboarding reviews, privileged access activity, policy changes, and audit logs. Analysts can triage by severity and machine ranked priority.",
            "why_it_exists": "Security teams need explainable risk evidence, not disconnected alerts that force manual correlation across fraud, IAM, KYC, and compliance tools.",
            "user_workflow_steps": [
                "Aggregate signals and alerts across every institution module.",
                "Rank alerts by severity, model priority, and operational impact.",
                "Expose the contributing factors behind each risk decision.",
                "Support audit review, reporting, and policy tuning from one interface.",
            ],
            "data_inputs": ["Alerts", "Sessions", "Risk events", "Audit logs", "Policy changes"],
            "outputs": ["Prioritised queue", "Analyst evidence", "Compliance report", "Operational metrics"],
            "technical_details": "Alert ranking combines severity, risk score movement, event age, customer impact, and model priority. This helps SOC teams focus first on active threats with the highest business impact.",
        },
    ]


def _compliance_frameworks():
    return [
        {
            "framework_name": "RBI Cybersecurity Framework",
            "framework_short": "RBI",
            "logo_text": "RBI",
            "color_class": "primary",
            "what_it_requires": ["Continuous monitoring", "Cyber incident reporting", "Access control", "Audit evidence"],
            "how_trustsphere_satisfies": ["Continuous Risk Engine", "Immutable audit log", "Privileged access monitoring", "Compliance reports"],
            "relevant_features": ["Continuous Risk Engine", "Audit Log", "PAM Module", "Compliance Reports"],
        },
        {
            "framework_name": "General Data Protection Regulation",
            "framework_short": "GDPR",
            "logo_text": "GDPR",
            "color_class": "info",
            "what_it_requires": ["Data minimisation", "Purpose limitation", "Security of processing", "Accountability"],
            "how_trustsphere_satisfies": ["Privacy preserving hashes", "No raw biometric storage", "Encrypted sensitive fields", "Access logging"],
            "relevant_features": ["Privacy Preserving Biometrics", "Encryption", "Audit Log", "Policy Controls"],
        },
        {
            "framework_name": "India Digital Personal Data Protection Act 2023",
            "framework_short": "DPDP",
            "logo_text": "DPDP",
            "color_class": "success",
            "what_it_requires": ["Consent aligned processing", "Personal data safeguards", "Breach accountability", "Data fiduciary governance"],
            "how_trustsphere_satisfies": ["Minimal identity telemetry", "Institution level controls", "Audit ready processing logs", "Indian data residency option"],
            "relevant_features": ["Data Minimisation", "Audit Log", "Compliance Reports", "Tenant Isolation"],
        },
        {
            "framework_name": "ISO 27001",
            "framework_short": "ISO",
            "logo_text": "ISO",
            "color_class": "secondary",
            "what_it_requires": ["Information security controls", "Risk treatment", "Access governance", "Continuous improvement"],
            "how_trustsphere_satisfies": ["Configurable risk policy", "Role based access", "Evidence generation", "Operational monitoring"],
            "relevant_features": ["Risk Policy", "Role Based Access", "Audit Trail", "SOC Dashboard"],
        },
        {
            "framework_name": "PCI DSS",
            "framework_short": "PCI",
            "logo_text": "PCI",
            "color_class": "warning",
            "what_it_requires": ["Strong access control", "Logging and monitoring", "Secure authentication", "Cardholder environment protection"],
            "how_trustsphere_satisfies": ["Step up orchestration", "Session monitoring", "Admin access control", "Device intelligence"],
            "relevant_features": ["Step Up Orchestrator", "Session Monitor", "Device Intelligence", "Audit Log"],
        },
        {
            "framework_name": "PSD2 Strong Customer Authentication",
            "framework_short": "PSD2",
            "logo_text": "SCA",
            "color_class": "danger",
            "what_it_requires": ["Dynamic authentication", "Transaction risk analysis", "Strong customer authentication", "Fraud monitoring"],
            "how_trustsphere_satisfies": ["Context aware step up", "Transaction risk scoring", "Behavioural verification", "Continuous session analysis"],
            "relevant_features": ["Step Up Orchestrator", "Behavioural Biometrics", "CRE", "Transaction Risk"],
        },
    ]


def _pricing_tiers():
    return [
        {
            "name": "Starter",
            "monthly_price": "2,500",
            "currency": "$",
            "target": "Regional banks and fintech teams beginning continuous risk monitoring.",
            "highlight": False,
            "cta": "Get Started",
            "features": [
                "Up to 50K users",
                "Continuous Risk Engine",
                "Device Intelligence",
                "Basic compliance reports",
                "Email support",
            ],
        },
        {
            "name": "Growth",
            "monthly_price": "8,000",
            "currency": "$",
            "target": "Growing digital banks that need behavioural intelligence and API scale.",
            "highlight": True,
            "cta": "Start Trial",
            "features": [
                "Up to 500K users",
                "Behavioural Biometrics",
                "KYC onboarding risk",
                "API access",
                "Priority support",
            ],
        },
        {
            "name": "Enterprise",
            "monthly_price": "Custom",
            "currency": "",
            "target": "Large financial institutions requiring custom controls and deployment options.",
            "highlight": False,
            "cta": "Contact Sales",
            "features": [
                "Unlimited users",
                "Privileged Access Monitoring",
                "Custom risk policy",
                "White label portal",
                "Dedicated support",
            ],
        },
    ]


def _addons():
    return [
        {
            "name": "Video KYC Risk Review",
            "price_display": "$1,200/month",
            "description": "Adds video review routing for high risk onboarding and recovery flows.",
        },
        {
            "name": "Advanced PAM Analytics",
            "price_display": "$2,000/month",
            "description": "Adds deeper insider threat scoring for sensitive employee systems.",
        },
        {
            "name": "Custom ML Model Training",
            "price_display": "$3,500/month",
            "description": "Institution specific model tuning using approved anonymised telemetry.",
        },
        {
            "name": "White Label Customer Portal",
            "price_display": "$1,500/month",
            "description": "Custom branding for customer facing trust and recovery experiences.",
        },
        {
            "name": "Regulatory Evidence Pack",
            "price_display": "$900/month",
            "description": "Expanded audit exports mapped to RBI, DPDP, GDPR, ISO, PCI, and PSD2 controls.",
        },
    ]


def _faqs():
    return [
        ("Can I start with Starter and upgrade?", "Yes. Plan upgrades are seamless and billed on a prorated basis."),
        ("Is there a free trial?", "Growth tier includes a 30 day full feature trial for approved banking teams."),
        ("Where is our data stored?", "Indian data residency is available for institutions with DPDP compliance needs."),
        ("Can TrustSphere be deployed on our own servers?", "Enterprise customers can use an on premise deployment option."),
        ("What SLA do you offer?", "Starter includes 99.5 percent, Growth includes 99.9 percent, and Enterprise includes 99.99 percent."),
        ("How long does integration take?", "A full API integration typically takes 4 to 6 weeks depending on the bank environment."),
    ]


@public_bp.get("/")
def index():
    stats = {
        "ato_growth": "354%",
        "insider_threat_pct": "34%",
        "fraud_losses": "USD 485B",
        "upi_volume": "INR 21T",
    }
    return render_template(
        "public/index.html",
        features_count=8,
        stats=stats,
        demo_form=DemoRequestForm(),
    )


@public_bp.get("/about")
def about():
    return render_template("public/about.html")


@public_bp.get("/features")
def features():
    return render_template("public/features.html", features=_features())


@public_bp.get("/compliance")
def compliance():
    return render_template("public/compliance.html", frameworks=_compliance_frameworks())


@public_bp.get("/pricing")
def pricing():
    return render_template(
        "public/pricing.html",
        tiers=_pricing_tiers(),
        addons=_addons(),
        faqs=_faqs(),
    )


@public_bp.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    inquiry_type = request.args.get("inquiry_type")
    if request.method == "GET" and inquiry_type in dict(form.inquiry_type.choices):
        form.inquiry_type.data = inquiry_type

    if form.validate_on_submit():
        payload = {
            "full_name": form.full_name.data,
            "email": form.email.data.lower(),
            "bank_name": form.bank_name.data,
            "phone": form.phone.data,
            "inquiry_type": form.inquiry_type.data,
            "message": form.message.data,
            "submitted_at": datetime.utcnow().isoformat() + "Z",
        }
        current_app.config.setdefault("CONTACT_INQUIRIES", []).append(payload)
        from app.tasks.email_tasks import send_contact_form_notification_task

        send_contact_form_notification_task.delay(
            {
                "name": form.full_name.data,
                "email": form.email.data[:50],
                "bank": form.bank_name.data,
                "message": form.message.data[:200],
            }
        )
        AuditLogger.log(
            actor_type="system",
            actor_id=None,
            actor_email=None,
            action="contact.inquiry",
            details=payload,
        )
        flash("Thank you for reaching out. Our team will contact you within 1 business day.", "success")
        return redirect(url_for("public.contact"))

    return render_template("public/contact.html", form=form)


@public_bp.route("/demo", methods=["GET", "POST"])
def demo():
    form = DemoRequestForm()
    if form.validate_on_submit():
        payload = {
            "company_name": form.company_name.data,
            "contact_name": form.contact_name.data,
            "email": form.email.data.lower(),
            "phone": form.phone.data,
            "bank_size": form.bank_size.data,
            "current_solution": form.current_solution.data,
            "primary_challenge": form.primary_challenge.data,
            "message": form.message.data,
            "submitted_at": datetime.utcnow().isoformat() + "Z",
        }
        current_app.config.setdefault("DEMO_REQUESTS", []).append(payload)
        from app.tasks.email_tasks import send_demo_request_notification_task

        send_demo_request_notification_task.delay(
            {
                "company": form.company_name.data,
                "contact": form.contact_name.data,
                "email": form.email.data[:50],
            }
        )
        AuditLogger.log(
            actor_type="system",
            actor_id=None,
            actor_email=None,
            action="demo.request",
            details=payload,
        )
        flash(
            "Thank you for requesting a demo. Our solutions team will contact you within 4 business hours.",
            "success",
        )
        return redirect(url_for("public.demo"))

    return render_template("public/demo.html", form=form)


@public_bp.get("/api-docs")
def api_docs():
    return render_template("public/features.html", features=_features())


@public_bp.get("/sw.js")
@limiter.exempt
def serve_sw():
    fallback_body = (
        "// TrustSphere Service Worker\n"
        'self.addEventListener("install", () => {});\n'
        'self.addEventListener("activate", () => {});\n'
        'self.addEventListener("fetch", () => {});\n'
    )
    try:
        response = send_from_directory(
            current_app.static_folder,
            "sw.js",
            mimetype="application/javascript",
        )
    except (FileNotFoundError, NotFound):
        response = Response(fallback_body, status=200, mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Content-Type"] = "application/javascript; charset=utf-8"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@public_bp.get("/offline")
def offline():
    return render_template("offline.html")
