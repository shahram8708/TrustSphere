"""Forms for TrustSphere admin SOC workflows."""

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    DateField,
    DecimalField,
    HiddenField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, NumberRange, Optional, ValidationError
from flask_wtf.file import FileField, FileRequired


class AlertActionForm(FlaskForm):
    """Validate alert lifecycle actions."""

    ALLOWED_ACTIONS = {
        "dismiss",
        "escalate",
        "block_user",
        "false_positive",
        "resolve",
        "assign",
        "notes",
    }

    action = HiddenField()
    notes = TextAreaField(
        "Investigation Notes",
        description="Add context about this action for the audit record.",
        validators=[Optional(), Length(max=2000)],
    )
    assign_to = SelectField(
        "Assign To Analyst",
        validators=[Optional()],
        choices=[("", "Select Analyst...")],
    )
    submit = SubmitField("Confirm Action")

    def validate_action(self, field):
        if field.data not in self.ALLOWED_ACTIONS:
            raise ValidationError("Invalid action.")


class UserActionForm(FlaskForm):
    """Validate user risk management actions."""

    ALLOWED_ACTIONS = {
        "suspend",
        "unsuspend",
        "force_stepup",
        "reset_behavioural_profile",
        "flag_high_risk",
        "clear_risk_score",
    }

    action = HiddenField()
    reason = TextAreaField(
        "Reason",
        description="Provide a reason for this action. This will be included in the audit log.",
        validators=[Optional(), Length(max=500)],
    )
    submit = SubmitField("Confirm")

    def validate_action(self, field):
        if field.data not in self.ALLOWED_ACTIONS:
            raise ValidationError("Invalid action.")


class SessionFilterForm(FlaskForm):
    """Filter admin session monitor results."""

    channel = SelectField(
        "Channel",
        choices=[
            ("", "All Channels"),
            ("web_browser", "Web Browser"),
            ("mobile_app", "Mobile App"),
            ("api", "API"),
            ("atm", "ATM"),
        ],
        validators=[Optional()],
    )
    risk_min = IntegerField(
        "Min Risk Score",
        default=0,
        validators=[Optional(), NumberRange(min=0, max=100)],
    )
    risk_max = IntegerField(
        "Max Risk Score",
        default=100,
        validators=[Optional(), NumberRange(min=0, max=100)],
    )
    is_flagged = SelectField(
        "Flag State",
        choices=[
            ("", "All Sessions"),
            ("true", "Flagged Only"),
            ("false", "Not Flagged"),
        ],
        validators=[Optional()],
    )
    is_active = SelectField(
        "Activity State",
        choices=[
            ("", "All"),
            ("true", "Active Only"),
            ("false", "Ended Only"),
        ],
        validators=[Optional()],
    )
    date_from = DateField("Date From", validators=[Optional()], format="%Y-%m-%d")
    date_to = DateField("Date To", validators=[Optional()], format="%Y-%m-%d")


class UserFilterForm(FlaskForm):
    """Filter admin user risk profiles."""

    search = StringField(
        "Search",
        description="Search by masked user ID or external user ID.",
        validators=[Optional(), Length(max=100)],
    )
    user_type = SelectField(
        "User Type",
        choices=[
            ("", "All Types"),
            ("customer", "Customer"),
            ("employee", "Employee"),
        ],
        validators=[Optional()],
    )
    risk_min = IntegerField("Min Risk Score", validators=[Optional(), NumberRange(min=0, max=100)])
    risk_max = IntegerField("Max Risk Score", validators=[Optional(), NumberRange(min=0, max=100)])
    is_suspended = SelectField(
        "Status",
        choices=[
            ("", "All"),
            ("false", "Active Only"),
            ("true", "Suspended Only"),
        ],
        validators=[Optional()],
    )


class OnboardingDecisionForm(FlaskForm):
    """Validate KYC onboarding review decisions."""

    decision = SelectField(
        "Decision",
        choices=[
            ("approve", "Approve Application"),
            ("manual_review", "Send to Manual Review"),
            ("reject", "Reject Application"),
        ],
        validators=[DataRequired()],
    )
    reviewer_notes = TextAreaField(
        "Reviewer Notes",
        validators=[Optional(), Length(max=2000)],
    )
    submit = SubmitField("Submit Decision")

    def validate_reviewer_notes(self, field):
        if self.decision.data == "reject" and not (field.data or "").strip():
            raise ValidationError("Notes are required when rejecting an application.")


class PolicyForm(FlaskForm):
    """Validate risk policy configuration."""

    policy_name = StringField(
        "Policy Name",
        validators=[DataRequired(), Length(min=3, max=100)],
    )
    threshold_low = IntegerField(
        "Low Risk Threshold (0 to this value)",
        validators=[DataRequired(), NumberRange(min=5, max=95)],
    )
    threshold_medium = IntegerField(
        "Medium Risk Threshold",
        validators=[DataRequired(), NumberRange(min=10, max=98)],
    )
    threshold_high = IntegerField(
        "High Risk Threshold",
        validators=[DataRequired(), NumberRange(min=15, max=99)],
    )
    stepup_rules_json = HiddenField()
    channel_policies_json = HiddenField()
    ml_weight_device = DecimalField(
        "Device Signal Weight",
        places=2,
        default=0.25,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    ml_weight_behavioural = DecimalField(
        "Behavioural Signal Weight",
        places=2,
        default=0.20,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    ml_weight_geographic = DecimalField(
        "Geographic Signal Weight",
        places=2,
        default=0.15,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    ml_weight_network = DecimalField(
        "Network Signal Weight",
        places=2,
        default=0.15,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    ml_weight_transaction = DecimalField(
        "Transaction Signal Weight",
        places=2,
        default=0.15,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    ml_weight_time = DecimalField(
        "Time Pattern Signal Weight",
        places=2,
        default=0.10,
        validators=[Optional(), NumberRange(min=0.0, max=1.0)],
    )
    submit = SubmitField("Save and Activate Policy")

    def validate_threshold_low(self, field):
        if self.threshold_medium.data is not None and field.data >= self.threshold_medium.data:
            raise ValidationError("Low threshold must be less than medium threshold.")

    def validate_threshold_medium(self, field):
        if self.threshold_high.data is not None and field.data >= self.threshold_high.data:
            raise ValidationError("Medium threshold must be less than high threshold.")

    def validate_threshold_high(self, field):
        if field.data >= 100:
            raise ValidationError("High threshold must be less than 100.")

    def _weight_sum(self):
        values = [
            self.ml_weight_device.data,
            self.ml_weight_behavioural.data,
            self.ml_weight_geographic.data,
            self.ml_weight_network.data,
            self.ml_weight_transaction.data,
            self.ml_weight_time.data,
        ]
        return sum(float(value or 0) for value in values)

    def _validate_weight_sum(self):
        total = self._weight_sum()
        if not 0.95 <= total <= 1.05:
            raise ValidationError(f"All signal weights must sum to 1.0. Current sum: {total:.2f}")

    def validate_ml_weight_device(self, field):
        self._validate_weight_sum()

    def validate_ml_weight_behavioural(self, field):
        self._validate_weight_sum()

    def validate_ml_weight_geographic(self, field):
        self._validate_weight_sum()

    def validate_ml_weight_network(self, field):
        self._validate_weight_sum()

    def validate_ml_weight_transaction(self, field):
        self._validate_weight_sum()

    def validate_ml_weight_time(self, field):
        self._validate_weight_sum()


class ReportForm(FlaskForm):
    """Validate compliance report generation parameters."""

    report_type = SelectField(
        "Report Type",
        choices=[
            ("rbi_report", "RBI Cybersecurity Framework Report"),
            ("alert_summary", "Alert Summary Report"),
            ("user_risk", "User Risk Distribution Report"),
            ("incident", "Incident Report"),
            ("gdpr_compliance", "GDPR Compliance Report"),
            ("iso27001", "ISO 27001 Controls Report"),
        ],
        validators=[DataRequired()],
    )
    date_from = DateField("From Date", validators=[Optional()], format="%Y-%m-%d")
    date_to = DateField("To Date", validators=[Optional()], format="%Y-%m-%d")
    format = SelectField(
        "Output Format",
        choices=[
            ("json", "JSON (Structured Data)"),
            ("csv", "CSV (Spreadsheet)"),
        ],
        validators=[DataRequired()],
    )
    institution_id = SelectField("Institution", validators=[Optional()], choices=[])
    alert_id = StringField(
        "Alert ID (for Incident Reports)",
        description="Required only for Incident Report type.",
        validators=[Optional(), Length(max=36)],
    )
    submit = SubmitField("Generate Report")

    def validate_date_from(self, field):
        if field.data and self.date_to.data and field.data > self.date_to.data:
            raise ValidationError("From date cannot be after to date.")

    def validate_alert_id(self, field):
        if self.report_type.data == "incident" and not (field.data or "").strip():
            raise ValidationError("Alert ID is required for Incident Reports.")


class SettingsForm(FlaskForm):
    """Validate super admin platform settings."""

    new_institution_name = StringField(
        "Institution Name",
        validators=[Optional(), Length(min=2, max=200)],
    )
    new_institution_domain = StringField(
        "Domain",
        validators=[Optional(), Length(min=4, max=100)],
    )
    new_institution_plan_tier = SelectField(
        "Plan Tier",
        choices=[
            ("starter", "Starter"),
            ("growth", "Growth"),
            ("enterprise", "Enterprise"),
        ],
    )
    mail_server = StringField("SMTP Server", validators=[Optional(), Length(max=200)])
    mail_port = IntegerField(
        "SMTP Port",
        validators=[Optional(), NumberRange(min=1, max=65535)],
    )
    mail_use_tls = BooleanField("Use TLS")
    mail_username = StringField("SMTP Username", validators=[Optional(), Length(max=200)])
    mail_password = PasswordField("SMTP Password (leave blank to keep current)", validators=[Optional()])
    platform_maintenance_mode = BooleanField("Maintenance Mode (disables all non admin access)")
    max_login_attempts = IntegerField(
        "Max Login Attempts Before Lockout",
        default=5,
        validators=[Optional(), NumberRange(min=3, max=20)],
    )
    session_timeout_minutes = IntegerField(
        "Admin Session Timeout (minutes)",
        default=30,
        validators=[Optional(), NumberRange(min=5, max=480)],
    )
    submit_settings = SubmitField("Save Platform Settings")
    submit_add_institution = SubmitField("Create Institution")


class SingleUserCreateForm(FlaskForm):
    """Form for IT admins to create a single end user (customer or employee)."""

    email = StringField("Email", validators=[DataRequired(), Length(max=200)])
    display_name = StringField("Display Name", validators=[Optional(), Length(max=200)])
    external_user_id = StringField("External User ID", validators=[Optional(), Length(max=100)])
    phone = StringField("Phone", validators=[Optional(), Length(max=32)])
    user_type = SelectField(
        "User Type",
        choices=[("customer", "Customer"), ("employee", "Employee")],
        validators=[DataRequired()],
    )
    institution_id = SelectField("Institution", choices=[], validators=[Optional()])
    submit = SubmitField("Create User")


class BulkUserUploadForm(FlaskForm):
    """Form for uploading CSV to create many users at once.

    Expected CSV headers: email,display_name,external_user_id,phone,user_type
    """

    csv_file = FileField("CSV File (UTF-8)", validators=[FileRequired()])
    default_user_type = SelectField(
        "Default User Type",
        choices=[("customer", "Customer"), ("employee", "Employee")],
        validators=[Optional()],
    )
    submit_upload = SubmitField("Upload and Create Users")
