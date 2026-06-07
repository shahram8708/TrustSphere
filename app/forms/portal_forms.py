"""Forms for the customer security portal."""

from flask_wtf import FlaskForm
from wtforms import BooleanField, DecimalField, HiddenField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional

from app.utils.validators import SafeString


class DeviceNameForm(FlaskForm):
    """Rename a registered device."""

    device_name = StringField(
        "Device Name",
        validators=[DataRequired(), Length(min=1, max=100), SafeString()],
    )
    device_id = HiddenField()
    submit = SubmitField("Save Name")


class RecoveryInitiateForm(FlaskForm):
    """Start an account recovery request."""

    account_identifier = StringField(
        "Your Account Email or User ID",
        description="Enter the email address or user ID associated with your account.",
        validators=[DataRequired(), Length(min=3, max=200)],
    )
    recovery_reason = SelectField(
        "Reason for Recovery",
        choices=[
            ("forgot_password", "Forgot Password"),
            ("account_locked", "Account Locked"),
            ("lost_device", "Lost Access Device"),
            ("suspicious_activity", "Suspicious Activity on Account"),
            ("other", "Other"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Start Recovery")


class RecoveryVerifyForm(FlaskForm):
    """Verify a recovery challenge."""

    verification_code = StringField(
        "Verification Code",
        description="Enter the code sent to your registered contact method.",
        validators=[DataRequired(), Length(min=4, max=10)],
    )
    challenge_id = HiddenField()
    submit = SubmitField("Verify and Recover Access")


class PreferencesForm(FlaskForm):
    """Customer security communication preferences."""

    preferred_stepup_method = SelectField(
        "Preferred Step Up Verification",
        choices=[
            ("push_notification", "Push Notification, fastest"),
            ("otp", "SMS One Time Password"),
            ("biometric", "Biometric, fingerprint or face"),
        ],
        validators=[DataRequired()],
    )
    email_alerts_enabled = BooleanField("Receive security alerts by email")
    sms_alerts_enabled = BooleanField("Receive security alerts by SMS")
    high_value_transaction_alert = BooleanField("Alert me for transactions above a threshold")
    transaction_alert_threshold = DecimalField(
        "Alert Threshold Amount, INR",
        places=2,
        description="You will be alerted for transactions above this amount.",
        validators=[Optional(), NumberRange(min=100, max=10000000)],
    )
    new_device_alert = BooleanField(
        "Alert me when a new device accesses my account",
        default=True,
    )
    foreign_login_alert = BooleanField(
        "Alert me for logins from outside India",
        default=True,
    )
    language = SelectField(
        "Preferred Language",
        choices=[
            ("en", "English"),
            ("hi", "Hindi"),
            ("mr", "Marathi"),
            ("ta", "Tamil"),
            ("te", "Telugu"),
            ("kn", "Kannada"),
            ("gu", "Gujarati"),
            ("bn", "Bengali"),
        ],
    )
    submit = SubmitField("Save Preferences")
