"""Public website forms for inquiries and demo requests."""

from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Optional

from app.utils.validators import SafeString


INQUIRY_CHOICES = [
    ("demo", "Request a Demo"),
    ("pricing", "Pricing Information"),
    ("technical", "Technical Integration"),
    ("compliance", "Compliance & Regulatory"),
    ("partnership", "Partnership"),
    ("other", "Other"),
]


class ContactForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[DataRequired(), Length(min=2, max=100), SafeString()],
    )
    email = EmailField(
        "Business Email",
        validators=[DataRequired(), Email(), Length(max=200)],
    )
    bank_name = StringField(
        "Bank / Institution Name",
        validators=[DataRequired(), Length(min=2, max=200), SafeString()],
    )
    phone = StringField("Phone Number", validators=[Optional(), Length(max=20)])
    inquiry_type = SelectField(
        "Inquiry Type",
        choices=INQUIRY_CHOICES,
        validators=[DataRequired()],
    )
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=20, max=2000), SafeString()],
    )
    submit = SubmitField("Send Message")


class DemoRequestForm(FlaskForm):
    company_name = StringField(
        "Bank / Institution Name",
        validators=[DataRequired(), Length(min=2, max=200), SafeString()],
    )
    contact_name = StringField(
        "Your Full Name",
        validators=[DataRequired(), Length(min=2, max=100), SafeString()],
    )
    email = EmailField(
        "Business Email",
        validators=[DataRequired(), Email(), Length(max=200)],
    )
    phone = StringField(
        "Phone Number",
        validators=[DataRequired(), Length(min=7, max=20)],
    )
    bank_size = SelectField(
        "Institution Size",
        choices=[
            ("small", "Small under 50K customers"),
            ("medium", "Medium 50K to 500K customers"),
            ("large", "Large 500K to 5M customers"),
            ("enterprise", "Enterprise 5M plus customers"),
        ],
        validators=[DataRequired()],
    )
    current_solution = StringField(
        "Current Security Solution",
        validators=[Optional(), Length(max=200), SafeString()],
    )
    primary_challenge = SelectField(
        "Primary Challenge",
        choices=[
            ("ato", "Account Takeover / Credential Stuffing"),
            ("insider", "Insider Threats"),
            ("kyc", "KYC & Onboarding Fraud"),
            ("compliance", "Regulatory Compliance"),
            ("analytics", "Fraud Analytics & Reporting"),
            ("other", "Other"),
        ],
        validators=[DataRequired()],
    )
    message = TextAreaField(
        "Additional Information",
        validators=[Optional(), Length(max=1000), SafeString()],
    )
    agree_contact = BooleanField(
        "I agree to be contacted by TrustSphere regarding this request",
        validators=[DataRequired()],
    )
    submit = SubmitField("Request Demo")
