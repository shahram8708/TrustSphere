"""Authentication and account recovery forms."""

import re

from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from app.models import AdminUser, Institution
from app.utils.validators import NoSQLInjection, SafeString, StrongPassword


def _normalise_domain(value):
    domain = (value or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].strip().strip(".")
    return domain


class LoginForm(FlaskForm):
    identifier = StringField("Email or User ID", validators=[DataRequired(), Length(min=1, max=200)])
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=1, max=256)],
    )
    remember_me = BooleanField("Keep me signed in for 30 days")
    submit = SubmitField("Sign In")

    def validate_identifier(self, field):
        raw = (field.data or "").strip()
        if "@" in raw:
            # treat as email: validate format and normalise to lowercase
            try:
                Email()(self, field)
            except ValidationError:
                raise
            field.data = raw.lower()
        else:
            field.data = raw


class RegisterForm(FlaskForm):
    institution_name = StringField(
        "Institution / Bank Name",
        validators=[DataRequired(), Length(min=2, max=200), SafeString()],
    )
    institution_domain = StringField(
        "Institution Domain",
        description="Example yourbank.com, used for API integration and JWT validation",
        validators=[DataRequired(), Length(min=4, max=100), NoSQLInjection()],
    )
    plan_tier = SelectField(
        "Plan",
        choices=[
            ("starter", "Starter, $2,500/month"),
            ("growth", "Growth, $8,000/month"),
            ("enterprise", "Enterprise, Custom Pricing"),
        ],
        validators=[DataRequired()],
    )
    admin_email = EmailField(
        "Administrator Email",
        validators=[DataRequired(), Email(), Length(max=200)],
    )
    admin_password = PasswordField(
        "Password",
        validators=[DataRequired(), StrongPassword()],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("admin_password", message="Passwords must match")],
    )
    agree_terms = BooleanField(
        "I agree to the Terms of Service and Privacy Policy",
        validators=[DataRequired(message="You must accept the terms to register")],
    )
    submit = SubmitField("Create Account")

    def validate_admin_email(self, field):
        email = (field.data or "").strip().lower()
        field.data = email
        if AdminUser.query.filter_by(email=email).first():
            raise ValidationError("An account with this email already exists.")

    def validate_institution_domain(self, field):
        domain = _normalise_domain(field.data)
        field.data = domain
        pattern = r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$"
        if not re.fullmatch(pattern, domain):
            raise ValidationError("Enter a valid institution domain.")
        if Institution.query.filter_by(domain=domain).first():
            raise ValidationError("An institution with this domain is already registered.")


class ForgotPasswordForm(FlaskForm):
    email = EmailField("Your Account Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[DataRequired(), StrongPassword()],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")],
    )
    submit = SubmitField("Set New Password")
