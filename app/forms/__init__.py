"""WTForms definitions for authentication, policy, alert, and portal workflows."""

from app.forms.auth_forms import (
    ForgotPasswordForm,
    LoginForm,
    RegisterForm,
    ResetPasswordForm,
)
from app.forms.admin_forms import (
    AlertActionForm,
    OnboardingDecisionForm,
    PolicyForm,
    ReportForm,
    SessionFilterForm,
    SettingsForm,
    UserActionForm,
    UserFilterForm,
)
from app.forms.portal_forms import (
    DeviceNameForm,
    PreferencesForm,
    RecoveryInitiateForm,
    RecoveryVerifyForm,
)
from app.forms.public_forms import ContactForm, DemoRequestForm

__all__ = [
    "AlertActionForm",
    "ContactForm",
    "DemoRequestForm",
    "DeviceNameForm",
    "ForgotPasswordForm",
    "LoginForm",
    "OnboardingDecisionForm",
    "PreferencesForm",
    "PolicyForm",
    "RegisterForm",
    "ReportForm",
    "RecoveryInitiateForm",
    "RecoveryVerifyForm",
    "ResetPasswordForm",
    "SessionFilterForm",
    "SettingsForm",
    "UserActionForm",
    "UserFilterForm",
]
