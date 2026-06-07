"""Validation and sanitisation helpers for TrustSphere forms and services."""

from __future__ import annotations

import hashlib
import re
import uuid

import bleach
from wtforms.validators import ValidationError


SPECIAL_CHARACTERS = set("!@#$%^&*()_+-=[]{}|;:,.<>?")


def validate_password_strength(password):
    """Return whether a password meets TrustSphere strength requirements."""
    password = password or ""
    missing = []
    if len(password) < 10:
        missing.append("at least 10 characters")
    if not any(character.isupper() for character in password):
        missing.append("one uppercase letter")
    if not any(character.islower() for character in password):
        missing.append("one lowercase letter")
    if not any(character.isdigit() for character in password):
        missing.append("one digit")
    if not any(character in SPECIAL_CHARACTERS for character in password):
        missing.append("one special character")

    if missing:
        return False, "Password must contain " + ", ".join(missing) + "."
    return True, ""


def validate_indian_phone(phone):
    """Validate and normalise an Indian mobile number."""
    if not phone:
        return False, "Phone number is required."

    value = re.sub(r"[\s().-]", "", str(phone).strip())
    if value.startswith("+91"):
        digits = value[3:]
    elif value.startswith("91") and len(value) == 12:
        digits = value[2:]
    elif value.startswith("0") and len(value) == 11:
        digits = value[1:]
    else:
        digits = value

    if re.fullmatch(r"[6-9]\d{9}", digits):
        return True, f"+91{digits}"
    return False, "Enter a valid 10 digit Indian mobile number."


def validate_email_domain(email, allowed_domains=None):
    """Validate email syntax and optionally restrict the domain."""
    value = (email or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return False, "Enter a valid email address."

    if allowed_domains:
        domain = value.rsplit("@", 1)[1]
        allowed = {item.strip().lower() for item in allowed_domains if item}
        if domain not in allowed:
            return False, "Email domain is not allowed for this institution."
    return True, ""


def sanitize_html(content, allowed_tags=None):
    """Strip unsafe HTML while preserving a small safe formatting subset."""
    tags = allowed_tags or ["b", "i", "em", "strong", "p", "br"]
    return bleach.clean(content or "", tags=tags, attributes={}, strip=True)


def validate_uuid(value):
    """Return true when the value is a valid UUID version 4 string."""
    try:
        parsed = uuid.UUID(str(value), version=4)
    except (TypeError, ValueError):
        return False
    return str(parsed) == str(value).lower()


def hash_identifier(value):
    """Return a privacy preserving SHA256 hash for an identifier."""
    return hashlib.sha256(str(value or "").strip().lower().encode("utf-8")).hexdigest()


class StrongPassword:
    """WTForms validator for TrustSphere password strength rules."""

    def __call__(self, form, field):
        is_valid, message = validate_password_strength(field.data)
        if not is_valid:
            raise ValidationError(message)


class NoSQLInjection:
    """WTForms validator that rejects common SQL injection indicators."""

    patterns = ("'", "--", ";", "UNION", "SELECT", "DROP", "INSERT")

    def __call__(self, form, field):
        value = str(field.data or "")
        upper_value = value.upper()
        if any(pattern in upper_value for pattern in self.patterns):
            raise ValidationError("Invalid characters detected.")


class SafeString:
    """WTForms validator that stores a sanitised string value."""

    def __call__(self, form, field):
        field.data = sanitize_html(field.data)
