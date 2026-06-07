"""Utility package for masking, security helpers, data validation, and formatting."""

from app.utils.decorators import (
    admin_required,
    api_key_required,
    institution_required,
    rate_limit_user,
    read_only_forbidden,
    role_required,
    super_admin_required,
)
from app.utils.ip_intel import (
    anonymise_ip,
    compute_network_risk_score,
    detect_impossible_travel,
    get_client_ip,
    get_ip_info,
    get_location_novelty_score,
)
from app.utils.pagination import Pagination, get_page_from_request, paginate_query
from app.utils.response import (
    error_response,
    not_found_response,
    success_response,
    unauthorized_response,
    validation_error_response,
)
from app.utils.validators import (
    NoSQLInjection,
    SafeString,
    StrongPassword,
    hash_identifier,
    sanitize_html,
    validate_email_domain,
    validate_indian_phone,
    validate_password_strength,
    validate_uuid,
)

__all__ = [
    "admin_required",
    "api_key_required",
    "institution_required",
    "rate_limit_user",
    "read_only_forbidden",
    "role_required",
    "super_admin_required",
    "anonymise_ip",
    "compute_network_risk_score",
    "detect_impossible_travel",
    "get_client_ip",
    "get_ip_info",
    "get_location_novelty_score",
    "Pagination",
    "get_page_from_request",
    "paginate_query",
    "error_response",
    "not_found_response",
    "success_response",
    "unauthorized_response",
    "validation_error_response",
    "NoSQLInjection",
    "SafeString",
    "StrongPassword",
    "hash_identifier",
    "sanitize_html",
    "validate_email_domain",
    "validate_indian_phone",
    "validate_password_strength",
    "validate_uuid",
]
