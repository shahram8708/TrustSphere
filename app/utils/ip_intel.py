"""Deterministic IP intelligence helpers for risk scoring."""

from __future__ import annotations

import hashlib
import ipaddress


LOCATIONS = [
    ("IN", "Mumbai"),
    ("IN", "Delhi"),
    ("IN", "Bengaluru"),
    ("IN", "Chennai"),
    ("US", "New York"),
    ("GB", "London"),
    ("SG", "Singapore"),
    ("DE", "Frankfurt"),
]

VPN_PREFIXES = ("45.83.", "89.187.", "138.199.", "185.159.")
TOR_PREFIXES = ("185.220.", "199.249.", "171.25.")
PROXY_PREFIXES = ("104.244.", "146.70.", "172.105.")


def get_client_ip(request_obj):
    """Extract the best available client IP from a Flask request object."""
    value = request_obj.headers.get("X-Forwarded-For", "")
    if value:
        value = value.split(",", 1)[0].strip()
    if not value:
        value = request_obj.headers.get("X-Real-IP", "").strip()
    if not value:
        value = (request_obj.remote_addr or "").strip()

    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1 and "." in value:
        return value.rsplit(":", 1)[0]
    return value


def anonymise_ip(ip_string):
    """Return an anonymised IP with the final IPv4 octet or IPv6 hextet zeroed."""
    try:
        address = ipaddress.ip_address(ip_string)
    except ValueError:
        return ""

    if address.version == 4:
        parts = str(address).split(".")
        parts[-1] = "0"
        return ".".join(parts)

    value = int(address)
    value = (value >> 16) << 16
    return str(ipaddress.IPv6Address(value))


def _is_private_or_loopback(ip_string):
    try:
        address = ipaddress.ip_address(ip_string)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def _location_for_ip(ip_string):
    digest = hashlib.sha256(ip_string.encode("utf-8")).hexdigest()
    index = int(digest[:4], 16) % len(LOCATIONS)
    return LOCATIONS[index]


def get_ip_info(ip_string):
    """Return deterministic location and proxy risk information for an IP."""
    ip_string = ip_string or ""
    if _is_private_or_loopback(ip_string):
        return {
            "country": "IN",
            "city": "Mumbai",
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False,
            "risk_score": 0,
        }

    is_vpn = ip_string.startswith(VPN_PREFIXES)
    is_tor = ip_string.startswith(TOR_PREFIXES)
    is_proxy = ip_string.startswith(PROXY_PREFIXES)
    country, city = _location_for_ip(ip_string)

    if is_vpn or is_tor or is_proxy:
        risk_score = 70
    elif country != "IN":
        risk_score = 30
    else:
        risk_score = 5

    return {
        "country": country,
        "city": city,
        "is_vpn": is_vpn,
        "is_tor": is_tor,
        "is_proxy": is_proxy,
        "risk_score": risk_score,
    }


def detect_impossible_travel(last_ip, current_ip, elapsed_seconds):
    """Detect improbable location change between two IP observations."""
    last_info = get_ip_info(last_ip)
    current_info = get_ip_info(current_ip)
    if last_info["country"] != current_info["country"] and elapsed_seconds < 3600:
        elapsed_minutes = max(int(elapsed_seconds // 60), 0)
        explanation = (
            f"Location changed from {last_info['city']} to {current_info['city']} "
            f"in {elapsed_minutes} minutes, impossible travel detected"
        )
        return True, explanation
    return False, ""


def compute_network_risk_score(ip_string):
    """Return a deterministic network risk score from 0 to 100."""
    ip_string = ip_string or ""
    if _is_private_or_loopback(ip_string):
        return 0
    if ip_string.startswith(TOR_PREFIXES):
        return 85
    if ip_string.startswith(VPN_PREFIXES) or ip_string.startswith(PROXY_PREFIXES):
        return 65
    digest = hashlib.sha256(ip_string.encode("utf-8")).hexdigest()
    return 15 + (int(digest[:2], 16) % 11)


def get_location_novelty_score(user_id, current_country, current_city):
    """Score whether a user location is new based on recent sessions."""
    from app.models import SessionRecord

    recent_sessions = (
        SessionRecord.query.filter_by(user_id=user_id)
        .order_by(SessionRecord.started_at.desc())
        .limit(10)
        .all()
    )
    countries = {session.ip_country for session in recent_sessions if session.ip_country}
    cities = {
        (session.ip_country, session.ip_city)
        for session in recent_sessions
        if session.ip_country and session.ip_city
    }

    if current_country not in countries:
        return 40
    if (current_country, current_city) not in cities:
        return 20
    return 0
