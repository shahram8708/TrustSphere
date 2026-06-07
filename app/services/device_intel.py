"""Device fingerprint registration and trust assessment."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import sys

from app.extensions import db
from app.services.audit import AuditLogger


class DeviceIntelligenceService:
    """Manage device trust levels and suspicious environment signals."""

    EMULATOR_STRINGS = {
        "generic",
        "android sdk",
        "emulator",
        "genymotion",
        "bluestacks",
        "nox",
        "ldplayer",
        "memu",
        "virtualbox",
        "vmware",
        "parallels",
        "qemu",
    }
    ROOT_INDICATORS = {
        "supersu",
        "magisk",
        "kingroot",
        "towelroot",
        "cf-auto-root",
        "framaroot",
    }

    @classmethod
    def register_or_update_device(cls, user_id, institution_id, fingerprint_hash, attributes_dict):
        """Register a new device or refresh a known device."""
        try:
            from app.models import Device

            attributes = attributes_dict or {}
            suspicious_flags = cls._check_suspicious_indicators(attributes)
            device = Device.query.filter_by(
                user_id=user_id,
                device_fingerprint_hash=fingerprint_hash,
                is_removed=False,
            ).first()
            is_new = device is None

            if device:
                device.last_seen_at = datetime.utcnow()
                cls._copy_known_attributes(device, attributes)
                if suspicious_flags:
                    device.trust_level = "suspicious"
                elif (
                    device.trust_level == "new"
                    and device.first_seen_at
                    and device.first_seen_at <= datetime.utcnow() - timedelta(days=7)
                ):
                    device.trust_level = "known"
            else:
                device = Device(
                    user_id=user_id,
                    institution_id=institution_id,
                    device_fingerprint_hash=fingerprint_hash,
                    device_name=attributes.get("device_name") or "Unknown Device",
                    device_type=attributes.get("device_type") or "desktop",
                    os_family=attributes.get("os_family"),
                    browser_family=attributes.get("browser_family"),
                    trust_level="suspicious" if suspicious_flags else "new",
                    is_rooted=bool(attributes.get("is_rooted")),
                    is_emulator=bool(attributes.get("is_emulator")),
                    first_seen_at=datetime.utcnow(),
                    last_seen_at=datetime.utcnow(),
                    is_removed=False,
                )

            db.session.add(device)
            AuditLogger.log(
                actor_type="system",
                actor_id=None,
                action="device.registered" if is_new else "device.updated",
                institution_id=institution_id,
                target_type="device",
                target_id=device.id,
                details={
                    "user_id": user_id,
                    "trust_level": device.trust_level,
                    "suspicious_flags": suspicious_flags,
                },
                commit=False,
            )
            db.session.commit()

            return {
                "device_id": device.id,
                "trust_level": device.trust_level,
                "is_new": is_new,
                "is_suspicious": bool(suspicious_flags),
                "suspicious_flags": suspicious_flags,
            }
        except Exception as exc:
            db.session.rollback()
            print(f"[DeviceIntelligenceService] Device registration failed: {exc}", file=sys.stderr)
            return {
                "device_id": None,
                "trust_level": "unknown",
                "is_new": False,
                "is_suspicious": False,
                "suspicious_flags": [],
            }

    @classmethod
    def _copy_known_attributes(cls, device, attributes):
        if attributes.get("device_type"):
            device.device_type = attributes.get("device_type")
        if attributes.get("os_family"):
            device.os_family = attributes.get("os_family")
        if attributes.get("browser_family"):
            device.browser_family = attributes.get("browser_family")
        if attributes.get("device_name"):
            device.device_name = attributes.get("device_name")
        device.is_rooted = bool(attributes.get("is_rooted", device.is_rooted))
        device.is_emulator = bool(attributes.get("is_emulator", device.is_emulator))

    @classmethod
    def _check_suspicious_indicators(cls, attributes_dict):
        """Return suspicious device environment flags."""
        flags = []
        try:
            attributes = attributes_dict or {}
            combined = " ".join(
                str(attributes.get(key) or "").lower()
                for key in ("os_family", "browser_family", "user_agent")
            )
            user_agent = str(attributes.get("user_agent") or "").lower()

            if any(item in combined for item in cls.EMULATOR_STRINGS):
                flags.append("emulator_detected")
            if any(item in user_agent for item in cls.ROOT_INDICATORS):
                flags.append("root_detected")
            if attributes.get("is_rooted") is True:
                flags.append("rooted_device")
            if attributes.get("is_emulator") is True:
                flags.append("emulator_flag")

            hardware = attributes.get("hardware_concurrency")
            if hardware is not None:
                try:
                    hardware = int(hardware)
                    if hardware == 0 or hardware > 128:
                        flags.append("impossible_hardware")
                except (TypeError, ValueError):
                    flags.append("impossible_hardware")

            resolution = str(attributes.get("screen_resolution") or "").lower().strip()
            if resolution:
                if resolution == "0x0":
                    flags.append("invalid_screen_resolution")
                elif "x" in resolution:
                    try:
                        width, height = [int(part.strip()) for part in resolution.split("x", 1)]
                        if width <= 0 or height <= 0 or width > 16000 or height > 16000:
                            flags.append("invalid_screen_resolution")
                    except (TypeError, ValueError):
                        flags.append("invalid_screen_resolution")
            return list(dict.fromkeys(flags))
        except Exception as exc:
            print(f"[DeviceIntelligenceService] Suspicious indicator check failed: {exc}", file=sys.stderr)
            return flags

    @classmethod
    def assess_device_for_user(cls, user_id, fingerprint_hash):
        """Return a trust assessment for a user's device fingerprint."""
        try:
            from app.models import Device

            device = Device.query.filter_by(
                user_id=user_id,
                device_fingerprint_hash=fingerprint_hash,
                is_removed=False,
            ).first()
            if not device:
                return {
                    "trust_score": 65,
                    "trust_level": "new",
                    "device_found": False,
                    "suspicious_flags": [],
                }
            flags = []
            if device.is_rooted:
                flags.append("rooted_device")
            if device.is_emulator:
                flags.append("emulator_flag")
            return {
                "trust_score": int(device.get_trust_score()),
                "trust_level": device.trust_level,
                "device_found": True,
                "suspicious_flags": flags,
            }
        except Exception as exc:
            print(f"[DeviceIntelligenceService] Device assessment failed: {exc}", file=sys.stderr)
            return {
                "trust_score": 40,
                "trust_level": "unknown",
                "device_found": False,
                "suspicious_flags": [],
            }

    @classmethod
    def get_user_devices_summary(cls, user_id):
        """Return visible devices for a user."""
        try:
            from app.models import Device

            devices = (
                Device.query.filter_by(user_id=user_id, is_removed=False)
                .order_by(Device.last_seen_at.desc())
                .all()
            )
            return [
                {
                    "device_id": device.id,
                    "device_name": device.device_name,
                    "trust_level": device.trust_level,
                    "device_type": device.device_type,
                    "last_seen": device.last_seen_at.isoformat() if device.last_seen_at else None,
                    "is_current": False,
                }
                for device in devices
            ]
        except Exception as exc:
            print(f"[DeviceIntelligenceService] Device summary failed: {exc}", file=sys.stderr)
            return []

    @classmethod
    def mark_device_removed(cls, device_id, user_id):
        """Soft delete a user's device."""
        try:
            from app.models import Device

            device = Device.query.filter_by(id=device_id, user_id=user_id, is_removed=False).first()
            if not device:
                return False, "Device not found or permission denied"
            device.is_removed = True
            db.session.add(device)
            AuditLogger.log(
                actor_type="system",
                actor_id=user_id,
                action="device.remove",
                institution_id=device.institution_id,
                target_type="device",
                target_id=device.id,
                details={"user_id": user_id},
                commit=False,
            )
            db.session.commit()
            return True, "Device removed"
        except Exception as exc:
            db.session.rollback()
            print(f"[DeviceIntelligenceService] Device removal failed: {exc}", file=sys.stderr)
            return False, "Device could not be removed"

    @classmethod
    def rename_device(cls, device_id, user_id, new_name):
        """Rename a user's device."""
        try:
            clean_name = str(new_name or "").strip()
            if len(clean_name) < 2 or len(clean_name) > 100:
                return False, "Device name must be between 2 and 100 characters"

            from app.models import Device

            device = Device.query.filter_by(id=device_id, user_id=user_id, is_removed=False).first()
            if not device:
                return False, "Device not found or permission denied"
            device.device_name = clean_name
            db.session.add(device)
            AuditLogger.log(
                actor_type="system",
                actor_id=user_id,
                action="device.rename",
                institution_id=device.institution_id,
                target_type="device",
                target_id=device.id,
                details={"new_name": clean_name},
                commit=False,
            )
            db.session.commit()
            return True, "Device renamed"
        except Exception as exc:
            db.session.rollback()
            print(f"[DeviceIntelligenceService] Device rename failed: {exc}", file=sys.stderr)
            return False, "Device could not be renamed"

    @classmethod
    def extract_fingerprint_from_request(cls, request_obj):
        """Create a weak fallback fingerprint from request headers."""
        try:
            headers = request_obj.headers
            raw_value = "|".join(
                [
                    headers.get("User-Agent", ""),
                    headers.get("Accept-Language", ""),
                    headers.get("Accept-Encoding", ""),
                ]
            )
            return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        except Exception as exc:
            print(f"[DeviceIntelligenceService] Fingerprint extraction failed: {exc}", file=sys.stderr)
            return hashlib.sha256(b"unknown-device").hexdigest()
