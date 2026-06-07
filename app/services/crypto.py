"""Field encryption and hashing service."""

from __future__ import annotations

import base64
import hashlib
import secrets
import sys

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class EncryptionService:
    """Fernet based encryption helpers for sensitive fields."""

    @classmethod
    def _get_key(cls):
        raw_value = current_app.config.get("ENCRYPTION_MASTER_KEY", "")
        if isinstance(raw_value, str):
            key_bytes = raw_value.encode("utf-8")
        else:
            key_bytes = raw_value

        try:
            return Fernet(key_bytes)
        except Exception:
            derived = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
            return Fernet(derived)

    @classmethod
    def encrypt(cls, plaintext):
        if plaintext is None or plaintext == "":
            return None
        try:
            token = cls._get_key().encrypt(str(plaintext).encode("utf-8"))
            return token.decode("utf-8")
        except Exception as exc:
            print(f"[EncryptionService] Encrypt failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def decrypt(cls, ciphertext):
        if ciphertext is None or ciphertext == "":
            return None
        try:
            value = cls._get_key().decrypt(str(ciphertext).encode("utf-8"))
            return value.decode("utf-8")
        except InvalidToken as exc:
            print(f"[EncryptionService] Invalid encrypted token: {exc}", file=sys.stderr)
            return None
        except Exception as exc:
            print(f"[EncryptionService] Decrypt failed: {exc}", file=sys.stderr)
            return None

    @classmethod
    def hash_field(cls, value):
        if value is None:
            return None
        return hashlib.sha256(str(value).lower().strip().encode("utf-8")).hexdigest()

    @classmethod
    def generate_token(cls, length=32):
        return secrets.token_urlsafe(length)

    @classmethod
    def hash_api_key(cls, api_key):
        return hashlib.sha256(str(api_key or "").encode("utf-8")).hexdigest()

    @classmethod
    def verify_api_key(cls, raw_key, stored_hash):
        return secrets.compare_digest(cls.hash_api_key(raw_key), stored_hash or "")

    @classmethod
    def generate_api_key(cls):
        raw_key = secrets.token_urlsafe(48)
        return raw_key, cls.hash_api_key(raw_key)
