"""Application configuration for TrustSphere."""

from datetime import timedelta
import os

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()


def env_value(name, default=None):
    """Return an environment variable with a safe fallback."""
    return os.getenv(name, default)


def env_bool(name, default=False):
    """Parse common boolean environment values."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default=0):
    """Parse integer environment values."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class BaseConfig:
    """Shared configuration for all environments."""

    SECRET_KEY = env_value("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = env_value("DATABASE_URL", "sqlite:///trustsphere.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 300}

    REDIS_URL = env_value("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL = env_value("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND = env_value("CELERY_RESULT_BACKEND", REDIS_URL)
    CELERY_TASK_ALWAYS_EAGER = False

    MAIL_SERVER = env_value("MAIL_SERVER", "localhost")
    MAIL_PORT = env_int("MAIL_PORT", 587)
    MAIL_USE_TLS = env_bool("MAIL_USE_TLS", True)
    MAIL_USERNAME = env_value("MAIL_USERNAME", "security@trustsphere.local")
    MAIL_PASSWORD = env_value("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = ("TrustSphere Security", MAIL_USERNAME)

    JWT_SECRET_KEY = env_value("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    ENCRYPTION_MASTER_KEY = env_value(
        "ENCRYPTION_MASTER_KEY",
        "development-only-master-key-change-before-production",
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    WTF_CSRF_ENABLED = True

    RATELIMIT_STORAGE_URI = REDIS_URL
    RATELIMIT_DEFAULT = "200 per day;50 per hour"

    DEFAULT_INSTITUTION_NAME = env_value(
        "DEFAULT_INSTITUTION_NAME",
        "TrustSphere Demo Bank",
    )
    DEFAULT_ADMIN_EMAIL = env_value("DEFAULT_ADMIN_EMAIL", "admin@trustsphere.com")
    DEFAULT_ADMIN_PASSWORD = env_value(
        "DEFAULT_ADMIN_PASSWORD",
        "Admin@TrustSphere2026",
    )

    PLATFORM_VERSION = "1.0.0"
    PLATFORM_NAME = "TrustSphere"


class DevelopmentConfig(BaseConfig):
    """Local development configuration."""

    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = False
    # Allow building external URLs when running background workers
    SERVER_NAME = env_value("SERVER_NAME", "localhost:5000")
    PREFERRED_URL_SCHEME = env_value("PREFERRED_URL_SCHEME", "http")
    APPLICATION_ROOT = env_value("APPLICATION_ROOT", "/")


class ProductionConfig(BaseConfig):
    """Production configuration."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"


class TestingConfig(BaseConfig):
    """Automated testing configuration."""

    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    CELERY_TASK_ALWAYS_EAGER = True
    RATELIMIT_STORAGE_URI = "memory://"


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
