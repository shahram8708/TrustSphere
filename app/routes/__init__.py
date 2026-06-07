"""Blueprint package for public, authentication, portal, admin, and API routes."""

from app.routes.admin import admin_bp
from app.routes.api import api_bp
from app.routes.auth import auth_bp
from app.routes.portal import portal_bp
from app.routes.public import public_bp

__all__ = ["admin_bp", "api_bp", "auth_bp", "portal_bp", "public_bp"]
