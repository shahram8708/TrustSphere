"""Development entry point for TrustSphere."""

import os

from app import create_app
from app.extensions import db
from seed import seed_database


app = create_app("development")

with app.app_context():
    db.create_all()
    seed_database()


def print_startup_banner():
    """Print the development server startup summary."""
    admin_email = app.config.get("DEFAULT_ADMIN_EMAIL", "admin@trustsphere.com")
    platform_name = app.config.get("PLATFORM_NAME", "TrustSphere")
    platform_version = app.config.get("PLATFORM_VERSION", "1.0.0")
    print("")
    print(f"{platform_name} {platform_version}")
    print("Admin URL: http://localhost:5000/auth/login")
    print(f"Admin Email: {admin_email}")
    print("Seed data checked.")
    print("")


def ensure_pwa_icons():
    """Generate PWA icons during development when they are missing."""
    icon_192 = os.path.join("app", "static", "img", "icon-192.png")
    icon_512 = os.path.join("app", "static", "img", "icon-512.png")
    if os.path.exists(icon_192) and os.path.exists(icon_512):
        return
    try:
        import generate_icons

        generate_icons.generate_trustsphere_icon()
    except Exception as exc:
        print(f"[TrustSphere] Icon generation skipped: {exc}")


if __name__ == "__main__":
    ensure_pwa_icons()
    print_startup_banner()
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
