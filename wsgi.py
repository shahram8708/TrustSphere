"""Production WSGI entry point for TrustSphere."""

from app import create_app


app = create_app("production")


if __name__ == "__main__":
    app.run(use_reloader=False)
