"""Standalone local-only Flask entry point for Sofia Vocabulary."""

import importlib.util
import os
import secrets
import sys
from pathlib import Path

from flask import Flask, send_from_directory

from extensions import db, login_manager

BASE_DIR = Path(__file__).resolve().parent

# Load this repository as a package even if the checkout folder uses a hyphen.
if "vocab_pro" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "vocab_pro",
        BASE_DIR / "__init__.py",
        submodule_search_locations=[str(BASE_DIR)],
    )
    package = importlib.util.module_from_spec(spec)
    sys.modules["vocab_pro"] = package
    spec.loader.exec_module(package)


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{BASE_DIR / 'vocab.db'}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    db.init_app(app)
    login_manager.init_app(app)

    from vocab_pro.models import User
    from vocab_pro import vocab_bp

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    app.register_blueprint(vocab_bp, url_prefix="/vocab")

    @app.get("/custom-icon")
    def custom_icon():
        from flask import request

        icon = "s2.png" if request.args.get("icon") == "s2" else "favicon.ico"
        return send_from_directory(app.static_folder, icon)

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("VOCAB_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)