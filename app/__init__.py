import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

from app.auth import auth_bp
from app.main import main_bp

load_dotenv()


def create_app(test_config=None):
    """Create and configure the phishing-detection web application."""

    project_root = Path(__file__).resolve().parent.parent

    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get(
            "FLASK_SECRET_KEY",
            "development-only-change-me",
        ),
        MODEL_PATH=str(
            project_root / "models" / "phishing_url_model.joblib"
        ),
    )

    if test_config:
        app.config.update(test_config)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    return app