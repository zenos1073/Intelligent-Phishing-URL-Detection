import os
from pathlib import Path

from flask import Flask

from app.auth import auth_bp
from app.database import close_db, init_app as init_database
from app.main import main_bp


def create_app(test_config=None):
    """Create and configure the phishing-detection web application."""
    project_root = Path(__file__).resolve().parent.parent
    instance_path = project_root / "instance"
    instance_path.mkdir(exist_ok=True)

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "development-only-change-me"),
        DATABASE=str(instance_path / "phishing_detection.db"),
        MODEL_PATH=str(project_root / "models" / "phishing_url_model.joblib"),
    )

    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.teardown_appcontext(close_db)
    init_database(app)

    return app
