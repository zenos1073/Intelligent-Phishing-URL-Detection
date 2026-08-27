import sqlite3
from datetime import datetime, timezone

import click
from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('phishing', 'legitimate')),
    confidence REAL NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans (scanned_at);
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create the SQLite database tables."""
        init_db()
        click.echo("Database initialized.")

    @app.cli.command("create-admin")
    @click.option("--name", prompt=True)
    @click.option("--email", prompt=True)
    @click.password_option()
    def create_admin_command(name, email, password):
        """Create an administrator account."""
        from werkzeug.security import generate_password_hash

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash, is_admin, created_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (name.strip(), email.strip().lower(), generate_password_hash(password), utc_now()),
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise click.ClickException("That email address is already registered.") from error
        click.echo("Administrator created.")
