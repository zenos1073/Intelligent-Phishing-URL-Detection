import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.database import get_db, utc_now


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(name) < 2:
            flash("Please enter your name.", "error")
        elif "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
        else:
            db = get_db()
            try:
                cursor = db.execute(
                    "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (name, email, generate_password_hash(password), utc_now()),
                )
                db.commit()
            except sqlite3.IntegrityError:
                flash("An account already exists for that email address.", "error")
            else:
                session.clear()
                session["user_id"] = cursor.lastrowid
                flash("Your account is ready. Scans will now be saved to your history.", "success")
                return redirect(url_for("main.index"))

    return render_template("register.html")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect email address or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['name']}.", "success")
            return redirect(url_for("main.index"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))


@auth_bp.route("/delete-account", methods=("POST",))
def delete_account():
    """Permanently remove the signed-in account and its scan history."""
    user_id = session.get("user_id")
    if user_id is None:
        flash("Please sign in before deleting an account.", "error")
        return redirect(url_for("auth.login"))

    db = get_db()
    db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    session.clear()
    flash("Your account and saved scan history have been deleted.", "success")
    return redirect(url_for("main.index"))
