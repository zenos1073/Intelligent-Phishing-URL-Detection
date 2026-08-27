from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from firebase_admin import auth as firebase_admin_auth

from app.firebase_auth import firebase_login, firebase_signup
from app.firebase_service import create_user_profile, delete_user_data


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
            result = firebase_signup(email, password)

            if "error" in result:
                message = result["error"].get("message", "")

                if message == "EMAIL_EXISTS":
                    flash(
                        "An account already exists for that email address.",
                        "error",
                    )
                else:
                    flash(
                        "Registration failed. Please try again.",
                        "error",
                    )
            else:
                uid = result["localId"]

                create_user_profile(
                    uid=uid,
                    name=name,
                    email=email,
                    is_admin=False,
                )

                session.clear()
                session["user_id"] = uid

                flash(
                    "Your account is ready. Scans will now be saved to your history.",
                    "success",
                )

                return redirect(url_for("main.index"))

    return render_template("register.html")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        result = firebase_login(email, password)

        if "error" in result:
            flash(
                "Incorrect email address or password.",
                "error",
            )
        else:
            uid = result["localId"]

            session.clear()
            session["user_id"] = uid

            flash("Welcome back.", "success")

            return redirect(url_for("main.index"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=("POST",))
def logout():
    session.clear()

    flash("You have been signed out.", "success")

    return redirect(url_for("main.index"))


@auth_bp.route("/delete-account", methods=("POST",))
def delete_account():
    """Permanently remove the signed-in Firebase account and its data."""

    user_id = session.get("user_id")

    if user_id is None:
        flash(
            "Please sign in before deleting an account.",
            "error",
        )
        return redirect(url_for("auth.login"))

    try:
        delete_user_data(user_id)
        firebase_admin_auth.delete_user(user_id)

    except Exception:
        flash(
            "Unable to delete the account. Please try again.",
            "error",
        )
        return redirect(url_for("main.index"))

    session.clear()

    flash(
        "Your account and saved scan history have been deleted.",
        "success",
    )

    return redirect(url_for("main.index"))