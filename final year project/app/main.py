from collections import Counter

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for

from app.database import get_db, utc_now
from app.ml.scoring import deserialise_reasons, score_url, serialise_reasons


main_bp = Blueprint("main", __name__)


@main_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None if user_id is None else get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/scan", methods=("POST",))
def scan():
    try:
        result = score_url(request.form.get("url"))
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("main.index"))

    if g.user:
        get_db().execute(
            "INSERT INTO scans (user_id, url, verdict, confidence, risk_level, reasons, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                g.user["id"], result["url"], result["verdict"], result["confidence"],
                result["risk_level"], serialise_reasons(result["reasons"]), utc_now(),
            ),
        )
        get_db().commit()

    return render_template("result.html", result=result)


@main_bp.route("/dashboard")
def dashboard():
    if not g.user:
        return redirect(url_for("auth.login"))
    scans = get_db().execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 100", (g.user["id"],)
    ).fetchall()
    scans = [
        {**dict(scan), "reasons_list": deserialise_reasons(scan["reasons"])}
        for scan in scans
    ]
    totals = Counter(scan["verdict"] for scan in scans)
    return render_template("dashboard.html", scans=scans, totals=totals)


@main_bp.route("/admin")
def admin():
    if not g.user or not g.user["is_admin"]:
        abort(403)

    db = get_db()
    totals = db.execute(
        "SELECT COUNT(*) AS total, SUM(verdict = 'phishing') AS phishing, SUM(verdict = 'legitimate') AS legitimate FROM scans"
    ).fetchone()
    daily = db.execute(
        "SELECT substr(scanned_at, 1, 10) AS day, COUNT(*) AS total, SUM(verdict = 'phishing') AS phishing "
        "FROM scans GROUP BY day ORDER BY day DESC LIMIT 14"
    ).fetchall()
    recent = db.execute(
        "SELECT scans.*, users.email FROM scans LEFT JOIN users ON users.id = scans.user_id "
        "ORDER BY scanned_at DESC LIMIT 50"
    ).fetchall()
    return render_template("admin.html", totals=totals, daily=daily, recent=recent)
