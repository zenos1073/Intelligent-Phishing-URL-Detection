from collections import Counter

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.firebase_service import (
    get_user_profile,
    get_user_scans,
    save_scan,
    get_all_users,
)
from app.ml.scoring import score_url


main_bp = Blueprint("main", __name__)


@main_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = get_user_profile(user_id)


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
        save_scan(g.user["id"], result)

    return render_template("result.html", result=result)


@main_bp.route("/dashboard")
def dashboard():
    if not g.user:
        return redirect(url_for("auth.login"))

    scans = get_user_scans(g.user["id"])

    for scan in scans:
        reasons = scan.get("reasons", [])

        if isinstance(reasons, list):
            scan["reasons_list"] = reasons
        else:
            scan["reasons_list"] = []

    totals = Counter(scan["verdict"] for scan in scans)

    return render_template(
        "dashboard.html",
        scans=scans,
        totals=totals,
    )


@main_bp.route("/admin")
def admin():
    if not g.user or not g.user.get("is_admin"):
        abort(403)

    from app.firebase_service import get_all_scans

    all_scans = get_all_scans()
    all_users = get_all_users()

    phishing_count = sum(
        1 for scan in all_scans
        if scan.get("verdict") == "phishing"
    )

    legitimate_count = sum(
        1 for scan in all_scans
        if scan.get("verdict") == "legitimate"
    )

    totals = {
        "total": len(all_scans),
        "phishing": phishing_count,
        "legitimate": legitimate_count,
    }

    daily_data = {}

    for scan in all_scans:
        scanned_at = scan.get("scanned_at", "")
        day = scanned_at[:10]

        if day not in daily_data:
            daily_data[day] = {
                "day": day,
                "total": 0,
                "phishing": 0,
            }

        daily_data[day]["total"] += 1

        if scan.get("verdict") == "phishing":
            daily_data[day]["phishing"] += 1

    daily = sorted(
        daily_data.values(),
        key=lambda item: item["day"],
        reverse=True,
    )[:14]

    recent = all_scans[:50]
    user_lookup = {
    user["id"]: user
    for user in all_users
}

    for scan in recent:
        user_id = scan.get("user_id")
        user = user_lookup.get(user_id)

        if user:
            scan["user_name"] = user.get("name", "Unknown")
            scan["user_email"] = user.get("email", "")
        else:
            scan["user_name"] = "Unknown"
            scan["user_email"] = ""

    return render_template(
    "admin.html",
    totals=totals,
    daily=daily,
    recent=recent,
    users=all_users,
)
