from datetime import datetime, timezone

from app.firebase_config import initialize_firebase


def get_firestore():
    return initialize_firebase()


def create_user_profile(uid, name, email, is_admin=False):
    db = get_firestore()

    db.collection("users").document(uid).set({
        "name": name,
        "email": email,
        "is_admin": is_admin,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


def get_user_profile(uid):
    db = get_firestore()

    document = db.collection("users").document(uid).get()

    if not document.exists:
        return None

    profile = document.to_dict()
    profile["id"] = uid

    return profile


def save_scan(uid, result):
    db = get_firestore()

    db.collection("scans").add({
        "user_id": uid,
        "url": result["url"],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "risk_level": result["risk_level"],
        "reasons": result["reasons"],
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


def get_user_scans(uid, limit=100):
    db = get_firestore()

    documents = (
        db.collection("scans")
        .where("user_id", "==", uid)
        .stream()
    )

    scans = []

    for document in documents:
        scan = document.to_dict()
        scan["id"] = document.id
        scans.append(scan)

    scans.sort(
        key=lambda scan: scan.get("scanned_at", ""),
        reverse=True,
    )

    return scans[:limit]


def get_all_scans():
    db = get_firestore()

    documents = db.collection("scans").stream()

    scans = []

    for document in documents:
        scan = document.to_dict()
        scan["id"] = document.id
        scans.append(scan)

    scans.sort(
        key=lambda scan: scan.get("scanned_at", ""),
        reverse=True,
    )

    return scans


def delete_user_data(uid):
    db = get_firestore()

    scans = (
        db.collection("scans")
        .where("user_id", "==", uid)
        .stream()
    )

    for scan in scans:
        scan.reference.delete()

    db.collection("users").document(uid).delete()
def get_all_users():
    db = get_firestore()

    documents = db.collection("users").stream()

    users = []

    for document in documents:
        user = document.to_dict()
        user["id"] = document.id
        users.append(user)

    return users