import firebase_admin
from firebase_admin import credentials, firestore
import os


def initialize_firebase():
    if firebase_admin._apps:
        return firestore.client()

    credentials_path = os.environ.get("FIREBASE_CREDENTIALS")

    if not credentials_path:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS environment variable is not set."
        )

    cred = credentials.Certificate(credentials_path)
    firebase_admin.initialize_app(cred)

    return firestore.client()