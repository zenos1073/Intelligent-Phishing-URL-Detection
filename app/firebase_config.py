import json
import os

import firebase_admin
from firebase_admin import credentials, firestore


def initialize_firebase():
    if firebase_admin._apps:
        return firestore.client()

    credentials_json = os.environ.get("FIREBASE_CREDENTIALS")

    if not credentials_json:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS environment variable is not set."
        )

    try:
        credentials_data = json.loads(credentials_json)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS does not contain valid JSON."
        ) from error

    cred = credentials.Certificate(credentials_data)
    firebase_admin.initialize_app(cred)

    return firestore.client()