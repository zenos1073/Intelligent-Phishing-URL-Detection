import json
import os
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, firestore


def initialize_firebase():
    if firebase_admin._apps:
        return firestore.client()

    credentials_value = os.environ.get("FIREBASE_CREDENTIALS")

    if not credentials_value:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS environment variable is not set."
        )

    # First, try the value as a file path.
    credentials_path = Path(credentials_value)

    if credentials_path.is_file():
        cred = credentials.Certificate(str(credentials_path))
    else:
        # Otherwise, treat it as JSON (useful for Render/cloud deployment).
        try:
            credentials_data = json.loads(credentials_value)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "FIREBASE_CREDENTIALS must be either a valid JSON "
                "credential or a path to the Firebase credential file."
            ) from error

        cred = credentials.Certificate(credentials_data)

    firebase_admin.initialize_app(cred)

    return firestore.client()