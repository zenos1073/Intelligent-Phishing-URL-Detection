import os
import requests


def firebase_signup(email, password):
    api_key = os.environ.get("FIREBASE_API_KEY")

    if not api_key:
        raise RuntimeError("FIREBASE_API_KEY is not set.")

    url = (
        "https://identitytoolkit.googleapis.com/v1/"
        "accounts:signUp"
        f"?key={api_key}"
    )

    response = requests.post(
        url,
        json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
        },
        timeout=10,
    )

    return response.json()


def firebase_login(email, password):
    api_key = os.environ.get("FIREBASE_API_KEY")

    if not api_key:
        raise RuntimeError("FIREBASE_API_KEY is not set.")

    url = (
        "https://identitytoolkit.googleapis.com/v1/"
        "accounts:signInWithPassword"
        f"?key={api_key}"
    )

    response = requests.post(
        url,
        json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
        },
        timeout=10,
    )

    return response.json()