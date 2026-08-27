import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
from flask import current_app

from app.ml.features import FEATURE_COLUMNS, extract_url_features


DISPLAY_NAMES = {
    "URLLength": "Unusually long URL",
    "DomainLength": "Long domain name",
    "IsDomainIP": "IP address used instead of a domain",
    "NoOfSubDomain": "Multiple subdomains",
    "HasObfuscation": "Encoded or obfuscated characters",
    "NoOfDegitsInURL": "Many digits in the URL",
    "NoOfEqualsInURL": "Multiple URL parameters",
    "NoOfQMarkInURL": "Query string present",
    "NoOfAmpersandInURL": "Several query parameters",
    "IsHTTPS": "No HTTPS encryption",
}


@lru_cache(maxsize=2)
def _load_model(model_path):
    path = Path(model_path)
    if not path.exists():
        return None
    return joblib.load(path)


def _heuristic_probability(features):
    """Safe temporary scoring for a new checkout before model training."""
    risk = 0.08
    risk += min(features["URLLength"] / 400, 0.18)
    risk += 0.30 if features["IsDomainIP"] else 0
    risk += min(features["NoOfSubDomain"] * 0.07, 0.21)
    risk += 0.20 if features["HasObfuscation"] else 0
    risk += min(features["NoOfDegitsInURL"] * 0.012, 0.12)
    risk += min(features["NoOfEqualsInURL"] * 0.04, 0.12)
    risk += 0.10 if not features["IsHTTPS"] else 0
    return min(risk, 0.95)


def _reasons(features):
    rules = [
        (features["IsDomainIP"], "The address uses an IP number instead of a named domain."),
        (features["HasObfuscation"], "The URL contains encoded characters often used to hide its destination."),
        (features["URLLength"] > 100, "The URL is unusually long."),
        (features["NoOfSubDomain"] >= 3, "The domain contains several nested subdomains."),
        (features["NoOfDegitsInURL"] >= 7, "The URL contains an unusually high number of digits."),
        (features["NoOfEqualsInURL"] >= 3, "The URL has multiple parameter assignments."),
        (not features["IsHTTPS"], "The URL does not use HTTPS encryption."),
    ]
    return [message for condition, message in rules if condition]


def score_url(value):
    url, features = extract_url_features(value)
    frame = pd.DataFrame([features], columns=FEATURE_COLUMNS)
    model = _load_model(current_app.config["MODEL_PATH"])

    if model is None:
        probability = _heuristic_probability(features)
        source = "Safety heuristic (train the model to enable ML predictions)"
    else:
        probability = float(model.predict_proba(frame)[0][1])
        source = "Trained machine-learning model"

    verdict = "phishing" if probability >= 0.50 else "legitimate"
    risk_level = "high" if probability >= 0.75 else "medium" if probability >= 0.50 else "low"
    reasons = _reasons(features)
    if not reasons:
        reasons = ["No prominent URL-structure warning signs were found."]

    return {
        "url": url,
        "features": features,
        "confidence": round(probability * 100, 1),
        "verdict": verdict,
        "risk_level": risk_level,
        "reasons": reasons,
        "source": source,
    }


def serialise_reasons(reasons):
    return json.dumps(reasons)


def deserialise_reasons(value):
    return json.loads(value)
