import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

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


# Known brands and their official domains.
# These are used only as an additional security rule.
KNOWN_BRANDS = {
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "whatsapp": ["whatsapp.com"],
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


def _get_domain(url):
    """Return the hostname from a URL."""

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if "@" in domain:
        domain = domain.split("@")[-1]

    if ":" in domain:
        domain = domain.split(":")[0]

    return domain


def _brand_impersonation(url):
    """
    Check whether a domain appears to imitate a known brand
    without using the brand's official domain.
    """

    domain = _get_domain(url)

    if not domain:
        return None

    for brand, official_domains in KNOWN_BRANDS.items():

        # Allow the official domain and its subdomains.
        for official_domain in official_domains:
            if domain == official_domain or domain.endswith("." + official_domain):
                return None

        # Remove common separators for lookalike detection.
        cleaned_domain = domain.replace("-", "").replace("_", "")

        # Only flag domains where the brand is part of the domain name
        # but the domain is not the official domain.
        if brand in cleaned_domain:
            return (
                f"Possible {brand.title()} brand impersonation: "
                f"the domain resembles {brand.title()} but is not "
                f"the official domain."
            )

    return None


def _reasons(features, url):
    rules = [
        (
            features["IsDomainIP"],
            "The address uses an IP number instead of a named domain.",
        ),
        (
            features["HasObfuscation"],
            "The URL contains encoded characters often used to hide its destination.",
        ),
        (
            features["URLLength"] > 100,
            "The URL is unusually long.",
        ),
        (
            features["NoOfSubDomain"] >= 3,
            "The domain contains several nested subdomains.",
        ),
        (
            features["NoOfDegitsInURL"] >= 7,
            "The URL contains an unusually high number of digits.",
        ),
        (
            features["NoOfEqualsInURL"] >= 3,
            "The URL has multiple parameter assignments.",
        ),
        (
            not features["IsHTTPS"],
            "The URL does not use HTTPS encryption.",
        ),
    ]

    reasons = [
        message
        for condition, message in rules
        if condition
    ]

    brand_warning = _brand_impersonation(url)

    if brand_warning:
        reasons.append(brand_warning)

    return reasons


def score_url(value):
    url, features = extract_url_features(value)

    frame = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    model = _load_model(
        current_app.config["MODEL_PATH"]
    )

    if model is None:

        probability = _heuristic_probability(features)

        source = (
            "Safety heuristic "
            "(train the model to enable ML predictions)"
        )

    else:

        probability = float(
            model.predict_proba(frame)[0][1]
        )

        source = "Trained machine-learning model"

    reasons = _reasons(features, url)

    # Brand impersonation is an additional security signal.
    brand_warning = _brand_impersonation(url)

    if brand_warning:

        # Increase the risk score when a known brand
        # appears to be impersonated.
        probability = max(probability, 0.80)

    probability = min(probability, 0.95)

    verdict = (
        "phishing"
        if probability >= 0.50
        else "legitimate"
    )

    risk_level = (
        "high"
        if probability >= 0.75
        else "medium"
        if probability >= 0.50
        else "low"
    )

    if not reasons:
        reasons = [
            "No prominent URL-structure warning signs were found."
        ]

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