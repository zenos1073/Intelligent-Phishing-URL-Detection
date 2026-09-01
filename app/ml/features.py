import ipaddress
import re
from urllib.parse import urlparse


FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


def normalise_url(value, max_length=2_048):
    """
    Validate the user's URL.

    The returned URL keeps the user's original trailing slash.
    Only a missing scheme is automatically given https://.
    """

    url = (value or "").strip()

    if not url:
        raise ValueError("Enter a URL to scan.")

    # Add HTTPS when the user does not provide a scheme.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(
            "Enter a complete HTTP or HTTPS URL."
        )

    if max_length is not None and len(url) > max_length:
        raise ValueError("The URL is too long to scan.")

    return url


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return 1
    except ValueError:
        return 0


def extract_url_features(value, max_length=2_048):
    """
    Extract URL-based features for the phishing detector.

    The URL returned by this function preserves the user's input.

    For machine-learning features, a trailing slash immediately after
    the domain is ignored so that:

        example.com
        example.com/

    produce the same feature values.

    No HTTP request is made.
    """

    # Keep the original/normalised URL for display and storage.
    url = normalise_url(
        value,
        max_length=max_length,
    )

    # ---------------------------------------------------------
    # Feature URL
    # ---------------------------------------------------------
    #
    # Ignore ONLY the trailing slash at the end of a bare domain.
    #
    # example:
    #   https://amazon.com
    #   https://amazon.com/
    #
    # Both are treated the same by the ML model.
    #
    # But:
    #   https://amazon.com/login/
    #
    # remains unchanged because the slash is part of the path.
    # ---------------------------------------------------------

    feature_url = url

    parsed_original = urlparse(url)

    if (
        parsed_original.path == "/"
        and not parsed_original.params
        and not parsed_original.query
        and not parsed_original.fragment
    ):
        feature_url = url.rstrip("/")

    parsed = urlparse(feature_url)

    hostname = (parsed.hostname or "").lower()

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    tld = (
        hostname_parts[-1]
        if len(hostname_parts) > 1
        else ""
    )

    letters = sum(
        char.isalpha()
        for char in feature_url
    )

    digits = sum(
        char.isdigit()
        for char in feature_url
    )

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        feature_url,
    )

    other_specials = sum(
        not char.isalnum()
        and char not in ":/?&=#.%_-"
        for char in feature_url
    )

    total_length = max(
        len(feature_url),
        1,
    )

    features = {
        "URLLength": len(feature_url),

        "DomainLength": len(hostname),

        "IsDomainIP": _is_ip_address(hostname),

        "TLDLength": len(tld),

        "NoOfSubDomain": max(
            0,
            len(hostname_parts) - 2,
        ),

        "HasObfuscation": int(
            bool(encoded_matches)
        ),

        "NoOfObfuscatedChar": sum(
            len(match)
            for match in encoded_matches
        ),

        "NoOfLettersInURL": letters,

        "LetterRatioInURL": round(
            letters / total_length,
            6,
        ),

        "NoOfDegitsInURL": digits,

        "DegitRatioInURL": round(
            digits / total_length,
            6,
        ),

        "NoOfEqualsInURL": feature_url.count("="),

        "NoOfQMarkInURL": feature_url.count("?"),

        "NoOfAmpersandInURL": feature_url.count("&"),

        "NoOfOtherSpecialCharsInURL": other_specials,

        "SpacialCharRatioInURL": round(
            sum(
                not char.isalnum()
                for char in feature_url
            ) / total_length,
            6,
        ),

        "IsHTTPS": int(
            parsed.scheme == "https"
        ),
    }

    return url, {
        column: features[column]
        for column in FEATURE_COLUMNS
    }