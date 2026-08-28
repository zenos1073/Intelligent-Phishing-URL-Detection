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
    """Validate and standardise a user URL without making a network request."""

    url = (value or "").strip()

    if not url:
        raise ValueError("Enter a URL to scan.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete HTTP or HTTPS URL.")

    if max_length is not None and len(url) > max_length:
        raise ValueError("The URL is too long to scan.")

    # Treat a domain with and without a trailing slash as the same URL.
    if not parsed.path:
        url = url + "/"

    return url

def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return 1
    except ValueError:
        return 0


def extract_url_features(value, max_length=2_048):
    """Return the URL-lexical features available at scan time.

    No HTTP request is made. This keeps the scanner safe from untrusted URLs and
    matches the URL-only information used by the training script.
    """
    url = normalise_url(value, max_length=max_length)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    hostname_parts = [part for part in hostname.split(".") if part]
    tld = hostname_parts[-1] if len(hostname_parts) > 1 else ""
    letters = sum(char.isalpha() for char in url)
    digits = sum(char.isdigit() for char in url)
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
    other_specials = sum(not char.isalnum() and char not in ":/?&=#.%_-" for char in url)
    total_length = max(len(url), 1)

    features = {
        "URLLength": len(url),
        "DomainLength": len(hostname),
        "IsDomainIP": _is_ip_address(hostname),
        "TLDLength": len(tld),
        "NoOfSubDomain": max(0, len(hostname_parts) - 2),
        "HasObfuscation": int(bool(encoded_matches)),
        "NoOfObfuscatedChar": sum(len(match) for match in encoded_matches),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letters / total_length, 6),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digits / total_length, 6),
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": other_specials,
        "SpacialCharRatioInURL": round(sum(not char.isalnum() for char in url) / total_length, 6),
        "IsHTTPS": int(parsed.scheme == "https"),
    }
    return url, {column: features[column] for column in FEATURE_COLUMNS}
