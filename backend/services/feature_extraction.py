"""
PhishGuard AI - Feature Extraction
Extracts 19 URL-based features for ML prediction.

IMPORTANT: This module is used by BOTH train_model.py and predictor.py.
The feature list and order must remain identical in both contexts.
The system NEVER visits or fetches the submitted URL.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from config import SUSPICIOUS_KEYWORDS, URL_SHORTENER_DOMAINS, TYPOSQUATTING_PATTERNS

# ── Canonical Feature Order ──────────────────────────────────────────────────
# This list defines the exact column order fed to the model.
# Do NOT change the order without retraining the model.
FEATURE_NAMES = [
    "url_length",           # 0  Total character count of the URL
    "domain_length",        # 1  Character count of the domain/netloc
    "path_length",          # 2  Character count of the URL path
    "num_dots",             # 3  Number of '.' characters in full URL
    "num_hyphens",          # 4  Number of '-' characters in full URL
    "num_underscores",      # 5  Number of '_' characters in full URL
    "num_slashes",          # 6  Number of '/' characters in full URL
    "num_question_marks",   # 7  Number of '?' characters
    "num_equals",           # 8  Number of '=' characters
    "num_ampersands",       # 9  Number of '&' characters
    "num_special_chars",    # 10 Count of special characters (non-alphanumeric, non '.')
    "num_digits",           # 11 Count of digit characters in full URL
    "has_at_symbol",        # 12 1 if '@' present in URL, else 0
    "has_ip_address",       # 13 1 if hostname appears to be an IP address
    "has_https",            # 14 1 if scheme is https, else 0
    "num_subdomains",       # 15 Number of subdomains (parts before TLD)
    "num_query_params",     # 16 Number of query string parameters
    "has_suspicious_keyword",  # 17 1 if any suspicious keyword found in URL
    "is_url_shortener",     # 18 1 if domain matches a known URL-shortener
    "has_typosquatting",    # 19 1 if potential typosquatting pattern detected
]

# Regex for IPv4 detection in hostname
_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def extract_features(url: str) -> dict:
    """
    Extract all features from a URL string.

    Args:
        url: The raw URL string (untrusted; never fetched).

    Returns:
        dict mapping feature name -> numeric value (int or float).
    """
    url = url.strip()

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("")

    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme or ""
    hostname = parsed.hostname or ""

    # ── Individual feature computations ──────────────────────────────────────

    url_length = len(url)
    domain_length = len(netloc)
    path_length = len(path)

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question_marks = url.count("?")
    num_equals = url.count("=")
    num_ampersands = url.count("&")

    # Special chars: anything that isn't alphanumeric or a dot
    num_special_chars = len(re.findall(r"[^a-zA-Z0-9.]", url))
    num_digits = len(re.findall(r"\d", url))

    has_at_symbol = 1 if "@" in url else 0
    has_ip_address = 1 if _IP_PATTERN.match(hostname) else 0
    has_https = 1 if scheme.lower() == "https" else 0

    # Subdomain count: parts of hostname minus the TLD and main domain
    hostname_parts = hostname.split(".")
    # e.g. sub.example.com -> ['sub','example','com'] -> subdomains = 1
    num_subdomains = max(0, len(hostname_parts) - 2) if len(hostname_parts) > 2 else 0

    # Query parameters
    try:
        query_params = parse_qs(query)
        num_query_params = len(query_params)
    except Exception:
        num_query_params = 0

    # Suspicious keyword detection (case-insensitive on the full URL)
    url_lower = url.lower()
    has_suspicious_keyword = int(
        any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)
    )

    # URL shortener detection (compare against known shortener domains)
    is_url_shortener = int(
        any(sd in hostname.lower() for sd in URL_SHORTENER_DOMAINS)
    )

    # Typosquatting detection (check for known phishing patterns)
    hostname_lower = hostname.lower()
    has_typosquatting = int(
        any(pattern in hostname_lower for pattern in TYPOSQUATTING_PATTERNS)
    )

    features = {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equals": num_equals,
        "num_ampersands": num_ampersands,
        "num_special_chars": num_special_chars,
        "num_digits": num_digits,
        "has_at_symbol": has_at_symbol,
        "has_ip_address": has_ip_address,
        "has_https": has_https,
        "num_subdomains": num_subdomains,
        "num_query_params": num_query_params,
        "has_suspicious_keyword": has_suspicious_keyword,
        "is_url_shortener": is_url_shortener,
        "has_typosquatting": has_typosquatting,
    }

    return features


def features_to_list(feature_dict: dict) -> list:
    """
    Convert feature dict to ordered list matching FEATURE_NAMES.
    Use this when feeding features to the trained sklearn model.
    """
    return [feature_dict[name] for name in FEATURE_NAMES]


def get_indicators(url: str, feature_dict: dict) -> tuple[list, list]:
    """
    Generate human-readable warning and positive signal indicators.

    Returns:
        (warnings: list[str], positives: list[str])
    """
    warnings = []
    positives = []

    if feature_dict["url_length"] > 75:
        warnings.append("Long URL detected (over 75 characters)")
    if feature_dict["has_at_symbol"]:
        warnings.append("@ symbol present in URL (common phishing trick)")
    if feature_dict["has_ip_address"]:
        warnings.append("IP address used as hostname instead of domain name")
    if feature_dict["num_subdomains"] > 2:
        warnings.append(f"Excessive subdomains detected ({feature_dict['num_subdomains']})")
    if feature_dict["num_hyphens"] > 3:
        warnings.append(f"High number of hyphens ({feature_dict['num_hyphens']})")
    if feature_dict["num_special_chars"] > 10:
        warnings.append("Excessive special characters in URL")
    if feature_dict["num_dots"] > 5:
        warnings.append(f"Unusual number of dots ({feature_dict['num_dots']})")
    if feature_dict["has_suspicious_keyword"]:
        warnings.append("Suspicious keyword detected (e.g. login, verify, secure, banking)")
    if feature_dict["is_url_shortener"]:
        warnings.append("URL shortener service detected — destination unknown")
    if feature_dict["has_typosquatting"]:
        warnings.append("Potential typosquatting detected (lookalike domain)")
    if feature_dict["num_digits"] > 8:
        warnings.append("High count of numeric characters in URL")
    if feature_dict["num_query_params"] > 5:
        warnings.append(f"Many query parameters ({feature_dict['num_query_params']})")

    if feature_dict["has_https"]:
        positives.append("HTTPS protocol detected")
    if feature_dict["num_subdomains"] <= 1:
        positives.append("Normal domain structure (few subdomains)")
    if not feature_dict["has_at_symbol"]:
        positives.append("No @ symbol in URL")
    if not feature_dict["has_ip_address"]:
        positives.append("Domain name used (not a raw IP address)")
    if feature_dict["url_length"] <= 75:
        positives.append("URL length is within normal range")

    return warnings, positives
