"""
PhishGuard AI - URL Validators
Input validation utilities for submitted URLs.
"""

import re
from urllib.parse import urlparse


def is_valid_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL string for format correctness.

    Returns:
        (is_valid: bool, error_message: str)
        error_message is empty string if valid.
    """
    if not url or not url.strip():
        return False, "URL cannot be empty."

    url = url.strip()

    if len(url) > 2048:
        return False, "URL exceeds maximum allowed length (2048 characters)."

    # Must have a scheme
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return False, "URL must begin with http:// or https://"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL could not be parsed. Please check the format."

    if not parsed.netloc:
        return False, "URL must contain a valid domain or hostname."

    # Reject clearly malformed netlocs
    hostname = parsed.hostname or ""
    if not hostname:
        return False, "Could not extract a valid hostname from the URL."

    return True, ""


def sanitize_url(url: str) -> str:
    """
    Strip leading/trailing whitespace from the URL.
    Does NOT follow or fetch the URL.
    """
    return url.strip()
