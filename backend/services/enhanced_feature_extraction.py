"""
PhishGuard AI - Enhanced Feature Extraction
Extracts 30+ URL-based features for ML prediction with professional dataset support.

IMPORTANT: This module is used by BOTH train_model.py and predictor.py.
The feature list and order must remain identical in both contexts.
The system NEVER visits or fetches the submitted URL.

Enhanced to detect real-world phishing patterns from professional datasets:
- Advanced typosquatting detection
- Homograph attack detection  
- Misleading TLD patterns
- URL structure analysis
- Professional phishing indicators
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from config import SUSPICIOUS_KEYWORDS, URL_SHORTENER_DOMAINS, TYPOSQUATTING_PATTERNS, LEGITIMATE_DOMAINS

# Enhanced feature set for professional phishing detection
ENHANCED_FEATURE_NAMES = [
    # Original 20 features
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
    
    # New enhanced features for professional dataset patterns
    "has_homograph_chars",  # 20 1 if contains homograph/unicode attack chars
    "has_misleading_tld",   # 21 1 if TLD structure is misleading (e.g., paypal.com.phish.ru)
    "has_suspicious_tld",   # 22 1 if TLD is commonly used for phishing (.tk, .ml, etc.)
    "has_port_number",      # 23 1 if non-standard port specified
    "path_depth",          # 24 Number of path segments (depth)
    "has_suspicious_path",  # 25 1 if path contains banking/login/verify keywords
    "has_suspicious_params", # 26 1 if query params contain suspicious keywords
    "domain_entropy",       # 27 Entropy of domain name (randomness measure)
    "looks_like_legitimate", # 28 1 if domain resembles legitimate service
    "has_multiple_services", # 29 1 if URL mentions multiple services (e.g., paypal-amazon)
    "url_complexity_score", # 30 Overall complexity score (0-1)
]

# Regex patterns for enhanced detection
_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PORT_PATTERN = re.compile(r":(\d+)")
_HOMOGRAPH_PATTERN = re.compile(r'[^\x00-\x7F]')  # Non-ASCII characters

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn', '.cc', '.pw', '.biz',
    '.info', '.top', '.click', '.download', '.stream', '.science', '.party'
]

# Legitimate service patterns for comparison
LEGITIMATE_SERVICES = {
    'banking': ['chase', 'bankofamerica', 'wellsfargo', 'citibank', 'sbi', 'hdfc', 'icici'],
    'payments': ['paypal', 'visa', 'mastercard', 'amex', 'venmo', 'zelle'],
    'tech': ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter'],
    'ecommerce': ['amazon', 'ebay', 'walmart', 'target', 'shopify']
}


def extract_enhanced_features(url: str) -> dict:
    """
    Extract enhanced features from a URL string.

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

    # ── Original 20 features ──────────────────────────────────────────────

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

    num_special_chars = len(re.findall(r"[^a-zA-Z0-9.]", url))
    num_digits = len(re.findall(r"\d", url))

    has_at_symbol = 1 if "@" in url else 0
    has_ip_address = 1 if _IP_PATTERN.match(hostname) else 0
    has_https = 1 if scheme.lower() == "https" else 0

    hostname_parts = hostname.split(".")
    num_subdomains = max(0, len(hostname_parts) - 2) if len(hostname_parts) > 2 else 0

    try:
        query_params = parse_qs(query)
        num_query_params = len(query_params)
    except Exception:
        num_query_params = 0

    url_lower = url.lower()
    hostname_lower = hostname.lower()

    # Suspicious keyword detection (smart - considers legitimate domains)
    has_suspicious_keyword = int(_detect_suspicious_keywords_smart(url_lower, hostname_lower))

    is_url_shortener = int(
        any(sd in hostname.lower() for sd in URL_SHORTENER_DOMAINS)
    )

    has_typosquatting = int(
        any(pattern in hostname_lower for pattern in TYPOSQUATTING_PATTERNS)
    )

    # ── New Enhanced Features ─────────────────────────────────────────────

    # Homograph attack detection (non-ASCII characters)
    has_homograph_chars = int(bool(_HOMOGRAPH_PATTERN.search(url)))

    # Misleading TLD detection (e.g., paypal.com.phishing.ru)
    has_misleading_tld = int(_detect_misleading_tld(url, hostname))

    # Suspicious TLD detection
    has_suspicious_tld = int(any(hostname_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))

    # Non-standard port detection
    port_match = _PORT_PATTERN.search(netloc)
    has_port_number = 1 if port_match and port_match.group(1) not in ['80', '443'] else 0

    # Path analysis
    path_segments = [seg for seg in path.split('/') if seg]
    path_depth = len(path_segments)

    suspicious_path_keywords = [
        'login', 'signin', 'verify', 'update', 'confirm', 'secure', 'account',
        'banking', 'paypal', 'amazon', 'google', 'apple', 'microsoft', 'reset'
    ]
    has_suspicious_path = int(any(kw in path.lower() for kw in suspicious_path_keywords))

    # Query parameter analysis
    suspicious_param_keywords = [
        'redirect', 'next', 'return', 'user', 'email', 'password', 'token',
        'session', 'ssn', 'credit', 'cvv', 'auth', 'verify'
    ]
    has_suspicious_params = int(any(kw in query.lower() for kw in suspicious_param_keywords))

    # Domain entropy (randomness measure)
    domain_entropy = _calculate_entropy(hostname_lower.replace('.', ''))

    # Legitimate service lookalike detection
    looks_like_legitimate = int(_looks_like_legitimate_service(hostname_lower))

    # Multiple service mention detection (e.g., paypal-amazon-verify.com)
    has_multiple_services = int(_has_multiple_service_mentions(hostname_lower))

    # Overall URL complexity score
    url_complexity_score = _calculate_complexity_score(
        url_length, num_special_chars, num_subdomains, path_depth, num_query_params
    )

    features = {
        # Original features
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
        
        # Enhanced features
        "has_homograph_chars": has_homograph_chars,
        "has_misleading_tld": has_misleading_tld,
        "has_suspicious_tld": has_suspicious_tld,
        "has_port_number": has_port_number,
        "path_depth": path_depth,
        "has_suspicious_path": has_suspicious_path,
        "has_suspicious_params": has_suspicious_params,
        "domain_entropy": domain_entropy,
        "looks_like_legitimate": looks_like_legitimate,
        "has_multiple_services": has_multiple_services,
        "url_complexity_score": url_complexity_score,
    }

    return features


def _detect_misleading_tld(url, hostname):
    """Detect misleading TLD patterns like paypal.com.phishing.ru"""
    url_lower = url.lower()
    hostname_lower = hostname.lower()
    
    # Check if legitimate service names appear in URL but not as actual domain
    for service_category in LEGITIMATE_SERVICES.values():
        for service in service_category:
            service_domain = f"{service}.com"
            if service_domain in url_lower and not hostname_lower.endswith(service_domain):
                return True
    
    return False


def _detect_suspicious_keywords_smart(url, hostname):
    """Detect suspicious keywords without hardcoded domain whitelist."""
    # Only check for suspicious keywords - let the model learn domain legitimacy
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            return True
    return False


def _calculate_entropy(text):
    """Calculate Shannon entropy of text (measure of randomness)"""
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_len = len(text)
    for count in char_counts.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def _looks_like_legitimate_service(hostname):
    """Check if hostname looks like a legitimate service based on patterns, not hardcoded lists."""
    # Check for legitimate patterns without hardcoded domains
    legitimate_patterns = [
        r'\.edu$', r'\.gov$', r'\.org$',  # Educational/Government/Non-profit
        r'\.ac\.', r'\.edu\.', r'\.gov\.',  # Academic/Educational/Government subdomains
    ]
    
    return any(re.search(pattern, hostname) for pattern in legitimate_patterns)


def _has_multiple_service_mentions(hostname):
    """Check if hostname mentions multiple services (suspicious)"""
    services_mentioned = 0
    all_services = []
    for service_list in LEGITIMATE_SERVICES.values():
        all_services.extend(service_list)
    
    for service in all_services:
        if service in hostname:
            services_mentioned += 1
    
    return services_mentioned > 1


def _calculate_complexity_score(url_len, special_chars, subdomains, path_depth, query_params):
    """Calculate overall URL complexity score (0-1, higher = more complex/suspicious)"""
    # Normalize each component
    url_score = min(url_len / 200, 1.0)  # URLs over 200 chars get max score
    special_score = min(special_chars / 20, 1.0)  # Over 20 special chars = max
    subdomain_score = min(subdomains / 5, 1.0)  # Over 5 subdomains = max
    path_score = min(path_depth / 10, 1.0)  # Over 10 path segments = max
    param_score = min(query_params / 10, 1.0)  # Over 10 params = max
    
    # Weighted average
    weights = [0.25, 0.2, 0.2, 0.15, 0.2]  # Sum = 1.0
    scores = [url_score, special_score, subdomain_score, path_score, param_score]
    
    complexity = sum(w * s for w, s in zip(weights, scores))
    return round(complexity, 4)


def enhanced_features_to_list(feature_dict: dict) -> list:
    """
    Convert enhanced feature dict to ordered list matching ENHANCED_FEATURE_NAMES.
    Use this when feeding features to the trained sklearn model.
    """
    return [feature_dict[name] for name in ENHANCED_FEATURE_NAMES]


def get_enhanced_indicators(url: str, feature_dict: dict) -> tuple[list, list]:
    """
    Generate enhanced human-readable warning and positive signal indicators.

    Returns:
        (warnings: list[str], positives: list[str])
    """
    warnings = []
    positives = []

    # Original indicators
    if feature_dict["url_length"] > 75:
        warnings.append("Long URL detected (over 75 characters)")
    if feature_dict["has_at_symbol"]:
        warnings.append("@ symbol present in URL (common phishing trick)")
    if feature_dict["has_ip_address"]:
        warnings.append("IP address used as hostname instead of domain name")
    if feature_dict["num_subdomains"] > 2:
        warnings.append(f"Excessive subdomains detected ({feature_dict['num_subdomains']})")
    if feature_dict["has_typosquatting"]:
        warnings.append("Potential typosquatting detected (lookalike domain)")

    # Enhanced indicators
    if feature_dict["has_homograph_chars"]:
        warnings.append("Unicode/homograph attack characters detected")
    if feature_dict["has_misleading_tld"]:
        warnings.append("Misleading TLD structure detected (e.g., service.com.malicious.ru)")
    if feature_dict["has_suspicious_tld"]:
        warnings.append("Suspicious top-level domain (commonly used for phishing)")
    if feature_dict["has_port_number"]:
        warnings.append("Non-standard port number specified")
    if feature_dict["path_depth"] > 5:
        warnings.append(f"Deep path structure ({feature_dict['path_depth']} levels)")
    if feature_dict["has_suspicious_path"]:
        warnings.append("Suspicious path keywords detected (login, verify, secure, etc.)")
    if feature_dict["has_suspicious_params"]:
        warnings.append("Suspicious query parameters detected (redirect, user, password, etc.)")
    if feature_dict["domain_entropy"] > 4.0:
        warnings.append("High domain randomness (possible generated domain)")
    if feature_dict["has_multiple_services"]:
        warnings.append("Multiple service names in domain (e.g., paypal-amazon)")
    if feature_dict["url_complexity_score"] > 0.7:
        warnings.append("High URL complexity score (multiple suspicious indicators)")

    # Positive indicators
    if feature_dict["has_https"]:
        positives.append("HTTPS protocol detected")
    if feature_dict["looks_like_legitimate"]:
        positives.append("Domain resembles legitimate service")
    if not feature_dict["has_homograph_chars"]:
        positives.append("No unicode attack characters")
    if not feature_dict["has_misleading_tld"]:
        positives.append("Normal TLD structure")
    if feature_dict["url_complexity_score"] < 0.3:
        positives.append("Low URL complexity (appears normal)")
    if feature_dict["domain_entropy"] < 3.0:
        positives.append("Normal domain structure (not randomly generated)")

    return warnings, positives


# Backward compatibility functions
def extract_features(url: str) -> dict:
    """Backward compatibility wrapper - returns original 20 features"""
    enhanced = extract_enhanced_features(url)
    
    # Return only the original 20 features for compatibility
    from .feature_extraction import FEATURE_NAMES
    return {name: enhanced[name] for name in FEATURE_NAMES}


def features_to_list(feature_dict: dict) -> list:
    """Backward compatibility wrapper"""
    from .feature_extraction import FEATURE_NAMES
    return [feature_dict[name] for name in FEATURE_NAMES]


def get_indicators(url: str, feature_dict: dict) -> tuple[list, list]:
    """Backward compatibility wrapper"""
    return get_enhanced_indicators(url, feature_dict)