"""
PhishGuard AI - Configuration
Application-wide settings and constants.
"""

import os

# ── Server ──────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 8000
RELOAD = True

# ── CORS ────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174", 
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://localhost:3000",
]

# ── Paths ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "model")

DATASET_PATH = os.path.join(DATA_DIR, "phishing_dataset.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")

# ── ML Settings ──────────────────────────────────────────
RANDOM_STATE = 42
TEST_SIZE = 0.2

# ── Risk Score Thresholds ────────────────────────────────
RISK_LOW_MAX = 30
RISK_MEDIUM_MAX = 60
# > 60 is HIGH

# ── Suspicious Keywords ───────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "account", "secure", "security",
    "update", "verify", "verification", "banking", "netbanking",
    "paypal", "ebay", "amazon", "microsoft", "apple", "google",
    "facebook", "instagram", "support", "helpdesk", "password",
    "credential", "confirm", "wallet", "crypto", "token", "alert",
    "suspended", "unusual", "activity", "click", "free", "prize",
    "winner", "urgent", "limited", "offer", "expire", "expiry",
    # Indian Banking Keywords
    "sbi", "hdfc", "icici", "kotak", "axis", "pnb", "upi", "paytm",
    "phonepe", "bharatpe", "googlepay", "mobikwik", "freecharge",
    # Typosquatting Indicators
    "bank", "banking", "online", "net", "secure", "verification"
]

# ── Typosquatting Detection ────────────────────────────────────
LEGITIMATE_DOMAINS = {
    # Indian Banks
    "onlinesbi.sbi.co.in", "netbanking.hdfcbank.com", "icicibank.com",
    "netbanking.kotak.com", "axisbank.com", "pnbindia.in",
    "netbanking.bankofindia.co.in", "unionbankofindia.co.in",
    
    # Global Banks  
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "hsbc.com", "jpmorgan.com",
    
    # Payment Services
    "paypal.com", "pay.google.com", "paytm.com", "phonepe.com",
    
    # Major Tech
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com"
}

TYPOSQUATTING_PATTERNS = [
    # SBI Variations
    "onlinessbi", "sbibank", "sbionline", "sbi-bank", "sbi.bank",
    
    # HDFC Variations  
    "hdfcbank", "hdfc-bank", "hdfcbanking", "hdfcsecure",
    
    # ICICI Variations
    "icicbank", "icici-bank", "icicisecure", "icicibanking",
    
    # PayPal Variations
    "paypa1", "paypaI", "paypal1", "paipal", "payp4l",
    
    # Amazon Variations
    "arnazon", "amazon1", "amazom", "amaz0n",
    
    # Google Variations
    "googIe", "goog1e", "gogle", "googel",
    
    # Microsoft Variations  
    "microsft", "microsofy", "micr0soft", "microseft"
]

# ── URL Shortener Domains ─────────────────────────────────
URL_SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "short.link", "rb.gy",
    "cutt.ly", "is.gd", "v.gd", "tiny.cc",
]
