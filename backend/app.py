from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import re
import tldextract
import numpy as np
import math
from collections import Counter
from rapidfuzz import fuzz
import os

app = Flask(__name__)
CORS(app)

# ──────────────────────────────────────────────
# Load trained model (safe load with error handling)
# ──────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "phishing_model.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print(f"[INFO] Model loaded successfully from: {MODEL_PATH}")
except FileNotFoundError:
    model = None
    print(f"[WARNING] Model file not found at: {MODEL_PATH}. ML prediction will be skipped.")
except Exception as e:
    model = None
    print(f"[ERROR] Failed to load model: {e}. ML prediction will be skipped.")


# ──────────────────────────────────────────────
# Brand list: hardcoded fallback + optional data.txt merge
# ──────────────────────────────────────────────
_BUILTIN_BRANDS = [
    "paypal", "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "yahoo", "ebay", "wellsfargo", "chase", "bankofamerica", "citibank"
]

_data_txt_path = os.path.join(os.path.dirname(__file__), "dataset", "data.txt")
if os.path.exists(_data_txt_path):
    try:
        with open(_data_txt_path, "r", encoding="utf-8") as f:
            _file_brands = [line.strip().lower() for line in f if line.strip()]
        BRAND_LIST = list(set(_BUILTIN_BRANDS + _file_brands))
        print(f"[INFO] Loaded {len(_file_brands)} brands from data.txt")
    except Exception as e:
        print(f"[WARNING] Could not read data.txt: {e}. Using built-in brands only.")
        BRAND_LIST = _BUILTIN_BRANDS
else:
    BRAND_LIST = _BUILTIN_BRANDS

# Whitelist of known-good exact domains — these will NEVER be flagged as phishing
WHITELIST = {
    "google.com", "www.google.com",
    "facebook.com", "www.facebook.com",
    "amazon.com", "www.amazon.com",
    "apple.com", "www.apple.com",
    "microsoft.com", "www.microsoft.com",
    "netflix.com", "www.netflix.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com",
    "paypal.com", "www.paypal.com",
    "yahoo.com", "www.yahoo.com",
    "ebay.com", "www.ebay.com",
    "dropbox.com", "www.dropbox.com",
}


# ──────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────

def is_whitelisted(url: str, full_domain: str) -> bool:
    """
    Returns True if the URL's full domain exactly matches a known-safe domain.
    Strips protocol and path before checking.
    """
    # Normalize: strip protocol, path, query, fragment
    stripped = re.sub(r"^https?://", "", url.lower().strip())
    stripped = stripped.split("/")[0].split("?")[0].split("#")[0]
    return stripped in WHITELIST or full_domain.lower() in WHITELIST


def detect_typosquat_similarity(domain: str) -> list:
    """
    Levenshtein-based fuzzy matching using rapidfuzz.

    Uses TWO metrics and picks the best:
      - fuzz.ratio:         pure character-level edit distance (catches 'paypa1', 'gooogle')
      - fuzz.partial_ratio: best substring match (catches 'paypal-login', 'secure-google')

    Threshold: >= 80% similarity, excluding exact matches.
    Returns: sorted list of (brand, score) tuples, highest score first.
    """
    domain = domain.lower().strip()
    if not domain:
        return []

    matches = []

    for brand in BRAND_LIST:
        brand_lower = brand.lower().strip()

        if domain == brand_lower:
            continue  # exact match is NOT a typosquat

        ratio         = fuzz.ratio(domain, brand_lower)
        partial_ratio = fuzz.partial_ratio(domain, brand_lower)
        best_score    = max(ratio, partial_ratio)

        if best_score >= 80:
            matches.append((brand_lower, best_score))

    # Deduplicate and sort by score descending
    seen = set()
    unique_matches = []
    for brand, score in sorted(matches, key=lambda x: -x[1]):
        if brand not in seen:
            seen.add(brand)
            unique_matches.append((brand, score))

    return unique_matches


def check_typosquatting(domain: str) -> bool:
    """
    Substring check — catches 'paypal-secure.com' style domains.
    Only flags if the brand name appears as part of a LONGER string (not an exact match).
    """
    common_targets = ["paypal", "google", "facebook", "amazon", "apple"]
    domain = domain.lower().strip()
    for target in common_targets:
        # Must contain the brand AND not BE the brand exactly
        if target in domain and domain != target:
            return True
    return False


def check_homograph(domain: str) -> bool:
    """Detect Unicode homograph attacks (non-ASCII characters in domain)."""
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def count_subdomains(url: str) -> int:
    """Count the number of subdomains using tldextract."""
    try:
        extracted = tldextract.extract(url)
        if extracted.subdomain:
            return len(extracted.subdomain.split("."))
    except Exception:
        pass
    return 0


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    probabilities = [n_x / len(text) for _, n_x in Counter(text).items()]
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    return round(entropy, 4)


def check_keywords(url: str) -> bool:
    """
    Check for phishing-related keywords using whole-word regex matching.
    Avoids false positives like matching 'secure' inside 'https'.
    """
    keywords = ["login", "verify", "secure", "account", "update", "bank", "confirm"]
    # Extract path + query only (after the domain) to reduce false positives on protocol
    path_part = re.sub(r"^https?://[^/]+", "", url.lower())
    full_check = url.lower()

    for word in keywords:
        # Check in path with word boundary OR as standalone param
        if re.search(r'[\W_]' + re.escape(word) + r'[\W_]|[\W_]' + re.escape(word) + r'$|^' + re.escape(word) + r'[\W_]', path_part):
            return True
        # Also check full URL but only with word boundaries
        if re.search(r'\b' + re.escape(word) + r'\b', full_check):
            return True
    return False


def extract_features(url: str) -> list:
    """
    Extract numerical features from a URL for the ML model.
    Uses word-boundary-aware keyword matching to prevent false positives.
    Returns a list of exactly 31 features.
    """
    features = []

    # Feature 1: URL length
    features.append(len(url))

    # Feature 2: Has IP address
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    features.append(1 if re.search(ip_pattern, url) else 0)

    # Feature 3: Uses HTTPS
    features.append(1 if url.lower().startswith("https") else 0)

    # Feature 4: Dot count
    features.append(url.count("."))

    # Feature 5: Suspicious keywords — word-boundary safe
    suspicious = ["login", "verify", "secure", "account", "update", "bank"]
    has_suspicious = any(
        re.search(r'\b' + re.escape(word) + r'\b', url, re.IGNORECASE)
        for word in suspicious
    )
    features.append(1 if has_suspicious else 0)

    # Pad remaining features to reach exactly 31
    while len(features) < 31:
        features.append(0)

    return features


def get_ml_prediction(url: str) -> tuple:
    """
    Run ML model prediction safely.
    Returns (result_label, raw_value) or ("Unknown", None) if model unavailable.
    """
    if model is None:
        return "Unknown", None

    try:
        features       = extract_features(url)
        features_array = np.array(features, dtype=float).reshape(1, -1)
        prediction_raw = model.predict(features_array)[0]
        result         = "Phishing" if int(prediction_raw) == -1 else "Legitimate"
        return result, int(prediction_raw)
    except Exception as e:
        print(f"[ERROR] ML prediction failed: {e}")
        return "Unknown", None


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def home():
    return "Phishing Detection API is running!"


@app.route("/predict", methods=["POST"])
def predict():
    data = request.json

    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field in request body"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Basic URL format sanity check
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    # Extract domain parts safely
    try:
        extracted   = tldextract.extract(url)
        domain      = extracted.domain
        suffix      = extracted.suffix
        subdomain   = extracted.subdomain
        full_domain = ".".join(filter(None, [subdomain, domain, suffix]))
    except Exception as e:
        return jsonify({"error": f"Failed to parse URL: {str(e)}"}), 400

    if not domain:
        return jsonify({"error": "Could not extract a valid domain from the URL"}), 400

    # ── Whitelist check — skip all analysis for known-safe domains ──
    if is_whitelisted(url, full_domain):
        return jsonify({
            "url":         url,
            "prediction":  "Legitimate",
            "risk_score":  0,
            "alerts":      [],
            "alert_count": 0,
            "whitelisted": True,
            "details": {
                "uses_https":              url.lower().startswith("https"),
                "has_ip_address":          False,
                "subdomain_count":         count_subdomains(url),
                "domain_entropy":          calculate_entropy(domain),
                "domain":                  domain,
                "full_domain":             full_domain,
                "url_length":              len(url),
                "has_suspicious_keywords": False,
                "is_typosquat":            False,
                "is_homograph":            False,
                "similar_brands":          [],
            }
        })

    alerts = []

    # 1. Substring typosquat check
    if check_typosquatting(domain):
        alerts.append("Possible typosquatting attack detected")

    # 2. Homograph / Unicode attack check
    if check_homograph(full_domain):
        alerts.append("Unicode homograph attack detected")

    # 3. Levenshtein fuzzy brand similarity check
    similar_brands = detect_typosquat_similarity(domain)
    for brand, score in similar_brands:
        alerts.append(f"Possible typosquatting of '{brand}' (similarity {score}%)")

    # 4. Too many subdomains
    subdomain_count = count_subdomains(url)
    if subdomain_count > 2:
        alerts.append(f"Too many subdomains ({subdomain_count} detected)")

    # 5. High entropy domain
    entropy = calculate_entropy(domain)
    if entropy > 3.5:
        alerts.append(f"High entropy domain detected (entropy: {entropy})")

    # 6. Phishing keywords in URL
    has_keywords = check_keywords(url)
    if has_keywords:
        alerts.append("Suspicious phishing keywords found in URL")

    # 7. IP address used instead of domain
    has_ip = bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url))
    if has_ip:
        alerts.append("URL contains an IP address instead of a domain name")

    # 8. No HTTPS
    uses_https = url.lower().startswith("https")
    if not uses_https:
        alerts.append("URL does not use HTTPS")

    # ── ML prediction ──
    ml_result, prediction_raw = get_ml_prediction(url)

    # ── Smart final verdict ──
    # If alerts are zero, never mark as Phishing regardless of model output.
    # This prevents a badly-calibrated model from overriding clean heuristics.
    if len(alerts) == 0:
        final_result = "Legitimate"
    elif ml_result == "Unknown":
        # No model available — use heuristic-only verdict
        final_result = "Phishing" if len(alerts) >= 2 else "Suspicious"
    else:
        # Both signals available — agree on Phishing only when both agree
        heuristic_bad = len(alerts) >= 2
        if ml_result == "Phishing" and heuristic_bad:
            final_result = "Phishing"
        elif ml_result == "Phishing" and not heuristic_bad:
            # Model says Phishing but heuristics disagree — be cautious, not definitive
            final_result = "Suspicious"
        else:
            final_result = ml_result  # "Legitimate"

    # ── Risk score ──
    effective_max = max(8, 8 + len(similar_brands))
    risk_score    = min(100, round((len(alerts) / effective_max) * 100))

    return jsonify({
        "url":         url,
        "prediction":  final_result,
        "risk_score":  risk_score,
        "alerts":      alerts,
        "alert_count": len(alerts),
        "whitelisted": False,
        "details": {
            "uses_https":              uses_https,
            "has_ip_address":          has_ip,
            "subdomain_count":         subdomain_count,
            "domain_entropy":          entropy,
            "domain":                  domain,
            "full_domain":             full_domain,
            "url_length":              len(url),
            "has_suspicious_keywords": has_keywords,
            "is_typosquat":            check_typosquatting(domain),
            "is_homograph":            check_homograph(full_domain),
            "similar_brands": [
                {"brand": b, "similarity": s} for b, s in similar_brands
            ],
            "ml_raw_prediction": prediction_raw,
        }
    })


if __name__ == "__main__":
    app.run(debug=True)