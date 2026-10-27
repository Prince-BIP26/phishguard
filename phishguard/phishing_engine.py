"""
phishing_engine.py
Rule-based phishing detection engine — Python port of phishing-engine.ts
"""

import re
from datetime import datetime
from urllib.parse import urlparse

# ── Constants ────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "suspend", "urgent", "alert", "click",
    "free", "winner", "prize", "gift", "offer", "limited",
    "paypal", "signin", "security", "wallet", "crypto",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".buzz", ".cam",
]

DISPOSABLE_EMAIL_DOMAINS = [
    "tempmail.com", "guerrillamail.com", "throwaway.email", "mailinator.com",
    "yopmail.com", "sharklasers.com", "trashmail.com", "10minutemail.com",
    "fakeinbox.com", "dispostable.com", "getnada.com",
]

LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
    "twitter.com", "linkedin.com", "github.com", "netflix.com", "paypal.com",
    "youtube.com", "instagram.com", "whatsapp.com", "wikipedia.org",
]

SMS_KEYWORDS = [
    "urgent", "immediately", "now", "asap", "expires", "limited time",
    "act fast", "hurry", "won", "winner", "prize", "free", "gift", "cash",
    "money", "bank", "credit", "debit", "refund", "payment", "ssn",
    "social security", "pin", "otp", "code", "verify your", "confirm your",
    "click here", "claim", "congratulations", "selected", "lucky",
    "bit.ly", "tinyurl", "goo.gl", "shorturl", "suspended", "blocked",
    "unusual activity", "text message", "sms", "txt",
]

CLONE_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "confirm", "account", "password", "auth",
]

THREAT_TYPE_LABELS = {
    "url":    "URL Phishing",
    "email":  "Email Phishing",
    "domain": "Domain Spoofing",
    "clone":  "Clone Website Phishing",
    "sms":    "SMS Phishing",
}

PHISHING_TYPES = [
    {
        "id": 1, "name": "URL Phishing", "icon": "🔗", "threatType": "url",
        "description": "Malicious URLs designed to trick users into visiting fake websites that steal credentials or install malware.",
        "example": "http://g00gle-secure.tk/login/verify-account",
        "placeholder": "e.g., http://paypa1-secure.tk/login",
        "prevention": "Always check the URL carefully before clicking. Look for misspellings and suspicious TLDs.",
    },
    {
        "id": 2, "name": "Email Phishing", "icon": "📧", "threatType": "email",
        "description": "Fraudulent emails from fake addresses designed to appear as trusted organizations to steal sensitive data.",
        "example": "support@paypa1-secure.xyz",
        "placeholder": "e.g., admin@g00gle-security.tk",
        "prevention": "Verify sender addresses carefully. Never click links in unexpected emails.",
    },
    {
        "id": 3, "name": "Domain Spoofing", "icon": "🌐", "threatType": "domain",
        "description": "Fake domains that mimic legitimate websites using similar-looking characters or misspellings to deceive users.",
        "example": "amaz0n-support.xyz",
        "placeholder": "e.g., faceb00k-login.tk",
        "prevention": "Always type URLs directly. Check for character substitutions like 0 for o.",
    },
    {
        "id": 4, "name": "Clone Website Phishing", "icon": "📋", "threatType": "clone",
        "description": "Exact replicas of legitimate websites hosted on different domains to harvest user credentials and data.",
        "example": "http://192.168.1.1/netflix/login/verify",
        "placeholder": "e.g., http://faceb00k.tk/login/signin",
        "prevention": "Check the domain matches the official site. Look for HTTPS and valid certificates.",
    },
    {
        "id": 5, "name": "SMS Phishing (Smishing)", "icon": "📱", "threatType": "sms",
        "description": "Phishing attacks via SMS text messages containing malicious links, urgency language, or fake prize claims.",
        "example": "URGENT: Your bank account is suspended! Verify now at bit.ly/xyz123",
        "placeholder": "e.g., You won a $500 gift card! Claim now: bit.ly/free",
        "prevention": "Never click links in unexpected texts. Contact the company directly through official channels.",
    },
]

# ── Detection helpers ─────────────────────────────────────────────────────────

def has_ip_address(url: str) -> bool:
    return bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url))

def has_suspicious_length(url: str) -> bool:
    return len(url) > 75

def has_no_https(url: str) -> bool:
    lower = url.lower()
    if not lower.startswith("http://") and not lower.startswith("https://"):
        return True
    return lower.startswith("http://")

def has_suspicious_keywords(url: str) -> bool:
    lower = url.lower()
    return any(kw in lower for kw in SUSPICIOUS_KEYWORDS)

def has_at_symbol(url: str) -> bool:
    return "@" in url

def has_too_many_dots(url: str) -> bool:
    return url.count(".") > 4

def has_suspicious_tld(url: str) -> bool:
    lower = url.lower()
    return any(tld in lower for tld in SUSPICIOUS_TLDS)

def has_hyphen_bomb(url: str) -> bool:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.hostname.count("-") > 3 if parsed.hostname else False
    except Exception:
        return False

def has_subdomain_abuse(url: str) -> bool:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return len(parsed.hostname.split(".")) > 4 if parsed.hostname else False
    except Exception:
        return False

def has_encoded_chars(url: str) -> bool:
    return bool(re.search(r'%[0-9a-fA-F]{2}', url)) and url.count("%") > 2

# ── Type detection ────────────────────────────────────────────────────────────

def detect_threat_type(input_text: str) -> str:
    trimmed = input_text.strip().lower()

    if re.search(r'[^\s@]+@[^\s@]+\.[^\s@]+', trimmed):
        return "email"

    if re.match(r'^(\+?\d[\d\s\-()\u200b]{7,})', trimmed):
        return "sms"

    has_spaces = " " in trimmed
    sms_count = sum(1 for kw in SMS_KEYWORDS if kw in trimmed)
    if has_spaces and sms_count >= 1:
        return "sms"

    is_url_like = bool(re.match(r'^https?://', trimmed)) or "/" in trimmed
    if is_url_like:
        clone_count = sum(1 for kw in CLONE_KEYWORDS if kw in trimmed)
        has_brand_mimic = any(
            trimmed.split(".")[0].endswith(ld.split(".")[0]) or ld.split(".")[0] in trimmed
            for ld in LEGITIMATE_DOMAINS
            if ld not in trimmed
        )
        has_ip = has_ip_address(trimmed)
        if (clone_count >= 1 and has_brand_mimic) or (has_ip and clone_count >= 1) or (has_brand_mimic and has_ip):
            return "clone"
        return "url"

    if re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$', trimmed):
        return "domain"

    if has_spaces:
        return "sms"

    return "url"

# ── Rule sets ─────────────────────────────────────────────────────────────────

def analyze_email(email: str):
    lower = email.lower()
    parts = lower.split("@")
    domain = parts[1] if len(parts) > 1 else ""
    local = parts[0] if parts else ""
    return [
        {"name": "Disposable Email Provider",      "description": "Email uses a known disposable/temporary email service",                       "weight": 30, "triggered": any(d in domain for d in DISPOSABLE_EMAIL_DOMAINS)},
        {"name": "Suspicious Keywords in Address", "description": "Email address contains phishing-related keywords",                            "weight": 15, "triggered": any(kw in lower for kw in SUSPICIOUS_KEYWORDS)},
        {"name": "Suspicious TLD",                 "description": "Email domain uses a TLD commonly associated with phishing",                   "weight": 15, "triggered": any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)},
        {"name": "Numeric Domain",                 "description": "Email domain contains excessive numbers suggesting auto-generated domain",     "weight": 20, "triggered": bool(re.search(r'\d{4,}', domain))},
        {"name": "Brand Impersonation",            "description": "Email domain mimics a well-known brand with slight misspelling",              "weight": 25, "triggered": any(ld.split(".")[0] in domain and domain != ld for ld in LEGITIMATE_DOMAINS)},
        {"name": "Hyphenated Domain",              "description": "Email domain uses excessive hyphens to appear legitimate",                    "weight": 10, "triggered": domain.count("-") > 2},
        {"name": "Long Local Part",                "description": "Local part of email is unusually long suggesting auto-generation",            "weight": 10, "triggered": len(local) > 30},
    ]

def analyze_domain(domain: str):
    lower = domain.lower()
    first_part = lower.split(".")[0] if "." in lower else lower
    return [
        {"name": "Suspicious TLD",      "description": "Domain uses a TLD commonly associated with phishing",                     "weight": 20, "triggered": any(lower.endswith(tld) for tld in SUSPICIOUS_TLDS)},
        {"name": "Brand Impersonation", "description": "Domain mimics a well-known brand name with slight variations",             "weight": 30, "triggered": any(ld.split(".")[0] in lower and lower != ld for ld in LEGITIMATE_DOMAINS)},
        {"name": "Excessive Hyphens",   "description": "Domain uses many hyphens to mimic legitimate sites",                      "weight": 15, "triggered": lower.count("-") > 2},
        {"name": "Excessive Length",    "description": "Domain is unusually long suggesting obfuscation",                         "weight": 10, "triggered": len(lower) > 40},
        {"name": "Subdomain Abuse",     "description": "Domain has too many subdomains to confuse users",                         "weight": 15, "triggered": len(lower.split(".")) > 4},
        {"name": "Numeric Domain",      "description": "Domain contains many numbers suggesting auto-generation",                  "weight": 15, "triggered": bool(re.search(r'\d{4,}', lower))},
        {"name": "Homograph Detection", "description": "Domain uses character substitution (e.g., 0 for o, 1 for l)",             "weight": 20, "triggered": bool(re.search(r'[0-9]', first_part)) and any(first_part.replace("0","o").replace("1","l") == ld.split(".")[0] for ld in LEGITIMATE_DOMAINS)},
    ]

def analyze_clone_website(url: str):
    lower = url.lower()
    return [
        {"name": "Brand Impersonation",        "description": "URL mimics a well-known website with slight variations",                         "weight": 25, "triggered": any(ld.split(".")[0] in lower and ld not in lower for ld in LEGITIMATE_DOMAINS)},
        {"name": "No HTTPS",                   "description": "Clone website doesn't use HTTPS encryption",                                     "weight": 20, "triggered": has_no_https(url)},
        {"name": "IP Address Usage",           "description": "Website hosted on raw IP instead of domain name",                                "weight": 25, "triggered": has_ip_address(url)},
        {"name": "Login/Verify Keywords",      "description": "URL contains login or verification keywords suggesting credential harvesting",    "weight": 15, "triggered": bool(re.search(r'\b(login|signin|verify|confirm|account)\b', lower))},
        {"name": "Suspicious Path",            "description": "URL has deep or suspicious path structure mimicking real sites",                  "weight": 10, "triggered": url.count("/") > 5},
        {"name": "Suspicious TLD",             "description": "Clone website uses a TLD commonly associated with phishing",                     "weight": 15, "triggered": has_suspicious_tld(url)},
        {"name": "Encoded Characters",         "description": "URL uses encoding to hide its true destination",                                 "weight": 10, "triggered": has_encoded_chars(url)},
    ]

def analyze_sms(message: str):
    lower = message.lower()
    return [
        {"name": "Urgency Language",       "description": "Message uses urgent language to pressure immediate action",              "weight": 20, "triggered": bool(re.search(r'\b(urgent|immediately|now|asap|expires|limited time|act fast|hurry)\b', lower))},
        {"name": "Suspicious Link",        "description": "Message contains a shortened or suspicious URL",                         "weight": 25, "triggered": bool(re.search(r'\b(bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|is\.gd|shorturl)\b', lower)) or bool(re.search(r'https?://\S+', lower))},
        {"name": "Financial Keywords",     "description": "Message references money, prizes, or financial incentives",              "weight": 20, "triggered": bool(re.search(r'\b(won|winner|prize|free|gift|cash|money|bank|credit|debit|refund|payment)\b', lower))},
        {"name": "Personal Info Request",  "description": "Message asks for personal or sensitive information",                     "weight": 25, "triggered": bool(re.search(r'\b(ssn|social security|password|pin|otp|code|verify|confirm your)\b', lower))},
        {"name": "Brand Impersonation",    "description": "Message pretends to be from a known brand or service",                  "weight": 15, "triggered": any(ld.split(".")[0] in lower for ld in LEGITIMATE_DOMAINS)},
        {"name": "Phone Number Presence",  "description": "Message includes callback phone number for vishing",                    "weight": 10, "triggered": bool(re.search(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', message))},
        {"name": "Suspicious Sender",      "description": "Message appears to be from a non-standard number or source",            "weight": 10, "triggered": bool(re.match(r'^(\+?\d{1,4})', message.strip()))},
    ]

def analyze_url_rules(url: str):
    return [
        {"name": "IP Address Detection",  "description": "URL contains an IP address instead of a domain name",                       "weight": 25, "triggered": has_ip_address(url)},
        {"name": "URL Length Check",      "description": "URL is unusually long (>75 characters)",                                     "weight": 15, "triggered": has_suspicious_length(url)},
        {"name": "HTTPS Verification",    "description": "URL does not use secure HTTPS protocol",                                     "weight": 20, "triggered": has_no_https(url)},
        {"name": "Suspicious Keywords",   "description": "URL contains phishing-related keywords",                                     "weight": 15, "triggered": has_suspicious_keywords(url)},
        {"name": "@ Symbol Detection",    "description": "URL contains @ symbol used to obfuscate the real destination",              "weight": 20, "triggered": has_at_symbol(url)},
        {"name": "Excessive Dots",        "description": "URL has too many dots indicating subdomain manipulation",                    "weight": 10, "triggered": has_too_many_dots(url)},
        {"name": "Suspicious TLD",        "description": "URL uses a top-level domain commonly associated with phishing",             "weight": 15, "triggered": has_suspicious_tld(url)},
        {"name": "Hyphen Abuse",          "description": "Domain contains excessive hyphens to mimic legitimate sites",               "weight": 10, "triggered": has_hyphen_bomb(url)},
        {"name": "Subdomain Abuse",       "description": "URL has excessive subdomains to confuse users",                             "weight": 10, "triggered": has_subdomain_abuse(url)},
        {"name": "Encoded Characters",    "description": "URL contains many encoded characters to hide its true content",             "weight": 10, "triggered": has_encoded_chars(url)},
    ]

# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_by_type(input_text: str, threat_type: str) -> dict:
    rule_map = {
        "email":  analyze_email,
        "domain": analyze_domain,
        "clone":  analyze_clone_website,
        "sms":    analyze_sms,
    }
    rules = rule_map.get(threat_type, analyze_url_rules)(input_text)

    risk_score = min(100, sum(r["weight"] for r in rules if r["triggered"]))
    if risk_score <= 20:
        classification = "Legitimate"
    elif risk_score <= 50:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    return {
        "url": input_text,
        "riskScore": risk_score,
        "classification": classification,
        "rules": rules,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "threatType": threat_type,
    }

def analyze_url(input_text: str) -> dict:
    threat_type = detect_threat_type(input_text)
    return analyze_by_type(input_text, threat_type)
