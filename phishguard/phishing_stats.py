"""
phishing_stats.py
Simulated phishing statistics — Python port of phishing-stats.ts
"""

YEARLY_THREAT_DATA = [
    {"year": "2022", "urlPhishing": 1250, "emailPhishing": 3400, "domainSpoofing": 890,  "cloneWebsite": 670,  "smsPhishing": 1100},
    {"year": "2023", "urlPhishing": 1780, "emailPhishing": 4200, "domainSpoofing": 1340, "cloneWebsite": 1020, "smsPhishing": 1850},
    {"year": "2024", "urlPhishing": 2350, "emailPhishing": 4900, "domainSpoofing": 1780, "cloneWebsite": 1560, "smsPhishing": 2700},
]

URL_PHISHING_PIE = [
    {"name": "Shortened URLs",  "value": 35, "fill": "hsl(0, 85%, 60%)"},
    {"name": "Typosquatting",   "value": 25, "fill": "hsl(30, 90%, 55%)"},
    {"name": "IP-based URLs",   "value": 20, "fill": "hsl(45, 85%, 55%)"},
    {"name": "Encoded URLs",    "value": 12, "fill": "hsl(200, 70%, 50%)"},
    {"name": "Open Redirects",  "value": 8,  "fill": "hsl(260, 60%, 55%)"},
]

EMAIL_PHISHING_PIE = [
    {"name": "Spear Phishing",                "value": 30, "fill": "hsl(0, 85%, 60%)"},
    {"name": "Business Email Compromise",     "value": 25, "fill": "hsl(30, 90%, 55%)"},
    {"name": "Credential Harvesting",         "value": 22, "fill": "hsl(45, 85%, 55%)"},
    {"name": "Malware Delivery",              "value": 15, "fill": "hsl(200, 70%, 50%)"},
    {"name": "Whaling",                       "value": 8,  "fill": "hsl(260, 60%, 55%)"},
]

DOMAIN_SPOOFING_PIE = [
    {"name": "Homograph Attacks", "value": 28, "fill": "hsl(0, 85%, 60%)"},
    {"name": "Typosquatting",     "value": 32, "fill": "hsl(30, 90%, 55%)"},
    {"name": "Combosquatting",    "value": 18, "fill": "hsl(45, 85%, 55%)"},
    {"name": "Subdomain Abuse",   "value": 14, "fill": "hsl(200, 70%, 50%)"},
    {"name": "TLD Manipulation",  "value": 8,  "fill": "hsl(260, 60%, 55%)"},
]

CLONE_WEBSITE_PIE = [
    {"name": "Banking Clones",       "value": 35, "fill": "hsl(0, 85%, 60%)"},
    {"name": "Social Media Clones",  "value": 28, "fill": "hsl(30, 90%, 55%)"},
    {"name": "E-commerce Clones",    "value": 20, "fill": "hsl(45, 85%, 55%)"},
    {"name": "Government Clones",    "value": 10, "fill": "hsl(200, 70%, 50%)"},
    {"name": "Crypto Clones",        "value": 7,  "fill": "hsl(260, 60%, 55%)"},
]

SMS_PHISHING_PIE = [
    {"name": "Package Delivery Scams", "value": 30, "fill": "hsl(0, 85%, 60%)"},
    {"name": "Bank Alert Scams",       "value": 27, "fill": "hsl(30, 90%, 55%)"},
    {"name": "Prize/Lottery Scams",    "value": 20, "fill": "hsl(45, 85%, 55%)"},
    {"name": "Tax/Govt Scams",         "value": 13, "fill": "hsl(200, 70%, 50%)"},
    {"name": "Account Verify Scams",   "value": 10, "fill": "hsl(260, 60%, 55%)"},
]

PIE_DATA_BY_TYPE = {
    "url":    URL_PHISHING_PIE,
    "email":  EMAIL_PHISHING_PIE,
    "domain": DOMAIN_SPOOFING_PIE,
    "clone":  CLONE_WEBSITE_PIE,
    "sms":    SMS_PHISHING_PIE,
}
