from flask import Flask, render_template, request, jsonify, Response
from phishing_engine import analyze_url, analyze_by_type, detect_threat_type, THREAT_TYPE_LABELS, PHISHING_TYPES
from phishing_stats import YEARLY_THREAT_DATA, PIE_DATA_BY_TYPE
import json
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", phishing_types=PHISHING_TYPES, threat_labels=THREAT_TYPE_LABELS)

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    input_text = data.get("input", "").strip()
    threat_type = data.get("threatType", None)

    if not input_text:
        return jsonify({"error": "No input provided"}), 400

    if threat_type:
        result = analyze_by_type(input_text, threat_type)
    else:
        result = analyze_url(input_text)

    return jsonify({
        "url": result["url"],
        "riskScore": result["riskScore"],
        "classification": result["classification"],
        "threatType": result["threatType"],
        "timestamp": result["timestamp"],
        "rules": result["rules"],
    })

@app.route("/api/detect-type", methods=["POST"])
def detect_type():
    data = request.get_json()
    input_text = data.get("input", "").strip()
    if not input_text:
        return jsonify({"type": "url"})
    threat_type = detect_threat_type(input_text)
    return jsonify({"type": threat_type, "label": THREAT_TYPE_LABELS[threat_type]})

@app.route("/api/stats/bar")
def bar_stats():
    return jsonify(YEARLY_THREAT_DATA)

@app.route("/api/stats/pie/<threat_type>")
def pie_stats(threat_type):
    data = PIE_DATA_BY_TYPE.get(threat_type, [])
    return jsonify(data)

@app.route("/report")
def download_report():
    now = datetime.now()
    report = f"""================================================================================
                        PHISHGUARD — PROJECT REPORT
================================================================================

Generated: {now.strftime('%Y-%m-%d')} at {now.strftime('%H:%M:%S')}

--------------------------------------------------------------------------------
1. PROJECT OVERVIEW
--------------------------------------------------------------------------------

Project Name  : PhishGuard
Version       : 1.0
Type          : Rule-Based Phishing Detection Tool
Category      : Cybersecurity / Student Project
Platform      : Web Application (Python + Flask)

PhishGuard is a client-side phishing detection tool that analyzes URLs, email
addresses, domains, SMS messages, and clone websites against a comprehensive
set of security rules. It classifies inputs as Legitimate, Suspicious, or
Phishing based on a weighted risk scoring system.

--------------------------------------------------------------------------------
2. TECHNOLOGY STACK
--------------------------------------------------------------------------------

Backend Framework   : Python 3 with Flask
Frontend            : HTML5, CSS3, Vanilla JavaScript
Charts              : Chart.js (CDN)
Fonts               : JetBrains Mono, Space Grotesk (Google Fonts)
Template Engine     : Jinja2

--------------------------------------------------------------------------------
3. THREAT DETECTION CAPABILITIES
--------------------------------------------------------------------------------

PhishGuard detects 5 types of phishing threats:

  3.1 URL Phishing
      - Detects suspicious URLs with IP addresses, excessive subdomains,
        misleading characters, and known malicious TLDs.
      - Rules: IP-based URL, suspicious TLD (.tk, .ml, .xyz, etc.),
        URL length analysis, HTTPS check, homograph detection.

  3.2 Email Phishing
      - Identifies phishing emails by analyzing sender domains,
        display name mismatches, and suspicious patterns.
      - Rules: Free email provider check, domain typosquatting,
        numeric sender patterns, suspicious TLD usage.

  3.3 Domain Spoofing
      - Detects domains that mimic legitimate brands using typosquatting,
        character substitution, and misleading subdomains.
      - Rules: Brand impersonation, homograph attacks, excessive hyphens,
        recently-registered TLD patterns.

  3.4 Clone Websites
      - Identifies cloned/fake versions of legitimate websites.
      - Rules: Login page on suspicious domain, brand keyword + bad TLD,
        IP-hosted login pages, credential harvesting indicators.

  3.5 SMS Phishing (Smishing)
      - Analyzes SMS messages for urgency tactics, suspicious links,
        and social engineering patterns.
      - Rules: URL shortener detection, urgency keywords, financial
        lure patterns, too-good-to-be-true offers.

--------------------------------------------------------------------------------
4. RISK SCORING ALGORITHM
--------------------------------------------------------------------------------

The engine uses a weighted rule-based scoring system:

  - Each rule has a weight (points) assigned based on severity.
  - Triggered rules accumulate points toward a total risk score.
  - The maximum score is capped at 100%.

Classification Thresholds:
  - Legitimate  : Risk Score <= 20%
  - Suspicious  : Risk Score 21% - 50%
  - Phishing    : Risk Score > 50%

--------------------------------------------------------------------------------
5. KEY FEATURES
--------------------------------------------------------------------------------

  + Universal input scanner (URL, email, domain, SMS, clone)
  + Auto-detection of input/threat type
  + Real-time live preview while typing
  + Detailed rule-by-rule analysis report
  + Visual risk score bar with color coding
  + Per-category phishing type cards with example inputs
  + Fully client-side analysis — no data stored server-side
  + Dark terminal-style UI theme

--------------------------------------------------------------------------------
6. PROJECT FILES
--------------------------------------------------------------------------------

  phishguard/
  |-- app.py                   # Flask application + API routes
  |-- phishing_engine.py       # Detection rules & scoring engine
  |-- phishing_stats.py        # Chart/statistics data
  |-- requirements.txt         # Python dependencies
  |-- templates/
  |   `-- index.html           # Main Jinja2 template
  `-- static/
      |-- css/style.css        # Dark terminal theme stylesheet
      `-- js/main.js           # Frontend interactivity & API calls

--------------------------------------------------------------------------------
7. SECURITY RULES SUMMARY
--------------------------------------------------------------------------------

Total Rules per Category:
  - URL Phishing     : 10 rules
  - Email Phishing   :  7 rules
  - Domain Spoofing  :  7 rules
  - Clone Website    :  7 rules
  - SMS Phishing     :  7 rules

Rule examples:
  * IP Address in URL          (weight: 25)
  * Suspicious TLD             (weight: 20)
  * Homograph Characters       (weight: 20)
  * Brand Impersonation        (weight: 30)
  * URL Shortener in SMS       (weight: 25)
  * Urgency Keywords           (weight: 20)

--------------------------------------------------------------------------------
8. RUNNING THE PROJECT
--------------------------------------------------------------------------------

  1. Install dependencies:
       pip install flask

  2. Start the server:
       python app.py

  3. Open in browser:
       http://localhost:5000

--------------------------------------------------------------------------------
9. LIMITATIONS & FUTURE SCOPE
--------------------------------------------------------------------------------

Current Limitations:
  - Rule-based only (no machine learning)
  - Cannot verify actual website content or SSL certificates
  - No real-time threat intelligence feed
  - No persistent scan history

Future Enhancements:
  - ML-based classification model integration
  - Browser extension for real-time protection
  - API integration with threat intelligence databases
  - Scan history with analytics dashboard

--------------------------------------------------------------------------------
10. CONCLUSION
--------------------------------------------------------------------------------

PhishGuard demonstrates a practical, rule-based approach to phishing detection
across multiple attack vectors. It provides instant, server-side analysis with
clear visual feedback, making it an effective educational and utility tool for
cybersecurity awareness.

================================================================================
                          END OF REPORT — PhishGuard v1.0
================================================================================"""
    filename = f"PhishGuard_Project_Report_{now.strftime('%Y-%m-%d')}.txt"
    return Response(
        report,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)
