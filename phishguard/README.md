# 🛡️ PhishGuard v1.0
**AI-Powered Phishing Detection Tool — Cybersecurity Project**

Detect phishing threats in URLs, email addresses, domains, and SMS messages instantly using a rule-based engine with 10 weighted security checks.

---

## 🚀 Quick Start

### Option 1 — Open directly in browser
```bash
open index.html
```
No server needed. All logic runs client-side.

### Option 2 — Local dev server (recommended)
```bash
# Python
python3 -m http.server 8080

# Node / npx
npx serve .
```
Then visit `http://localhost:8080`

### Run Tests (Node.js)
```bash
node tests.js
```
Or open `tests.html` in a browser for a visual test runner.

---

## 📁 File Structure

```
phishguard/
├── index.html      Main application UI
├── detector.js     Core detection engine (10 rules, fixed scoring)
├── ui.js           DOM rendering, phishing type cards, history panel
├── style.css       Dark cyberpunk theme (JetBrains Mono + Syne)
├── tests.js        Node.js test runner (22 test cases)
├── tests.html      Browser-based visual test runner
├── CHANGELOG.md    All bugs fixed in v1.0
└── README.md       This file
```

---

## 🔍 How It Works

### Input Types Supported
| Type | Example |
|------|---------|
| URL | `https://github.com` |
| Email Address | `user@gmail.com` |
| Domain | `evil-phishing.tk` |
| Phone / SMS | `+1 800 555 0100` |
| Text / SMS body | `Click here to claim your prize!` |

### The 10 Security Rules

| # | Rule | Weight | What it checks |
|---|------|--------|----------------|
| 1 | IP Address Detection | 35 | Hostname is a raw IP (e.g. `192.168.1.1`) |
| 2 | URL Length Check | 10 | Input longer than 70 chars |
| 3 | HTTPS Verification | 20 | Scheme is `http://` not `https://` |
| 4 | Suspicious Keywords | 20 | Phishing keywords in hostname/path |
| 5 | @ Symbol Detection | 35 | `@` in URL authority (obfuscation trick) |
| 6 | Excessive Dots | 15 | ≥4 dots in hostname |
| 7 | Suspicious TLD | 20 | `.tk`, `.xyz`, `.top`, `.ml`, etc. |
| 8 | Hyphen Abuse | 10 | ≥2 hyphens in registrable domain |
| 9 | Subdomain Abuse | 15 | ≥5 hostname parts |
| 10 | Encoded Characters | 20 | `%xx` in hostname, punycode, hex IP |

### Verdict Thresholds
| Verdict | Risk Score |
|---------|-----------|
| ✅ Legitimate | < 10% |
| ⚠️ Suspicious | 10% – 24% |
| 🚨 Phishing | ≥ 25% |

Risk % = (sum of triggered rule weights) / (total possible weight) × 100

---

## 🐛 Bugs Fixed in v1.0

See [CHANGELOG.md](CHANGELOG.md) for full details. Summary:

1. **Critical** — HTTPS check logic was inverted; `https://` URLs were flagged as Phishing
2. **Critical** — Scoring counted ALL rules, not just triggered ones (inflated every score)
3. **Moderate** — Plain email addresses triggered URL-specific rules incorrectly
4. **Moderate** — `@` obfuscation in URL authority was not detected via URL parser
5. **Moderate** — Percent-encoded hostname chars missed (URL() normalises before check)
6. **Minor** — `www.domain.com` triggered subdomain abuse rule (threshold too low)
7. **Minor** — Single-hyphen domains flagged as hyphen abuse
8. **Minor** — Verdict thresholds miscalibrated vs real scoring distribution

---

## 🧪 Test Examples

Try these in the scanner to see each verdict:

**Legitimate:**
```
https://github.com
https://google.com
user@gmail.com
```

**Suspicious:**
```
http://example.com
https://xn--pypal-4ve.com
```

**Phishing:**
```
http://payp4l-secure.tk/verify
http://192.168.1.1/login
https://secure-amazon-verify.xyz/update
http://legit.com@evil.com/page
```

---

## ⚙️ Extending the Engine

To add a new rule, push an object to the `RULES` array in `detector.js`:

```js
{
  id: "my_rule",
  label: "My Rule Label",
  weight: 15,                   // contribution to risk score (0–100 total)
  description: "Shown in UI",
  check(input) {
    // return true to TRIGGER the rule (flag as risky)
    // return false to PASS
    return false;
  }
}
```

The scoring, verdicts, and UI update automatically.

---

## 📜 License
MIT — free to use and extend for educational cybersecurity projects.
