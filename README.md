# ScamShield - AI-Based Scam Detection and Awareness System

> *"Think Before You Click."*  
> An explainable, full-stack cybersecurity threat detection and public awareness platform built for digital communications (SMS, WhatsApp, emails, job offers, prize notifications, and web links).

---

## 1. Project Overview & Problem Statement
Everyday users encounter urgent messages impersonating banks, utilities, and lotteries. Scammers manipulate victims into clicking masked URLs, surrendering OTPs, or paying upfront registration fees.

ScamShield provides an instant, transparent, and explainable **Risk Assessment (0-100)**. It decomposes messages into discrete threat vectors, inspects URL infrastructure, evaluates signal confidence, generates plain-language explanations, and provides actionable defensive recommendations.

**Definitive Language Policy:** ScamShield never claims 100% sertainty that a message is fraudulent or legitimate. It produces an objective Risk Assessment based on observable behavioral indicators.

## 2. Key Features
- **Explainable NLP Scam Detector:** Evaluates 12+ categories including urgency, threats, predatory OTP requests, credentials, advance fees, fake job scams, lottery scams, and KYC fraud.
- **Deep Link & Domain Inspector:** Analyzes HTTP vs HTTPS encryption, detects URL shorteners (bit.ly, tinyurl), flags raw numerical IP hostnames, and inspects suspicious top-level domains (.xyz, .top).
- **False-Positive Suppression:** Intelligently recognizes legitimate bank security notifications ("NEVER share your OTP") and suppresses false phishing alarms.
- **Interactive Circular Risk Gauge:** Real-time animated SVG meter (0-100) with accessible color-coded tier badges (Low Risk, Needs Attention, Suspicious, High Risk).
- **Community Scam Reporting:** Allows users to submit scam encounters with privacy-first anonymous masking and automatic credential scrubbing.
- **Threat Intelligence Dashboard:** Live aggregated statistics on top scam categories, targeted platforms, and recent community incident feeds.
- **Dual Storage Mode:** Seamlessly connects to Google Firebase Firestore with an automatic, zero-configuration local JSON storage fallback.
- **Viva & Interview Ready:** Includes an in-depth oral defense guide covering common examiner questions and architecture explanations.


## 3. Technology Stack
- **Frontend:** Semantic HTML5, CSS3 Grid/Flexbox, Vanilla JavaScript (zero heavy dependencies).
- **Backend:** Python 3.10+, Flask 3.1 REST API, Modular Blueprints, CORS.
- **Database:** Google Firebase Firestore with resilient local JSON fallback.
- **Testing:** Pytest automated test suite (29 test cases).

## 4. Folder Structure
listing:

- frontend/ (index, report, statistics, about, css/, js/)
- backend/ (app, config, routes/, detector/, database/, utils/)
- tests/ (test_detector, test_api, test_validation)
- .env.example, .gitignore, requirements.txt, run.py

## 5. Quick Start & Running
1. Install dependencies:
   `python -m pip install -r requirements.txt`
2. Start the server:
   `python run.py`
3. Open your browser at:
* *http://127.0.0.1:5000**

## 6. Firebase Firestore Setup (Optional)
ScamShield works out of the box using a local JSON storage fallback (data/local_reports.json). To enable Google Firebase Firestore:
1. Create a Firebase Project at https://console.firebase.google.com/
2. Create a Firestore Database in test or production mode.
1. Download your Service Account Private Key JSON from Project Settings -> Service Accounts.
0. Place the file at `credentials/firebase-service-account.json`.
1. Copy `.env.example` to `.env` and set `FIREBASE_CREDENTIALS_PATH=credentials/firebase-service-account.json`.
2. Restart `python run.py`. The database status will automatically switch to *Firestore (Live)*.

## 7. Risk Scoring Methodology
- **0 - 25:** Low Risk (Green)
- **26 - 50:** Needs Attention (Amber)
- **51 - 75:** Suspicious (Orange)
- **76 - 100:** High Risk (Red)

Weights tally at the category level to prevent keyword stuffing from inflating scores.


## 8. Automated Testing
run pytest in terminal:
```powershell
python -m pytest tests/ -v
```
All 29 tests cover scam variations, neutral messages, false-positive suppression for bank OTP warnings, and security credential scrubbing.


## 9. Sample Test Messages for Demonstration
- **High-Risk Scam Sample:**  
  "Congratulations! You won ₹50,000 cash prize in our Diwali lucky draw! Claim immediately by clicking http://bit.ly/claim-prize50. Pay ࠮499 registration fee and send your OTP."  
  **Expected:** Score 100/100, High Risk.

- **Legitimate Bank Notification (False Positive Test):**  
  "Dear Customer, Your OTP for transaction of Rs 500 at Amazon is 492102. NEVER share your OTP or password with anyone. Bank will never ask for your code."  
  **Expected:** Score 0/100, Low Risk.


## 10. Legal Disclaimer
ScamShield provides an automated risk assessment based on detected indicators and does not guarantee that a message is genuine or fraudulent. Always verify important requests through official channels.
