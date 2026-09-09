"""
ScamShield - Core Scam Detection Engine
Modular, explainable scam detection combining text normalization,
contextual phrase analysis, deep link inspection, and transparent risk scoring.
"""

from .text_processor import TextProcessor
from .patterns import (
    URGENCY_PATTERNS,
    THREAT_PATTERNS,
    PASSWORD_REQUEST_PATTERNS,
    PAYMENT_REQUEST_PATTERNS,
    BANKING_PATTERNS,
    PRIZE_PATTERNS,
    INVESTMENT_PATTERNS,
    JOB_SCAM_PATTERNS,
    KYC_PATTERNS,
    PERSONAL_INFO_PATTERNS,
    BYPASS_PATTERNS,
)
from .risk_scorer import RiskScorer
from ..config import Config


class ScamDetector:
    """Explainable scam detection engine."""

    def __init__(self):
        self.processor = TextProcessor()
        self.scorer = RiskScorer()

    def analyze_message(self, message: str) -> dict:
        """
        Main analysis method.
        Inspects message text, extracts indicators, computes risk score,
        and constructs an explainable report.
        """
        normalized = self.processor.normalize(message)

        # 1. Individual Detection Modules
        urgency_matches = self.detect_urgency(normalized)
        threat_matches = self.detect_threats(normalized)
        otp_matches = self.detect_otp_requests(normalized)
        password_matches = self.detect_password_requests(normalized)
        payment_matches = self.detect_payment_requests(normalized)
        banking_matches = self.detect_banking_requests(normalized)
        prize_matches = self.detect_prize_scam(normalized)
        job_matches = self.detect_job_scam(normalized)
        investment_matches = self.detect_investment_scam(normalized)
        kyc_matches = self.detect_kyc_scam(normalized)
        personal_info_matches = self.detect_personal_info(normalized)
        bypass_matches = self.detect_bypass_procedures(normalized)

        # URL extraction & inspection
        links = self.detect_links(message)

        # 2. Build Active Categories Map
        active_categories = {}
        if urgency_matches:
            active_categories["Urgency"] = urgency_matches
        if threat_matches:
            active_categories["Threatening Language"] = threat_matches
        if otp_matches:
            active_categories["OTP Request"] = otp_matches
        if password_matches:
            active_categories["Password Request"] = password_matches
        if payment_matches:
            active_categories["Payment Request"] = payment_matches
        if banking_matches:
            active_categories["Banking Information"] = banking_matches
        if prize_matches:
            active_categories["Fake Prize"] = prize_matches
        if job_matches:
            active_categories["Fake Job Scam"] = job_matches
        if investment_matches:
            active_categories["Unrealistic Investment"] = investment_matches
        if kyc_matches:
            active_categories["KYC Scam"] = kyc_matches
        if personal_info_matches:
            active_categories["Personal Information"] = personal_info_matches
        if bypass_matches:
            active_categories["Bypass Procedures"] = bypass_matches

        # Check for link-based categories
        has_suspicious_link = any(l.get("is_suspicious") for l in links)
        has_shortener = any(l.get("is_shortened") for l in links)
        if has_suspicious_link:
            active_categories["Suspicious Link"] = [l["raw_url"] for l in links if l.get("is_suspicious")]
        elif links:
            # Neutral link present (not overtly suspicious on its own)
            active_categories["Web Link Present"] = [l["raw_url"] for l in links]

        if has_shortener:
            active_categories["URL Shortener"] = [l["raw_url"] for l in links if l.get("is_shortened")]

        # 3. Calculate Risk Score and Tier
        score, risk_level, confidence, color = self.scorer.calculate_score(active_categories, links)

        # 4. Construct Indicators List
        indicators = self._build_indicators_list(active_categories, links)

        # 5. Generate Plain-Language Explanation & Recommendations
        explanation = self.generate_explanation(active_categories, links, risk_level)
        recommendations = self.generate_recommendations(active_categories, links)

        # 6. Concise Summary
        if score >= 76:
            summary = "The message contains multiple severe warning signs strongly associated with fraudulent scams."
        elif score >= 51:
            summary = "The message exhibits several suspicious characteristics that warrant high caution."
        elif score >= 26:
            summary = "The message contains elements that need attention before proceeding or responding."
        else:
            summary = "No major scam indicators were detected, but continue exercising standard digital safety."

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "confidence": confidence,
            "color": color,
            "indicators": indicators,
            "summary": summary,
            "explanation": explanation,
            "recommendations": recommendations,
            "links_analyzed": links,
            "disclaimer": Config.DISCLAIMER,
        }

    # Modular detector methods
    def detect_urgency(self, text: str) -> list:
        return self.processor.match_phrases(text, URGENCY_PATTERNS)

    def detect_threats(self, text: str) -> list:
        return self.processor.match_phrases(text, THREAT_PATTERNS)

    def detect_otp_requests(self, text: str) -> list:
        if self.processor.is_predatory_otp_request(text):
            # Return matching phrases
            matches = self.processor.match_phrases(text, URGENCY_PATTERNS)
            explicit = [p for p in ["otp", "verification code", "one time password", "share the code", "send your otp"] if p in text]
            return explicit or ["Soliciting OTP code"]
        return []

    def detect_password_requests(self, text: str) -> list:
        if self.processor.has_benign_advisory(text):
            return []
        return self.processor.match_phrases(text, PASSWORD_REQUEST_PATTERNS)

    def detect_payment_requests(self, text: str) -> list:
        return self.processor.match_phrases(text, PAYMENT_REQUEST_PATTERNS)

    def detect_banking_requests(self, text: str) -> list:
        if self.processor.has_benign_advisory(text):
            return []
        return self.processor.match_phrases(text, BANKING_PATTERNS)

    def detect_prize_scam(self, text: str) -> list:
        return self.processor.match_phrases(text, PRIZE_PATTERNS)

    def detect_job_scam(self, text: str) -> list:
        return self.processor.match_phrases(text, JOB_SCAM_PATTERNS)

    def detect_investment_scam(self, text: str) -> list:
        return self.processor.match_phrases(text, INVESTMENT_PATTERNS)

    def detect_kyc_scam(self, text: str) -> list:
        return self.processor.match_phrases(text, KYC_PATTERNS)

    def detect_personal_info(self, text: str) -> list:
        return self.processor.match_phrases(text, PERSONAL_INFO_PATTERNS)

    def detect_bypass_procedures(self, text: str) -> list:
        return self.processor.match_phrases(text, BYPASS_PATTERNS)

    def detect_links(self, text: str) -> list:
        return self.processor.extract_urls(text)

    def _build_indicators_list(self, active_categories: dict, links: list) -> list:
        """Construct detailed, user-friendly indicator cards."""
        indicators = []

        descriptions = {
            "OTP Request": ("high", "Requests a one-time password or verification code to compromise account security."),
            "Password Request": ("high", "Asks for passwords, PINs, or confidential login credentials."),
            "Banking Information": ("high", "Solicits payment card numbers, CVVs, IFSC, or sensitive bank details."),
            "Unrealistic Investment": ("high", "Promises guaranteed, risk-free, or unusually high investment returns."),
            "Suspicious Link": ("high", "Contains a URL with obfuscation, numerical IP host, or high-risk domain properties."),
            "Payment Request": ("medium", "Demands advance payment, processing fees, or registration charges."),
            "KYC Scam": ("high", "Fabricates urgent identity verification or account suspension threats."),
            "Fake Job Scam": ("medium", "Advertises effortless high income with no experience or requires an upfront fee."),
            "Fake Prize": ("medium", "Announces lottery or prize winnings for competitions you may not have entered."),
            "Threatening Language": ("medium", "Uses psychological fear of legal action, police arrest, or account blockage."),
            "Personal Information": ("medium", "Requests sensitive personal identity numbers or private credentials."),
            "Bypass Procedures": ("high", "Instructs recipient to conceal actions from banks, family, or official support."),
            "URL Shortener": ("medium", "Utilizes URL shortening services that mask the true destination address."),
            "Urgency": ("low", "Employs high-pressure time limits to provoke an unreflective, hurried response."),
            "Web Link Present": ("low", "Message contains a web link. Always verify the domain name carefully."),
        }

        for cat, matches in active_categories.items():
            if cat in descriptions:
                sev, desc = descriptions[cat]
                indicators.append({
                    "type": cat,
                    "description": desc,
                    "severity": sev,
                    "matched_terms": matches[:5],  # Cap terms display
                })

        return indicators

    def generate_explanation(self, active_categories: dict, links: list, risk_level: str) -> str:
        """Construct plain-language explanation of why the message is flagged."""
        if not active_categories and not links:
            return (
                "No major scam indicators were detected in this message. "
                "However, this does not guarantee that the message is legitimate. "
                "Always remain alert to unexpected contacts or requests for sensitive information."
            )

        reasons = []
        if "Fake Prize" in active_categories:
            reasons.append("claims an unexpected reward or prize")
        if "Urgency" in active_categories:
            reasons.append("pressures you with artificial urgency to act quickly")
        if "Suspicious Link" in active_categories or "URL Shortener" in active_categories:
            reasons.append("includes a shortened or suspicious web link that conceals its real destination")
        if "Payment Request" in active_categories:
            reasons.append("demands an upfront payment or processing fee")
        if "OTP Request" in active_categories:
            reasons.append("solicits a confidential OTP or authentication code")
        if "Password Request" in active_categories or "Banking Information" in active_categories:
            reasons.append("requests sensitive banking details or passwords")
        if "Threatening Language" in active_categories or "KYC Scam" in active_categories:
            reasons.append("uses fear tactics such as threats of account suspension or police intervention")
        if "Fake Job Scam" in active_categories:
            reasons.append("presents an unrealistic job offer requiring advance fees")
        if "Unrealistic Investment" in active_categories:
            reasons.append("promises guaranteed high investment profits without risk")

        if reasons:
            joined_reasons = ", ".join(reasons[:-1]) + (" and " + reasons[-1] if len(reasons) > 1 else reasons[0])
            return (
                f"The message appears suspicious because it {joined_reasons}. "
                "Cybercriminals frequently combine these techniques to manipulate victims into hasty decisions."
            )
        else:
            return (
                "The message contains some indicators that require attention. "
                "Verify the sender's identity through an independent, official channel before taking action."
            )

    def generate_recommendations(self, active_categories: dict, links: list) -> list:
        """Construct specific, actionable safety recommendations."""
        recs = []

        if "OTP Request" in active_categories:
            recs.append("Never share OTPs, verification codes, or 2FA prompts with anyone, even if they claim to be bank officials.")
        if "Password Request" in active_categories or "Banking Information" in active_categories:
            recs.append("Do not share CVV numbers, PINs, passwords, or netbanking credentials under any circumstances.")
        if "Payment Request" in active_categories:
            recs.append("Do not send money or pay upfront fees until you have independently verified the authenticity of the request.")
        if "Suspicious Link" in active_categories or "URL Shortener" in active_categories or links:
            recs.append("Do not click links received in unsolicited messages. Manually visit the organization's official website.")
        if "Unrealistic Investment" in active_categories:
            recs.append("Be cautious of guaranteed or unusually high returns. Legitimate investments always carry market risk.")
        if "Fake Job Scam" in active_categories:
            recs.append("Never pay registration, training, or application fees for employment. Legitimate employers do not charge applicants.")
        if "Fake Prize" in active_categories:
            recs.append("Remember: You cannot legitimately win a lottery, contest, or prize that you never entered.")
        if "Threatening Language" in active_categories or "KYC Scam" in active_categories:
            recs.append("Official agencies and banks do not issue legal notices, arrest threats, or sudden deactivations via SMS or messaging apps.")

        # Default general recommendations
        recs.append("Verify the sender by contacting the organization through phone numbers or emails published on their official website.")
        recs.append("Consider reporting suspicious messages to help protect others in your community.")

        # Return unique recommendations
        seen = set()
        unique_recs = []
        for r in recs:
            if r not in seen:
                seen.add(r)
                unique_recs.append(r)

        return unique_recs[:5]
