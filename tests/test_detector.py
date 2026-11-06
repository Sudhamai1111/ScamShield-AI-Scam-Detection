"""
ScamShield - Detection Engine Test Suite
Tests indicator extraction, risk scoring bounds (0-100), risk tiers,
explanation generation, and false-positive suppression on legitimate messages.
"""

import pytest
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.detector.scam_detector import ScamDetector
from backend.detector.text_processor import TextProcessor
from backend.detector.risk_scorer import RiskScorer


@pytest.fixture
def detector():
    return ScamDetector()


class TestScamDetector:
    """Comprehensive tests covering >= 15 scam, neutral, and edge cases."""

    # 1. Suspicious: Fake Prize Scam
    def test_fake_prize_scam(self, detector):
        msg = "Congratulations! You won ?1,00,000 in our lucky draw. Claim your prize now."
        res = detector.analyze_message(msg)
        assert res["risk_score"] >= 20
        assert any(i["type"] == "Fake Prize" for i in res["indicators"])

    # 2. Suspicious: Predatory OTP Request
    def test_predatory_otp_request(self, detector):
        msg = "Urgent: Send your OTP immediately to verify your transaction code."
        res = detector.analyze_message(msg)
        assert res["risk_score"] >= 25
        assert any(i["type"] == "OTP Request" for i in res["indicators"])

    # 3. Suspicious: Account Suspension Threat
    def test_account_suspension_threat(self, detector):
        msg = "Your bank account suspended immediately due to unauthorized activity. Contact support."
        res = detector.analyze_message(msg)
        assert any(i["type"] == "Threatening Language" for i in res["indicators"])

    # 4. Suspicious: Fake Job Registration Fee
    def test_fake_job_fee_scam(self, detector):
        msg = "Work from home part time job. Earn ?5000 daily. No experience required. Pay registration fee to join."
        res = detector.analyze_message(msg)
        assert res["risk_score"] >= 40
        assert any(i["type"] == "Fake Job Scam" for i in res["indicators"])
        assert any(i["type"] == "Payment Request" for i in res["indicators"])

    # 5. Suspicious: Guaranteed Investment Return
    def test_investment_scam(self, detector):
        msg = "Double your money in 48 hours! Guaranteed returns with our risk-free crypto bot."
        res = detector.analyze_message(msg)
        assert res["risk_score"] >= 25
        assert any(i["type"] == "Unrealistic Investment" for i in res["indicators"])

    # 6. Suspicious: Shortened Link
    def test_shortened_url_detection(self, detector):
        msg = "Your delivery package requires address confirmation at http://bit.ly/track9812 immediately."
        res = detector.analyze_message(msg)
        assert any(i["type"] == "URL Shortener" for i in res["indicators"])
        assert res["links_analyzed"][0]["is_shortened"] is True

    # 7. Suspicious: Advance Payment / Processing Fee
    def test_processing_fee_request(self, detector):
        msg = "Your loan of Rs 5,00,000 is approved. Transfer money for processing fee of Rs 1,500 now."
        res = detector.analyze_message(msg)
        assert any(i["type"] == "Payment Request" for i in res["indicators"])

    # 8. Suspicious: KYC Expiration Threat
    def test_kyc_suspension_scam(self, detector):
        msg = "Dear customer, your KYC expired. Update KYC urgently to avoid deactivation."
        res = detector.analyze_message(msg)
        assert any(i["type"] == "KYC Scam" for i in res["indicators"])

    # 9. Suspicious: Raw Numerical IP Hostname
    def test_raw_ip_address_link(self, detector):
        msg = "Security update needed: please login at http://192.168.1.105/portal immediately."
        res = detector.analyze_message(msg)
        assert any(l["is_ip"] for l in res["links_analyzed"])


    # 18. Obfuscated shortened link combined with account-blocking threat
    def test_obfuscated_bank_suspension_link(self, detector):
        msg = (
            "SBI ALERT: Your account will be blocked today. "
            "Verify immediately at hxxp://bit[dot]ly/sbi-verify to avoid suspension."
        )
        res = detector.analyze_message(msg)
        indicator_types = {item["type"] for item in res["indicators"]}

        assert res["risk_score"] >= 51
        assert res["risk_level"] == "Suspicious"
        assert "Urgency" in indicator_types
        assert "Threatening Language" in indicator_types
        assert "Suspicious Link" in indicator_types
        assert "URL Shortener" in indicator_types
        assert res["links_analyzed"][0]["hostname"] == "bit.ly"
        assert res["links_analyzed"][0]["is_shortened"] is True

    # 10. Suspicious: Legal / Police Threat
    def test_legal_action_threat(self, detector):
        msg = "Final notice: Legal action and police case will be initiated against you within 24 hours."
        res = detector.analyze_message(msg)
        assert any(i["type"] == "Threatening Language" for i in res["indicators"])
        assert any(i["type"] == "Urgency" for i in res["indicators"])

    # 11. Suspicious: Combined Multi-Vector Phishing (Specification Example)
    def test_combined_high_risk_scam(self, detector):
        msg = "Congratulations! You won ?50,000. Claim immediately by clicking http://bit.ly/example. Pay ?499 processing fee and send your OTP."
        res = detector.analyze_message(msg)
        assert res["risk_score"] >= 76
        assert res["risk_level"] == "High Risk"
        assert len(res["indicators"]) >= 4

    # 12. Legitimate / Neutral: Project Meeting Reminder
    def test_legitimate_meeting_reminder(self, detector):
        msg = "Hi team, please remember our project sprint review is scheduled for tomorrow at 3 PM."
        res = detector.analyze_message(msg)
        assert res["risk_score"] <= 25
        assert res["risk_level"] == "Low Risk"

    # 13. Legitimate / Neutral: Delivery Notification without Fee
    def test_legitimate_package_delivery(self, detector):
        msg = "Your courier order #89218 has been shipped with BlueDart and will arrive on Friday. Thank you."
        res = detector.analyze_message(msg)
        assert res["risk_score"] <= 25
        assert res["risk_level"] == "Low Risk"

    # 14. Legitimate / Neutral: College Announcement
    def test_legitimate_college_notice(self, detector):
        msg = "Annual semester exam registration deadline is Friday. Check the university notice board."
        res = detector.analyze_message(msg)
        assert res["risk_score"] <= 25
        assert res["risk_level"] == "Low Risk"

    # 15. Legitimate / Neutral: Friendly Conversation
    def test_legitimate_casual_chat(self, detector):
        msg = "Hey Rahul, let us catch up for coffee this weekend if you are free."
        res = detector.analyze_message(msg)
        assert res["risk_score"] <= 25
        assert res["risk_level"] == "Low Risk"

    # 16. Legitimate Bank Advisory (False Positive Suppression)
    def test_legitimate_bank_otp_advisory(self, detector):
        msg = "Your OTP for transaction of Rs 500 at Amazon is 492102. NEVER share your OTP or password with anyone. Bank will never ask for your code."
        res = detector.analyze_message(msg)
        assert res["risk_score"] <= 25
        assert res["risk_level"] == "Low Risk"
        # Predatory OTP indicator should not trigger
        assert not any(i["type"] == "OTP Request" for i in res["indicators"])

    # 17. Score Bounds & Structure Invariant
    def test_score_bounds_and_structure(self, detector):
        msg = "Urgent congratulations! You won cash. Transfer money and send your OTP to bit.ly/win."
        res = detector.analyze_message(msg)
        assert 0 <= res["risk_score"] <= 100
        assert res["risk_level"] in ["Low Risk", "Needs Attention", "Suspicious", "High Risk"]
        assert 0.0 <= res["confidence"] <= 1.0
        assert "disclaimer" in res
        assert "recommendations" in res
        assert "explanation" in res
