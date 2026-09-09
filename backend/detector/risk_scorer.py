"""
ScamShield - Transparent Risk Scoring Engine
Calculates explainable risk scores (0?100), maps risk tiers, and evaluates signal confidence.
"""

from ..config import Config


class RiskScorer:
    """Computes category-level risk scores with transparent weights and hard clamping."""

    # Category weight specifications
    WEIGHTS = {
        "OTP Request": 25,
        "Password Request": 25,
        "Banking Information": 25,
        "Unrealistic Investment": 25,
        "Suspicious Link": 20,
        "URL Shortener": 10,
        "Payment Request": 20,
        "Fake Job Scam": 20,
        "Fake Prize": 20,
        "KYC Scam": 20,
        "Threatening Language": 15,
        "Personal Information": 15,
        "Bypass Procedures": 15,
        "Urgency": 10,
    }

    @classmethod
    def calculate_score(cls, active_categories: dict, link_details: list = None) -> tuple:
        """
        Calculate total risk score (0?100) using category-level aggregation.
        Avoids keyword stuffing by scoring each category at most once.

        Args:
            active_categories: dict mapping category name -> list of matched keywords
            link_details: list of analyzed URL dictionaries

        Returns:
            (int: score, str: tier_label, float: confidence, str: tier_color)
        """
        base_score = 0
        counted_categories = set()

        # 1. Tally unique category weights
        for cat_name in active_categories.keys():
            if cat_name in cls.WEIGHTS and cat_name not in counted_categories:
                base_score += cls.WEIGHTS[cat_name]
                counted_categories.add(cat_name)

        # 2. Check extra link-specific risks (e.g. raw IP or suspicious TLD)
        if link_details:
            for link in link_details:
                if link.get("is_ip") and "IP Host Risk" not in counted_categories:
                    base_score += 15
                    counted_categories.add("IP Host Risk")
                if link.get("has_suspicious_tld") and "Suspicious TLD" not in counted_categories:
                    base_score += 10
                    counted_categories.add("Suspicious TLD")

        # 3. Multi-indicator synergy: When multiple distinct attack vectors align
        # (e.g. Urgency + Payment + Fake Prize), the convergence warrants slight synergy
        if len(counted_categories) >= 4:
            base_score += 10
        elif len(counted_categories) >= 2:
            base_score += 5

        # 4. Strictly clamp between 0 and 100
        final_score = max(0, min(100, int(base_score)))

        # 5. Determine risk tier according to exact specification:
        # 0?25: Low Risk
        # 26?50: Needs Attention
        # 51?75: Suspicious
        # 76?100: High Risk
        tier_info = cls.get_risk_tier(final_score)

        # 6. Compute signal confidence (0.0 to 1.0)
        # Note: Confidence represents the clarity and agreement of detected patterns,
        # NOT a guarantee or certainty of fraud.
        confidence = cls.compute_signal_confidence(final_score, len(counted_categories))

        return final_score, tier_info["label"], confidence, tier_info["color"]

    @staticmethod
    def get_risk_tier(score: int) -> dict:
        """Map score 0-100 to standard risk tier."""
        for tier_key, tier_data in Config.RISK_TIERS.items():
            if tier_data["min"] <= score <= tier_data["max"]:
                return tier_data
        # Fallback if edge boundary
        if score > 100:
            return Config.RISK_TIERS["HIGH"]
        return Config.RISK_TIERS["LOW"]

    @staticmethod
    def compute_signal_confidence(score: int, indicator_count: int) -> float:
        """
        Calculates signal confidence metric based on detected indicator volume and score alignment.
        Values range between 0.50 and 0.96.
        """
        if indicator_count == 0:
            return 0.50
        elif indicator_count == 1:
            return 0.65
        elif indicator_count == 2:
            return 0.78
        elif indicator_count == 3:
            return 0.86
        else:
            return min(0.95, round(0.85 + (indicator_count * 0.02), 2))
