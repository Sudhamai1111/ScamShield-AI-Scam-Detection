"""
ScamShield - Application Configuration
Handles environment variables, security limits, risk thresholds, and constants.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
BACKEND_DIR = BASE_DIR / "backend"
LOCAL_DATA_DIR = BASE_DIR / "data"

LOCAL_DATA_DIR.mkdir(exist_ok=True)


class Config:
    """Centralized application configuration."""

    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    PORT = int(os.getenv("PORT", 5000))
    HOST = os.getenv("HOST", "127.0.0.1")

    # Security & Input Validation
    MIN_MESSAGE_LENGTH = 10
    MAX_MESSAGE_LENGTH = 5000
    MAX_REPORT_DESCRIPTION_LENGTH = 2000
    MAX_REPORTS_PER_QUERY = 50

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # Firebase Firestore Settings
    FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS_PATH", "")
    FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "")
    FIREBASE_COLLECTION_NAME = os.getenv("FIREBASE_COLLECTION_NAME", "scam_reports")
    LOCAL_FALLBACK_FILE = LOCAL_DATA_DIR / "local_reports.json"

    # Risk Tiers (Strict specification)
    # 0?25: Low Risk
    # 26?50: Needs Attention
    # 51?75: Suspicious
    # 76?100: High Risk
    RISK_TIERS = {
        "LOW": {"min": 0, "max": 25, "label": "Low Risk", "color": "#43A047"},
        "ATTENTION": {"min": 26, "max": 50, "label": "Needs Attention", "color": "#FB8C00"},
        "SUSPICIOUS": {"min": 51, "max": 75, "label": "Suspicious", "color": "#E65100"},
        "HIGH": {"min": 76, "max": 100, "label": "High Risk", "color": "#E53935"},
    }

    # Mandatory Legal & Safety Disclaimer
    DISCLAIMER = (
        "ScamShield provides an automated risk assessment based on detected indicators. "
        "It cannot determine with 100% certainty whether a message is genuine or fraudulent. "
        "Always independently verify important requests through official channels."
    )
