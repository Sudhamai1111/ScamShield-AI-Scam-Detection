"""
ScamShield - Request Validation & Sensitive Data Scrubbing
"""

import re
from urllib.parse import urlparse
from ..config import Config

ALLOWED_CATEGORIES = [
    "SMS",
    "WhatsApp",
    "Email",
    "Social Media",
    "Fake Job",
    "Investment",
    "Shopping",
    "Prize/Lottery",
    "Banking",
    "KYC",
    "Threat/Urgency",
    "Other",
]

ALLOWED_PLATFORMS = [
    "SMS",
    "WhatsApp",
    "Email",
    "Telegram",
    "Instagram",
    "Facebook",
    "Twitter/X",
    "Phone Call",
    "Website",
    "Other",
]


class ValidationError(Exception):
    """Custom exception for client request validation errors."""
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def validate_analyze_request(data: dict) -> str:
    """Validates POST /api/analyze payload."""
    if not isinstance(data, dict):
        raise ValidationError("Invalid request body. JSON object expected.")

    message = data.get("message")
    if message is None or not str(message).strip():
        raise ValidationError("Please enter a message to analyze.")

    message_str = str(message).strip()

    if len(message_str) < Config.MIN_MESSAGE_LENGTH:
        raise ValidationError(
            f"Message is too short. Please enter at least {Config.MIN_MESSAGE_LENGTH} characters."
        )

    if len(message_str) > Config.MAX_MESSAGE_LENGTH:
        raise ValidationError(
            f"Message is too long. Please limit your input to {Config.MAX_MESSAGE_LENGTH} characters."
        )

    return message_str


def validate_report_request(data: dict) -> dict:
    """Validates POST /api/reports payload."""
    if not isinstance(data, dict):
        raise ValidationError("Invalid request body. JSON object expected.")

    message = data.get("message")
    if not message or not str(message).strip():
        raise ValidationError("Scam message text is required.")

    message_str = str(message).strip()
    if len(message_str) < 5:
        raise ValidationError("Scam message must be at least 5 characters.")
    if len(message_str) > Config.MAX_MESSAGE_LENGTH:
        raise ValidationError(f"Message exceeds maximum length of {Config.MAX_MESSAGE_LENGTH} characters.")

    category = str(data.get("category", "Other")).strip()
    if category not in ALLOWED_CATEGORIES:
        category = "Other"

    platform = str(data.get("platform", "Other")).strip()
    if platform not in ALLOWED_PLATFORMS:
        platform = "Other"

    sender = str(data.get("sender", "")).strip()
    if len(sender) > 100:
        sender = sender[:100]

    url = str(data.get("url", "")).strip()
    if url:
        if len(url) > 500:
            raise ValidationError("URL is too long. Maximum 500 characters allowed.")

    description = str(data.get("description", "")).strip()
    if len(description) > Config.MAX_REPORT_DESCRIPTION_LENGTH:
        raise ValidationError(
            f"Description exceeds maximum limit of {Config.MAX_REPORT_DESCRIPTION_LENGTH} characters."
        )

    sensitive_warnings = scan_for_credentials(message_str + " " + description)
    if sensitive_warnings:
        raise ValidationError(
            f"Sensitive credentials detected ({', '.join(sensitive_warnings)}). "
            "For your security, do NOT submit passwords, OTPs, PINs, or CVVs in scam reports."
        )

    return {
        "message": message_str,
        "category": category,
        "platform": platform,
        "sender": sender,
        "url": url,
        "description": description,
        "anonymous": bool(data.get("anonymous", True)),
    }


def scan_for_credentials(text: str) -> list:
    """Checks whether the text looks like someone pasted their private password or CVV."""
    warnings = []
    # CVV check: e.g. "cvv: 123" or "cvv 456"
    if re.search(r"(?i)\b(?:cvv|cvc)\s*[:=]?\s*\d{3,4}\b", text):
        warnings.append("Payment Card CVV")
    # PIN check: e.g. "atm pin: 1234"
    if re.search(r"(?i)\b(?:atm pin|upi pin|card pin)\s*[:=]?\s*\d{4,6}\b", text):
        warnings.append("ATM/UPI PIN")
    return warnings
