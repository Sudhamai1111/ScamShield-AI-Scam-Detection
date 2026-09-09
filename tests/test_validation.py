"""
ScamShield - Validation & Sanitization Tests
Tests input boundaries, credential scrubbing, and payload defense.
"""

import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.utils.validators import (
    validate_analyze_request,
    validate_report_request,
    scan_for_credentials,
    ValidationError,
)


class TestValidation:
    """Unit tests for input filters and security rules."""

    def test_valid_analyze_message(self):
        msg = "This is a legitimate or suspicious text that is definitely longer than ten characters."
        result = validate_analyze_request({"message": msg})
        assert result == msg

    def test_missing_message_key(self):
        with pytest.raises(ValidationError) as exc:
            validate_analyze_request({"not_message": "Hello world!"})
        assert "Please enter a message" in str(exc.value)

    def test_exceeding_max_length(self):
        long_text = "a" * 5005
        with pytest.raises(ValidationError) as exc:
            validate_analyze_request({"message": long_text})
        assert "too long" in str(exc.value)

    def test_credential_leak_detection_cvv(self):
        leak_text = "Here is the scam message, and my CVV: 891"
        warnings = scan_for_credentials(leak_text)
        assert "Payment Card CVV" in warnings

    def test_credential_leak_detection_pin(self):
        leak_text = "My ATM PIN: 4812 was typed here"
        warnings = scan_for_credentials(leak_text)
        assert "ATM/UPI PIN" in warnings

    def test_report_rejects_sensitive_credentials(self):
        payload = {
            "message": "Scam message asking for card details",
            "description": "I accidentally entered my ATM PIN: 9912",
            "category": "Banking",
            "platform": "SMS"
        }
        with pytest.raises(ValidationError) as exc:
            validate_report_request(payload)
        assert "Sensitive credentials detected" in str(exc.value)
