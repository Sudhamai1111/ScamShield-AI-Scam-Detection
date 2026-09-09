"""
ScamShield - Message Analysis Route
POST /api/analyze
"""

import logging
from flask import Blueprint, request
from ..detector.scam_detector import ScamDetector
from ..utils.validators import validate_analyze_request, ValidationError
from ..utils.helpers import error_response

logger = logging.getLogger(__name__)
analyze_bp = Blueprint("analyze", __name__)
detector = ScamDetector()


@analyze_bp.route("/analyze", methods=["POST"])
def analyze_message():
    """Analyze a submitted text message for potential scam indicators."""
    data = request.get_json(silent=True)
    if data is None:
        return error_response("Invalid JSON payload or Content-Type header missing.", 400)

    try:
        clean_message = validate_analyze_request(data)
    except ValidationError as ve:
        return error_response(ve.message, ve.status_code)
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return error_response("Unable to validate message input.", 400)

    try:
        result = detector.analyze_message(clean_message)
        return result, 200
    except Exception as e:
        logger.error(f"Analysis engine error: {e}", exc_info=True)
        return error_response("Something went wrong while analyzing the message. Please try again.", 500)
