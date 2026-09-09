"""
ScamShield - Response Formatting & Utility Helpers
"""

from flask import jsonify


def success_response(data: dict = None, message: str = "Success", status_code: int = 200):
    """Standardized API success envelope."""
    payload = {"success": True, "message": message}
    if data is not None:
        payload.update(data)
    return jsonify(payload), status_code


def error_response(message: str, status_code: int = 400, details: dict = None):
    """Standardized API error envelope."""
    payload = {"success": False, "error": message}
    if details:
        payload["details"] = details
    return jsonify(payload), status_code
