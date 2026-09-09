"""
ScamShield - Community Scam Reports Route
POST /api/reports
GET /api/reports
"""

import logging
from flask import Blueprint, request
from ..database.firebase import db_manager
from ..utils.validators import validate_report_request, ValidationError
from ..utils.helpers import success_response, error_response

logger = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports", methods=["POST"])
def submit_report():
    """Submit a community scam report for awareness logging."""
    data = request.get_json(silent=True)
    if data is None:
        return error_response("Invalid JSON payload.", 400)

    try:
        validated_data = validate_report_request(data)
    except ValidationError as ve:
        return error_response(ve.message, ve.status_code)
    except Exception as e:
        logger.error(f"Report validation error: {e}")
        return error_response("Invalid report details.", 400)

    try:
        save_result = db_manager.save_report(validated_data)
        return success_response(
            {"report_id": save_result.get("id"), "storage": save_result.get("backend")},
            message="Report submitted successfully.",
            status_code=201,
        )
    except Exception as e:
        logger.error(f"Report storage failure: {e}", exc_info=True)
        return error_response("We couldn't submit the report right now. Please try again later.", 500)


@reports_bp.route("/reports", methods=["GET"])
def list_reports():
    """List sanitized recent reports for community awareness."""
    try:
        limit = int(request.args.get("limit", 20))
        reports = db_manager.get_reports(limit=limit)
        return success_response({"reports": reports}, message="Reports retrieved.")
    except Exception as e:
        logger.error(f"Failed to fetch reports: {e}")
        return error_response("Could not retrieve reports at this time.", 500)
