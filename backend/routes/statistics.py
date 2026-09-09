"""
ScamShield - Threat Intelligence Statistics & Health Route
GET /api/statistics
GET /api/health
"""

import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify
from ..database.firebase import db_manager
from ..utils.helpers import success_response, error_response

logger = logging.getLogger(__name__)
statistics_bp = Blueprint("statistics", __name__)


@statistics_bp.route("/statistics", methods=["GET"])
def get_stats():
    """Retrieve aggregated awareness statistics."""
    try:
        stats = db_manager.get_statistics()
        return success_response(stats, message="Statistics retrieved successfully.")
    except Exception as e:
        logger.error(f"Error compiling statistics: {e}", exc_info=True)
        return error_response("Unable to load statistics at this time.", 500)


@statistics_bp.route("/health", methods=["GET"])
def health_check():
    """Service health monitoring endpoint."""
    return jsonify({
        "status": "ok",
        "service": "ScamShield API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }), 200
