"""
ScamShield - Flask Application Factory
Configures application instances, registers blueprints, sets up CORS,
and serves frontend static files.
"""

import os
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from .config import Config, FRONTEND_DIR
from .routes.analyze import analyze_bp
from .routes.reports import reports_bp
from .routes.statistics import statistics_bp


def create_app(config_class=Config):
    """Flask application factory."""
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )
    app.config.from_object(config_class)

    # Enable CORS for API routes
    CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})

    # Register API Blueprints
    app.register_blueprint(analyze_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")
    app.register_blueprint(statistics_bp, url_prefix="/api")

    # Frontend Page Serving Routes
    @app.route("/")
    @app.route("/index.html")
    def serve_home():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/report.html")
    def serve_report():
        return send_from_directory(FRONTEND_DIR, "report.html")

    @app.route("/statistics.html")
    def serve_statistics():
        return send_from_directory(FRONTEND_DIR, "statistics.html")

    @app.route("/about.html")
    def serve_about():
        return send_from_directory(FRONTEND_DIR, "about.html")

    # Static Assets Routing (CSS / JS)
    @app.route("/css/<path:filename>")
    def serve_css(filename):
        return send_from_directory(FRONTEND_DIR / "css", filename)

    @app.route("/js/<path:filename>")
    def serve_js(filename):
        return send_from_directory(FRONTEND_DIR / "js", filename)

    # Global Error Handlers (Friendly, non-leaking)
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            "success": False,
            "error": "The requested resource was not found on this server."
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "success": False,
            "error": "HTTP method not allowed for this endpoint."
        }), 405

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({
            "success": False,
            "error": "An internal server error occurred. Please try again later."
        }), 500

    return app
