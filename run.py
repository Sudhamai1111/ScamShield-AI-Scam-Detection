"""
ScamShield - Application Entry Point
Starts the Flask server to host both the API and the cybersecurity frontend.
"""

import os
import sys
from pathlib import Path

# Ensure root directory is always on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.app import create_app
from backend.config import Config

app = create_app()

if __name__ == "__main__":
    host = Config.HOST
    port = Config.PORT
    debug = Config.DEBUG

    print("=" * 65)
    print(" ???  ScamShield - AI-Based Scam Detection and Awareness System")
    print("=" * 65)
    print(f" * Server running on: http://{host}:{port}")
    print(f" * API Health Check:  http://{host}:{port}/api/health")
    print(f" * Interactive UI:   http://{host}:{port}/")
    print("=" * 65)

    app.run(host=host, port=port, debug=debug)
