"""
ScamShield - REST API Test Suite
Validates status codes, payload structures, endpoints, and error handling.
"""

import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestAPIEndpoints:
    """Integration tests for Flask REST endpoints."""

    def test_health_endpoint(self, client):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert "service" in data

    def test_analyze_endpoint_success(self, client):
        payload = {
            "message": "Congratulations! You have won ?50,000 cash prize. Click http://bit.ly/win to claim."
        }
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "confidence" in data
        assert "indicators" in data
        assert "explanation" in data
        assert "recommendations" in data
        assert "disclaimer" in data
        assert 0 <= data["risk_score"] <= 100

    def test_analyze_endpoint_empty_input(self, client):
        res = client.post("/api/analyze", json={"message": ""})
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "error" in data

    def test_analyze_endpoint_too_short(self, client):
        res = client.post("/api/analyze", json={"message": "Hi"})
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False

    def test_statistics_endpoint(self, client):
        res = client.get("/api/statistics")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "total_reports" in data
        assert "top_category" in data
        assert "categories_breakdown" in data

    def test_submit_report_endpoint_success(self, client):
        report_data = {
            "message": "Part time work from home scam offering 10000 daily with joining fee.",
            "category": "Fake Job",
            "platform": "Telegram",
            "sender": "@job_recruiter_fake",
            "url": "https://fakejob-offer.xyz",
            "description": "Asked for Rs 500 security deposit",
            "anonymous": True
        }
        res = client.post("/api/reports", json=report_data)
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "report_id" in data
