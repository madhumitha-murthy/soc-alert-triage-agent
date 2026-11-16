"""Tests for the FastAPI endpoints."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.agents.schemas import TriageDecision
from src.api.app import app


@pytest.fixture
def client():
    # Tests run without TRIAGE_API_KEY set — auth is skipped (dev mode)
    os.environ.pop("TRIAGE_API_KEY", None)
    return TestClient(app)


@pytest.fixture
def authed_client():
    """Client with API key auth enforced."""
    os.environ["TRIAGE_API_KEY"] = "test-secret-key"
    c = TestClient(app)
    yield c
    os.environ.pop("TRIAGE_API_KEY", None)


@pytest.fixture
def sample_alert():
    return {
        "alert_id": "ALERT-API-001",
        "rule_name": "Test Sigma Rule",
        "rule_id": "test-123",
        "sigma_level": "high",
        "description": "A test alert",
        "matched_event": {"Image": "test.exe", "EventID": 1},
        "techniques": ["T1059.001"],
    }


def _mock_triage(alert, llm=None):
    """Mock triage function that returns a fixed decision."""
    alert_id = (
        alert.alert_id if hasattr(alert, "alert_id")
        else alert.get("alert_id", "X")
    )
    return TriageDecision(
        alert_id=alert_id,
        label="malicious",
        confidence=0.85,
        severity="high",
        techniques=["T1059.001"],
        reasoning="Mock detection",
        recommended_action="Investigate",
    )


class TestHealthEndpoint:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_no_auth_required(self, authed_client):
        """Health endpoint should work even without API key."""
        r = authed_client.get("/health")
        assert r.status_code == 200


class TestAuth:
    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_rejects_missing_key(self, mock_fn, authed_client, sample_alert):
        r = authed_client.post("/triage", json=sample_alert)
        assert r.status_code == 401

    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_rejects_wrong_key(self, mock_fn, authed_client, sample_alert):
        r = authed_client.post(
            "/triage", json=sample_alert,
            headers={"X-API-Key": "wrong-key"},
        )
        assert r.status_code == 401

    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_accepts_correct_key(self, mock_fn, authed_client, sample_alert):
        r = authed_client.post(
            "/triage", json=sample_alert,
            headers={"X-API-Key": "test-secret-key"},
        )
        assert r.status_code == 200

    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_no_key_configured_allows_all(self, mock_fn, client, sample_alert):
        """When TRIAGE_API_KEY is unset, all requests pass (dev mode)."""
        r = client.post("/triage", json=sample_alert)
        assert r.status_code == 200


class TestTriageEndpoint:
    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_triage_success(self, mock_fn, client, sample_alert):
        r = client.post("/triage", json=sample_alert)
        assert r.status_code == 200
        data = r.json()
        assert data["alert_id"] == "ALERT-API-001"
        assert data["label"] == "malicious"
        assert data["severity"] == "high"
        assert "reasoning" in data
        assert "recommended_action" in data

    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_triage_minimal_alert(self, mock_fn, client):
        r = client.post("/triage", json={
            "alert_id": "A-MIN",
            "rule_name": "Minimal",
        })
        assert r.status_code == 200

    def test_triage_missing_fields(self, client):
        r = client.post("/triage", json={"rule_name": "No ID"})
        assert r.status_code == 422

    def test_triage_empty_body(self, client):
        r = client.post("/triage", json={})
        assert r.status_code == 422

    @patch("src.api.app.triage_alert", side_effect=Exception("LLM failed"))
    def test_triage_error(self, mock_fn, client, sample_alert):
        r = client.post("/triage", json=sample_alert)
        assert r.status_code == 500
        assert "Triage failed" in r.json()["detail"]


class TestBatchEndpoint:
    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_batch_success(self, mock_fn, client, sample_alert):
        r = client.post("/triage/batch", json=[sample_alert, sample_alert])
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 2

    @patch("src.api.app.triage_alert", side_effect=_mock_triage)
    def test_batch_empty(self, mock_fn, client):
        r = client.post("/triage/batch", json=[])
        assert r.status_code == 200
        assert r.json() == []

    def test_batch_too_large(self, client):
        alerts = [
            {"alert_id": f"A-{i}", "rule_name": "R"} for i in range(51)
        ]
        r = client.post("/triage/batch", json=alerts)
        assert r.status_code == 400
        assert "Maximum 50" in r.json()["detail"]
