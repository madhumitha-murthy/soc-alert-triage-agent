"""Tests for Pydantic schemas."""

import pytest

from src.agents.schemas import AlertInput, TriageDecision


class TestAlertInput:
    def test_minimal(self):
        alert = AlertInput(alert_id="A-001", rule_name="Test Rule")
        assert alert.alert_id == "A-001"
        assert alert.matched_event == {}
        assert alert.techniques == []

    def test_full(self):
        alert = AlertInput(
            alert_id="A-002",
            rule_name="Mimikatz",
            rule_id="abc-123",
            sigma_level="critical",
            description="Detects mimikatz",
            matched_event={"Image": "mimikatz.exe"},
            techniques=["T1003.001"],
        )
        assert alert.sigma_level == "critical"
        assert alert.techniques == ["T1003.001"]

    def test_defaults(self):
        alert = AlertInput(alert_id="A-003", rule_name="R")
        assert alert.sigma_level == "medium"
        assert alert.description == ""


class TestTriageDecision:
    def test_malicious(self):
        d = TriageDecision(
            alert_id="A-001",
            label="malicious",
            confidence=0.9,
            severity="high",
            techniques=["T1053.005"],
            reasoning="Scheduled task creation",
            recommended_action="Investigate",
        )
        assert d.label == "malicious"
        assert d.severity == "high"

    def test_benign(self):
        d = TriageDecision(
            alert_id="A-002",
            label="benign",
            confidence=0.8,
            severity=None,
            reasoning="Normal activity",
            recommended_action="No action",
        )
        assert d.severity is None

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            TriageDecision(
                alert_id="A-003",
                label="benign",
                confidence=1.5,
                reasoning="x",
                recommended_action="y",
            )

    def test_confidence_zero(self):
        d = TriageDecision(
            alert_id="A-004",
            label="benign",
            confidence=0.0,
            reasoning="Unknown",
            recommended_action="Review",
        )
        assert d.confidence == 0.0
