"""Tests for the triage agent using a fake LLM (no API calls)."""

import json

import pytest

from src.agents.schemas import TriageDecision
from src.agents.triage_agent import (
    _build_alert_prompt,
    _parse_decision,
    build_triage_graph,
    triage_alert,
)
from tests.fake_llm import FakeLLM

# --- Fixtures ---

@pytest.fixture
def fake_llm():
    return FakeLLM()


@pytest.fixture
def malicious_alert():
    return {
        "alert_id": "ALERT-0001",
        "rule_name": "Mimikatz Credential Dumping",
        "rule_id": "test-rule-001",
        "sigma_level": "critical",
        "description": "Detects mimikatz credential dumping from LSASS memory",
        "matched_event": {
            "Image": "C:\\tools\\mimikatz.exe",
            "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "User": "SYSTEM",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "EventID": 1,
        },
        "techniques": ["T1003.001"],
    }


@pytest.fixture
def benign_alert():
    return {
        "alert_id": "ALERT-0002",
        "rule_name": "WFP Bind Allowed",
        "rule_id": "test-rule-002",
        "sigma_level": "low",
        "description": "Windows Filtering Platform allowed a bind to a local port",
        "matched_event": {
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "EventID": 5158,
            "Application": "\\device\\harddiskvolume2\\guestagent.exe",
            "User": "LOCAL SERVICE",
        },
        "techniques": [],
    }


# --- Unit tests for _parse_decision ---

class TestParseDecision:
    def test_valid_json(self):
        text = json.dumps({
            "alert_id": "A-001",
            "label": "malicious",
            "confidence": 0.9,
            "severity": "high",
            "techniques": ["T1053"],
            "reasoning": "Scheduled task abuse",
            "recommended_action": "Investigate",
        })
        d = _parse_decision(text, "A-001")
        assert d.label == "malicious"
        assert d.severity == "high"
        assert d.confidence == 0.9

    def test_json_in_markdown_block(self):
        text = (
            '```json\n{"alert_id":"A","label":"benign",'
            '"confidence":0.8,"reasoning":"ok",'
            '"recommended_action":"none"}\n```'
        )
        d = _parse_decision(text, "A")
        assert d.label == "benign"
        assert d.severity is None  # Benign should have null severity

    def test_invalid_json_fallback(self):
        text = "This alert is clearly malicious based on the evidence."
        d = _parse_decision(text, "A-003")
        assert d.label == "malicious"
        assert d.confidence == 0.3  # Low confidence fallback

    def test_benign_fallback(self):
        text = "This looks normal."
        d = _parse_decision(text, "A-004")
        assert d.label == "benign"

    def test_overrides_alert_id(self):
        text = json.dumps({
            "alert_id": "WRONG",
            "label": "benign",
            "confidence": 0.5,
            "reasoning": "x",
            "recommended_action": "y",
        })
        d = _parse_decision(text, "CORRECT")
        assert d.alert_id == "CORRECT"

    def test_normalizes_label(self):
        text = json.dumps({
            "alert_id": "A",
            "label": "MALICIOUS",
            "confidence": 0.7,
            "severity": "high",
            "reasoning": "x",
            "recommended_action": "y",
        })
        d = _parse_decision(text, "A")
        assert d.label == "malicious"

    def test_invalid_label_defaults_benign(self):
        text = json.dumps({
            "alert_id": "A",
            "label": "unknown",
            "confidence": 0.5,
            "reasoning": "x",
            "recommended_action": "y",
        })
        d = _parse_decision(text, "A")
        assert d.label == "benign"

    def test_benign_nullifies_severity(self):
        text = json.dumps({
            "alert_id": "A",
            "label": "benign",
            "confidence": 0.8,
            "severity": "high",  # Should be overridden to None
            "reasoning": "x",
            "recommended_action": "y",
        })
        d = _parse_decision(text, "A")
        assert d.severity is None


# --- Unit tests for _build_alert_prompt ---

class TestBuildAlertPrompt:
    def test_contains_alert_id(self, malicious_alert):
        prompt = _build_alert_prompt(malicious_alert)
        assert "ALERT-0001" in prompt

    def test_contains_rule_name(self, malicious_alert):
        prompt = _build_alert_prompt(malicious_alert)
        assert "Mimikatz" in prompt

    def test_contains_techniques(self, malicious_alert):
        prompt = _build_alert_prompt(malicious_alert)
        assert "T1003.001" in prompt

    def test_contains_event(self, malicious_alert):
        prompt = _build_alert_prompt(malicious_alert)
        assert "mimikatz.exe" in prompt

    def test_truncates_long_events(self):
        alert = {
            "alert_id": "A",
            "rule_name": "R",
            "matched_event": {"data": "x" * 5000},
        }
        prompt = _build_alert_prompt(alert)
        assert "truncated" in prompt


# --- Integration tests with fake LLM ---

class TestTriageAgent:
    def test_triage_returns_decision(self, fake_llm, malicious_alert):
        decision = triage_alert(malicious_alert, llm=fake_llm)
        assert isinstance(decision, TriageDecision)
        assert decision.alert_id == "ALERT-0001"

    def test_malicious_detection(self, fake_llm, malicious_alert):
        decision = triage_alert(malicious_alert, llm=fake_llm)
        assert decision.label == "malicious"
        assert decision.severity is not None
        assert decision.confidence > 0.5

    def test_benign_detection(self, fake_llm, benign_alert):
        decision = triage_alert(benign_alert, llm=fake_llm)
        assert decision.label == "benign"
        assert decision.severity is None

    def test_decision_has_reasoning(self, fake_llm, malicious_alert):
        decision = triage_alert(malicious_alert, llm=fake_llm)
        assert len(decision.reasoning) > 0

    def test_decision_has_action(self, fake_llm, malicious_alert):
        decision = triage_alert(malicious_alert, llm=fake_llm)
        assert len(decision.recommended_action) > 0

    def test_graph_builds(self, fake_llm):
        graph = build_triage_graph(llm=fake_llm)
        assert graph is not None


class TestTriageAgentEdgeCases:
    def test_empty_event(self, fake_llm):
        alert = {
            "alert_id": "ALERT-EMPTY",
            "rule_name": "Test",
            "matched_event": {},
            "techniques": [],
        }
        decision = triage_alert(alert, llm=fake_llm)
        assert isinstance(decision, TriageDecision)

    def test_missing_fields(self, fake_llm):
        alert = {
            "alert_id": "ALERT-MIN",
            "rule_name": "Minimal",
        }
        decision = triage_alert(alert, llm=fake_llm)
        assert decision.alert_id == "ALERT-MIN"

    def test_alert_input_object(self, fake_llm):
        from src.agents.schemas import AlertInput
        alert = AlertInput(
            alert_id="ALERT-OBJ",
            rule_name="Object Test",
            sigma_level="low",
        )
        decision = triage_alert(alert, llm=fake_llm)
        assert decision.alert_id == "ALERT-OBJ"
