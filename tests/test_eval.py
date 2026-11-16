"""Tests for the evaluation harness."""

import json

import pytest

from src.eval.evaluator import EvalReport, _compute_metrics, evaluate, save_report
from tests.fake_llm import FakeLLM


@pytest.fixture
def fake_llm():
    return FakeLLM()


@pytest.fixture
def mini_golden_set(tmp_path):
    """Create a small golden set for testing."""
    alerts = [
        {
            "alert_id": "ALERT-T001",
            "rule_name": "Mimikatz Credential Dumping",
            "sigma_level": "critical",
            "description": "Detects mimikatz credential dumping",
            "matched_event": {
                "Image": "C:\\tools\\mimikatz.exe",
                "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
                "User": "SYSTEM",
                "EventID": 1,
            },
            "techniques": ["T1003.001"],
            "ground_truth": {"label": "malicious", "severity": "critical"},
        },
        {
            "alert_id": "ALERT-T002",
            "rule_name": "Suspicious PowerShell Execution",
            "sigma_level": "high",
            "description": "PowerShell with encoded command",
            "matched_event": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell -enc SGVsbG8gV29ybGQ=",
                "User": "admin",
                "EventID": 1,
            },
            "techniques": ["T1059.001"],
            "ground_truth": {"label": "malicious", "severity": "high"},
        },
        {
            "alert_id": "ALERT-T003",
            "rule_name": "WFP Bind Allowed",
            "sigma_level": "low",
            "description": "Windows Filtering Platform bind",
            "matched_event": {
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "EventID": 5158,
                "Application": "\\device\\windowsazure\\guestagent.exe",
                "User": "LOCAL SERVICE",
            },
            "techniques": [],
            "ground_truth": {"label": "benign", "severity": None},
        },
        {
            "alert_id": "ALERT-T004",
            "rule_name": "Explorer Normal Operation",
            "sigma_level": "low",
            "description": "Normal explorer.exe activity",
            "matched_event": {
                "Image": "C:\\Windows\\explorer.exe",
                "EventID": 1,
                "User": "user_abc",
            },
            "techniques": [],
            "ground_truth": {"label": "benign", "severity": None},
        },
    ]
    path = tmp_path / "test_golden.json"
    with open(path, "w") as f:
        json.dump(alerts, f)
    return path


class TestComputeMetrics:
    def test_perfect_scores(self):
        report = EvalReport()
        report.total = 4
        report.label_correct = 4
        report.true_positives = 2
        report.true_negatives = 2
        report.false_positives = 0
        report.false_negatives = 0
        report.severity_total = 2
        report.severity_correct = 2
        _compute_metrics(report)
        assert report.label_accuracy == 1.0
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.f1 == 1.0
        assert report.false_alarm_rate == 0.0
        assert report.severity_accuracy == 1.0

    def test_all_wrong(self):
        report = EvalReport()
        report.total = 4
        report.label_correct = 0
        report.true_positives = 0
        report.true_negatives = 0
        report.false_positives = 2
        report.false_negatives = 2
        _compute_metrics(report)
        assert report.label_accuracy == 0.0
        assert report.precision == 0.0
        assert report.recall == 0.0

    def test_empty(self):
        report = EvalReport()
        _compute_metrics(report)
        assert report.label_accuracy == 0.0

    def test_partial(self):
        report = EvalReport()
        report.total = 4
        report.label_correct = 3
        report.true_positives = 1
        report.true_negatives = 2
        report.false_positives = 0
        report.false_negatives = 1
        _compute_metrics(report)
        assert report.label_accuracy == 0.75
        assert report.precision == 1.0
        assert report.recall == 0.5
        assert report.false_alarm_rate == 0.0


class TestEvaluate:
    def test_runs_on_golden_set(self, mini_golden_set, fake_llm):
        report = evaluate(mini_golden_set, llm=fake_llm, verbose=False)
        assert report.total == 4
        assert len(report.results) == 4
        assert len(report.errors) == 0

    def test_max_alerts(self, mini_golden_set, fake_llm):
        report = evaluate(mini_golden_set, llm=fake_llm, max_alerts=2, verbose=False)
        assert report.total == 2

    def test_metrics_computed(self, mini_golden_set, fake_llm):
        report = evaluate(mini_golden_set, llm=fake_llm, verbose=False)
        # Metrics should be populated
        assert 0.0 <= report.label_accuracy <= 1.0
        assert 0.0 <= report.precision <= 1.0
        assert 0.0 <= report.recall <= 1.0

    def test_latency_tracked(self, mini_golden_set, fake_llm):
        report = evaluate(mini_golden_set, llm=fake_llm, verbose=False)
        assert report.avg_latency_ms >= 0
        for r in report.results:
            assert r.latency_ms >= 0


class TestSaveReport:
    def test_saves_json(self, mini_golden_set, fake_llm, tmp_path):
        report = evaluate(mini_golden_set, llm=fake_llm, verbose=False)
        out = tmp_path / "report.json"
        save_report(report, out)
        assert out.exists()
        with open(out) as f:
            data = json.load(f)
        assert "label_accuracy" in data
        assert "per_alert" in data
        assert len(data["per_alert"]) == 4


class TestReportToDict:
    def test_serialises(self):
        report = EvalReport()
        report.total = 10
        report.label_correct = 8
        report.true_positives = 3
        report.true_negatives = 5
        report.false_positives = 1
        report.false_negatives = 1
        report.severity_total = 3
        report.severity_correct = 2
        _compute_metrics(report)
        d = report.to_dict()
        assert d["total"] == 10
        assert "confusion_matrix" in d
        assert d["confusion_matrix"]["true_positives"] == 3
