"""Evaluation harness for the SOC triage agent.

Runs the agent against the golden set, compares predictions to ground truth,
and produces accuracy, precision, recall, F1, severity accuracy, and a full report.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.agents.schemas import TriageDecision
from src.agents.triage_agent import triage_alert


@dataclass
class EvalResult:
    """Result of evaluating a single alert."""

    alert_id: str
    predicted_label: str
    true_label: str
    predicted_severity: str | None
    true_severity: str | None
    label_correct: bool
    severity_correct: bool | None  # None if benign (no severity to check)
    confidence: float
    latency_ms: float
    reasoning: str


@dataclass
class EvalReport:
    """Aggregate evaluation metrics."""

    total: int = 0
    label_correct: int = 0
    label_accuracy: float = 0.0

    # Binary classification metrics (malicious = positive)
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_alarm_rate: float = 0.0

    # Severity (only for correctly-classified malicious alerts)
    severity_total: int = 0
    severity_correct: int = 0
    severity_accuracy: float = 0.0

    # Latency
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0

    # Per-alert results
    results: list[EvalResult] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to dict (excluding per-alert results for summary)."""
        return {
            "total": self.total,
            "label_accuracy": round(self.label_accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_alarm_rate": round(self.false_alarm_rate, 4),
            "severity_accuracy": round(self.severity_accuracy, 4),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "p95_latency_ms": round(self.p95_latency_ms, 1),
            "confusion_matrix": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
            },
            "severity": {
                "total": self.severity_total,
                "correct": self.severity_correct,
                "accuracy": round(self.severity_accuracy, 4),
            },
            "errors": len(self.errors),
        }


def _compute_metrics(report: EvalReport) -> None:
    """Compute aggregate metrics from per-alert results."""
    if report.total == 0:
        return

    report.label_accuracy = report.label_correct / report.total

    # Precision / recall / F1
    tp, fp = report.true_positives, report.false_positives
    fn, tn = report.false_negatives, report.true_negatives

    report.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    report.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if report.precision + report.recall > 0:
        report.f1 = 2 * report.precision * report.recall / (report.precision + report.recall)

    # False alarm rate = FP / (FP + TN)
    report.false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Severity accuracy
    if report.severity_total > 0:
        report.severity_accuracy = report.severity_correct / report.severity_total

    # Latency stats
    latencies = [r.latency_ms for r in report.results]
    if latencies:
        report.avg_latency_ms = sum(latencies) / len(latencies)
        sorted_lat = sorted(latencies)
        p95_idx = int(len(sorted_lat) * 0.95)
        report.p95_latency_ms = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]


def evaluate(
    golden_set_path: str | Path,
    llm=None,
    max_alerts: int | None = None,
    verbose: bool = True,
) -> EvalReport:
    """Run the triage agent against a labeled golden set.

    Args:
        golden_set_path: Path to JSON file with labeled alerts (ground_truth field).
        llm: Optional LLM instance (for testing with a fake model).
        max_alerts: Limit number of alerts to evaluate (for quick runs).
        verbose: Print progress.

    Returns:
        EvalReport with all metrics.
    """
    with open(golden_set_path) as f:
        alerts = json.load(f)

    if max_alerts:
        alerts = alerts[:max_alerts]

    report = EvalReport()
    report.total = len(alerts)

    for i, alert in enumerate(alerts):
        alert_id = alert["alert_id"]
        ground_truth = alert["ground_truth"]
        true_label = ground_truth["label"]
        true_severity = ground_truth.get("severity")

        # Build agent-facing alert (strip ground truth)
        agent_alert = {
            k: v for k, v in alert.items()
            if k not in ("ground_truth", "source_recording")
        }

        try:
            start = time.time()
            decision: TriageDecision = triage_alert(agent_alert, llm=llm)
            latency_ms = (time.time() - start) * 1000

            label_correct = decision.label == true_label

            # Severity check (only for true malicious predicted as malicious)
            severity_correct = None
            if true_label == "malicious" and decision.label == "malicious":
                report.severity_total += 1
                if decision.severity == true_severity:
                    severity_correct = True
                    report.severity_correct += 1
                else:
                    severity_correct = False

            # Confusion matrix
            if decision.label == "malicious" and true_label == "malicious":
                report.true_positives += 1
            elif decision.label == "malicious" and true_label == "benign":
                report.false_positives += 1
            elif decision.label == "benign" and true_label == "benign":
                report.true_negatives += 1
            elif decision.label == "benign" and true_label == "malicious":
                report.false_negatives += 1

            if label_correct:
                report.label_correct += 1

            result = EvalResult(
                alert_id=alert_id,
                predicted_label=decision.label,
                true_label=true_label,
                predicted_severity=decision.severity,
                true_severity=true_severity,
                label_correct=label_correct,
                severity_correct=severity_correct,
                confidence=decision.confidence,
                latency_ms=latency_ms,
                reasoning=decision.reasoning,
            )
            report.results.append(result)

            if verbose:
                status = "OK" if label_correct else "MISS"
                print(f"  [{i+1}/{len(alerts)}] {alert_id}: {status} "
                      f"(pred={decision.label}, true={true_label}, {latency_ms:.0f}ms)")

        except Exception as e:
            report.errors.append({"alert_id": alert_id, "error": str(e)})
            if verbose:
                print(f"  [{i+1}/{len(alerts)}] {alert_id}: ERROR — {e}")

    _compute_metrics(report)
    return report


def print_report(report: EvalReport) -> None:
    """Pretty-print the evaluation report."""
    print("\n" + "=" * 60)
    print("SOC TRIAGE AGENT — EVALUATION REPORT")
    print("=" * 60)
    print(f"Total alerts:        {report.total}")
    print(f"Label accuracy:      {report.label_accuracy:.1%}")
    print(f"Precision:           {report.precision:.1%}")
    print(f"Recall:              {report.recall:.1%}")
    print(f"F1 score:            {report.f1:.3f}")
    print(f"False alarm rate:    {report.false_alarm_rate:.1%}")
    print(f"\nSeverity accuracy:   {report.severity_accuracy:.1%} "
          f"({report.severity_correct}/{report.severity_total})")
    print(f"\nAvg latency:         {report.avg_latency_ms:.0f}ms")
    print(f"P95 latency:         {report.p95_latency_ms:.0f}ms")
    print(f"Errors:              {len(report.errors)}")

    if report.errors:
        print("\nErrors:")
        for err in report.errors[:5]:
            print(f"  {err['alert_id']}: {err['error']}")

    # Confusion matrix
    print("\nConfusion matrix:")
    print("                  Predicted")
    print("                  Malicious  Benign")
    print(f"  Actual Mal      {report.true_positives:>5}      {report.false_negatives:>5}")
    print(f"  Actual Ben      {report.false_positives:>5}      {report.true_negatives:>5}")


def save_report(report: EvalReport, output_path: str | Path) -> None:
    """Save evaluation report to JSON."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = report.to_dict()
    data["per_alert"] = [
        {
            "alert_id": r.alert_id,
            "predicted_label": r.predicted_label,
            "true_label": r.true_label,
            "predicted_severity": r.predicted_severity,
            "true_severity": r.true_severity,
            "label_correct": r.label_correct,
            "severity_correct": r.severity_correct,
            "confidence": r.confidence,
            "latency_ms": round(r.latency_ms, 1),
        }
        for r in report.results
    ]

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\nReport saved to {output_path}")
