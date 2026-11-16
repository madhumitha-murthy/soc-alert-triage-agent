"""CLI entry point: run evaluation against the golden set."""

import argparse
from pathlib import Path

from src.eval.evaluator import evaluate, print_report, save_report


def main():
    parser = argparse.ArgumentParser(description="Evaluate SOC triage agent")
    parser.add_argument(
        "--split",
        choices=["dev", "test", "full"],
        default="dev",
        help="Which golden set split to evaluate on (default: dev)",
    )
    parser.add_argument(
        "--max-alerts",
        type=int,
        default=None,
        help="Limit number of alerts (for quick runs)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save JSON report",
    )
    args = parser.parse_args()

    golden_dir = Path("data/golden_set")
    split_map = {
        "dev": golden_dir / "dev_set.json",
        "test": golden_dir / "test_set.json",
        "full": golden_dir / "golden_set.json",
    }
    golden_path = split_map[args.split]

    if not golden_path.exists():
        print(f"Golden set not found at {golden_path}. Run 'make golden-set' first.")
        return

    print(f"Evaluating on {args.split} split: {golden_path}")
    report = evaluate(golden_path, max_alerts=args.max_alerts)
    print_report(report)

    output_path = args.output or f"results/eval_{args.split}.json"
    save_report(report, output_path)


if __name__ == "__main__":
    main()
