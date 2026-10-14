"""Evaluate the existing deterministic QR review rules on synthetic examples."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import app1


DATASET_PATH = Path(__file__).with_name("evaluation_dataset.json")
EXPECTED_CATEGORIES = {"normal-looking", "malformed", "suspicious-indicator"}


def predicted_category(findings: list[dict[str, Any]]) -> str:
    categories = {finding.get("category") for finding in findings}
    has_format = "format" in categories
    has_indicator = "indicator" in categories
    if has_format and has_indicator:
        return "mixed-signals"
    if has_format:
        return "malformed"
    if has_indicator:
        return "suspicious-indicator"
    return "normal-looking"


def evaluate_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Run parser/engine cases and compare scenario labels with observed findings."""
    results = []
    confusion = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    scenario_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case in cases:
        expected = case.get("expected_category")
        review_expected = case.get("expected_review_signal")
        if expected not in EXPECTED_CATEGORIES:
            raise ValueError(f"Unsupported expected category in case {case.get('id')!r}.")
        if not isinstance(review_expected, bool):
            raise ValueError(f"Case {case.get('id')!r} needs a boolean expected_review_signal label.")
        payload = app1.parse_upi_payload(case["payload"])
        report = app1.run_risk_engine(payload)
        actual_findings = report["findings"]
        predicted = predicted_category(actual_findings)
        predicted_review = predicted in {"malformed", "suspicious-indicator", "mixed-signals"}
        correct = expected == predicted

        if review_expected and predicted_review:
            confusion["true_positive"] += 1
        elif not review_expected and not predicted_review:
            confusion["true_negative"] += 1
        elif predicted_review:
            confusion["false_positive"] += 1
        else:
            confusion["false_negative"] += 1

        result = {
            "id": case["id"],
            "scenario": case["scenario"],
            "expected_category": expected,
            "predicted_category": predicted,
            "verdict": report["verdict"],
            "trust_score": report["trust_score"],
            "correct": correct,
            "expected_review_signal": review_expected,
            "predicted_review_signal": predicted_review,
            "finding_rules": [finding["rule"] for finding in actual_findings],
        }
        results.append(result)
        scenario_groups[case["scenario"]].append(result)

    groups = {
        scenario: {
            "total": len(group),
            "correct": sum(case["correct"] for case in group),
            "incorrect": sum(not case["correct"] for case in group),
            "case_ids": [case["id"] for case in group],
        }
        for scenario, group in sorted(scenario_groups.items())
    }
    return {
        "total_cases": len(results),
        "correct": sum(result["correct"] for result in results),
        "incorrect": sum(not result["correct"] for result in results),
        "review_signal_counts": confusion,
        "scenario_groups": groups,
        "case_results": results,
    }


def load_dataset(dataset_path: str | Path = DATASET_PATH) -> dict[str, Any]:
    with Path(dataset_path).open("r", encoding="utf-8") as source:
        dataset = json.load(source)
    if not isinstance(dataset, dict) or dataset.get("synthetic_only") is not True:
        raise ValueError("Evaluation dataset must explicitly declare synthetic_only=true.")
    if not isinstance(dataset.get("cases"), list):
        raise ValueError("Evaluation dataset must contain a cases list.")
    return dataset


def format_summary(result: dict[str, Any], dataset_name: str) -> str:
    counts = result["review_signal_counts"]
    lines = [
        f"Evaluation: {dataset_name}",
        "Synthetic scenario checks only; results are not real-world accuracy or fraud labels.",
        f"Total test cases: {result['total_cases']}",
        f"Correct category classifications: {result['correct']}",
        f"Incorrect category classifications: {result['incorrect']}",
        "",
        "Expected versus predicted categories:",
    ]
    for case in result["case_results"]:
        state = "CORRECT" if case["correct"] else "INCORRECT"
        lines.append(
            f"- {case['id']} [{case['scenario']}]: expected {case['expected_category']}; "
            f"predicted {case['predicted_category']}; verdict {case['verdict']}; {state}"
        )
    lines.extend([
        "",
        "Review-signal counts (not fraud detection metrics):",
        f"- True positive: {counts['true_positive']}",
        f"- True negative: {counts['true_negative']}",
        f"- False positive: {counts['false_positive']}",
        f"- False negative: {counts['false_negative']}",
        "",
        "Results grouped by scenario:",
    ])
    for scenario, stats in result["scenario_groups"].items():
        lines.append(
            f"- {scenario}: {stats['correct']}/{stats['total']} correct, "
            f"{stats['incorrect']} incorrect"
        )
    lines.extend([
        "",
        "A review signal means this engine emitted a format or wording indicator. "
        "It does not establish that a transaction or recipient is fraudulent.",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH, help="Synthetic JSON evaluation dataset")
    args = parser.parse_args(argv)
    dataset = load_dataset(args.dataset)
    result = evaluate_cases(dataset["cases"])
    print(format_summary(result, dataset.get("dataset_name", "Synthetic evaluation")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
