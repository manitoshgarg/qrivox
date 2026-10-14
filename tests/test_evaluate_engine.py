"""Tests for the synthetic detection-engine evaluation utility."""

import pytest

import evaluate_engine


def test_dataset_is_documented_synthetic_and_all_cases_are_classified():
    dataset = evaluate_engine.load_dataset()
    result = evaluate_engine.evaluate_cases(dataset["cases"])

    assert dataset["synthetic_only"] is True
    assert "not verified fraud" in dataset["label_scope"]
    assert result["total_cases"] == 7
    assert result["correct"] == 7
    assert result["incorrect"] == 0
    assert all(case["correct"] for case in result["case_results"])


def test_review_signal_false_positive_and_false_negative_counts_are_scenario_based():
    dataset = evaluate_engine.load_dataset()
    result = evaluate_engine.evaluate_cases(dataset["cases"])
    counts = result["review_signal_counts"]

    assert counts == {
        "true_positive": 5,
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
    }
    assert result["scenario_groups"]["malformed payload"] == {
        "total": 2,
        "correct": 2,
        "incorrect": 0,
        "case_ids": ["malformed-uri-authority", "malformed-amount"],
    }


def test_summary_is_clear_that_counts_are_not_fraud_accuracy():
    dataset = evaluate_engine.load_dataset()
    summary = evaluate_engine.format_summary(
        evaluate_engine.evaluate_cases(dataset["cases"]), dataset["dataset_name"]
    )

    assert "Expected versus predicted categories" in summary
    assert "Results grouped by scenario" in summary
    assert "not real-world accuracy or fraud labels" in summary
    assert "not fraud detection metrics" in summary


def test_evaluation_rejects_missing_scenario_labels_and_cli_prints_results(capsys):
    with pytest.raises(ValueError, match="Unsupported expected category"):
        evaluate_engine.evaluate_cases([{
            "id": "invalid", "scenario": "invalid", "payload": "upi://pay",
            "expected_category": "confirmed-fraud", "expected_review_signal": True,
        }])

    assert evaluate_engine.main([]) == 0
    assert "Total test cases: 7" in capsys.readouterr().out
