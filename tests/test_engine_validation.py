"""Small deterministic validation cases for the heuristic review engine.

All example addresses and text are synthetic test data, not real recipients or
claims of verified fraud.
"""

import app1


def analyze(uri: str) -> dict:
    return app1.run_risk_engine(app1.parse_upi_payload(uri))


def assert_score_is_bounded(report: dict) -> None:
    assert 0 <= report["trust_score"] <= 100
    assert "not a calibrated fraud probability" in report["score_note"]


def test_normal_looking_payment_has_no_claim_of_safety() -> None:
    report = analyze("upi://pay?pa=shop%40demo.test&pn=Corner%20Store&cu=INR")

    assert_score_is_bounded(report)
    assert report["verdict"] == "NO HIGH-RISK INDICATORS"
    assert report["verdict"] != "SECURE"
    assert report["account_class"]["label"] == "Unverified recipient"


def test_malformed_upi_uri_is_a_format_finding() -> None:
    report = analyze("upi://payment?pa=shop%40demo.test")

    assert_score_is_bounded(report)
    finding = next(f for f in report["findings"] if f["category"] == "format")
    assert finding["rule"] == "Unexpected UPI URI structure"
    assert finding["severity"] == "HIGH"


def test_suspicious_text_is_a_cautious_indicator() -> None:
    report = analyze("upi://pay?pa=recipient%40demo.test&tn=urgent")

    assert_score_is_bounded(report)
    finding = next(f for f in report["findings"] if f["rule"] == "Potentially concerning wording")
    assert finding["category"] == "indicator"
    assert finding["severity"] == "LOW"
    assert finding["impact"] == -8
    assert "does not establish fraud" in finding["reason"]


def test_synthetic_lookalike_style_identifier_is_not_a_known_malicious_match() -> None:
    # Synthetic string only: it does not identify a real payment account.
    report = analyze("upi://pay?pa=paytrn-demo%40example.test")

    assert_score_is_bounded(report)
    assert not any(f["category"] == "known_malicious_match" for f in report["findings"])
    assert any(f["rule"] == "No malicious-account lookup" for f in report["info"])
    assert report["trust_score"] == 100


def test_fixed_amount_is_informational_and_does_not_reduce_score() -> None:
    baseline = analyze("upi://pay?pa=shop%40demo.test")
    fixed_amount = analyze("upi://pay?pa=shop%40demo.test&am=250.00")

    assert_score_is_bounded(baseline)
    assert_score_is_bounded(fixed_amount)
    finding = next(f for f in fixed_amount["findings"] if f["rule"] == "Pre-filled amount")
    assert finding["category"] == "observation"
    assert finding["severity"] == "INFO"
    assert finding["impact"] == 0
    assert fixed_amount["trust_score"] == baseline["trust_score"]


def test_missing_optional_fields_do_not_reduce_score() -> None:
    baseline = analyze("upi://pay?pa=shop%40demo.test")
    minimal = app1.parse_upi_payload("upi://pay?pa=shop%40demo.test")
    report = app1.run_risk_engine(minimal)

    assert minimal["amount"] is None
    assert minimal["name"] == ""
    assert minimal["txn_ref"] == ""
    assert_score_is_bounded(report)
    assert report["trust_score"] == baseline["trust_score"]


def test_all_informational_findings_have_zero_score_impact() -> None:
    reports = [
        analyze("upi://pay?pa=shop%40demo.test&am=250"),
        analyze("upi://pay?pa=recipient%40demo.test&sign=present"),
        analyze("upi://payment?pa=shop%40demo.test"),
    ]

    for report in reports:
        assert_score_is_bounded(report)
        assert report["info"]
        assert all(finding["impact"] == 0 for finding in report["info"])
