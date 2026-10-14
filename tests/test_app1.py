"""Characterization tests for the current UPI parser and heuristic risk engine.

These tests document existing behavior. They do not validate the rules as
scientifically reliable fraud indicators.
"""

import app1


def make_payload(uri: str) -> dict:
    return app1.parse_upi_payload(uri)


def assert_valid_report(report: dict) -> None:
    assert isinstance(report, dict)
    assert 0 <= report["trust_score"] <= 100
    assert report["verdict"] in {
        "NO HIGH-RISK INDICATORS", "REVIEW DETAILS",
        "SUSPICIOUS INDICATORS", "MULTIPLE HIGH-RISK SIGNALS",
    }
    assert isinstance(report["findings"], list)
    for severity in ("critical", "high", "medium", "low"):
        assert isinstance(report[severity], list)
    assert report["account_class"]["label"] == "Unverified recipient"
    assert report["payload"]
    assert "not a calibrated fraud probability" in report["score_note"]


def test_parser_extracts_payment_fields_and_decodes_values() -> None:
    payload = make_payload(
        "upi://pay?pa=shop%40oksbi&pn=Corner%20Store&am=125.50"
        "&cu=INR&tr=ORDER-42"
    )

    assert payload["vpa"] == "shop@oksbi"
    assert payload["name"] == "Corner Store"
    assert payload["amount"] == "125.50"
    assert payload["currency"] == "INR"
    assert payload["txn_ref"] == "ORDER-42"


def test_parser_defaults_missing_optional_fields() -> None:
    payload = make_payload("upi://pay?pa=shop%40oksbi")

    assert payload["vpa"] == "shop@oksbi"
    assert payload["name"] == ""
    assert payload["amount"] is None
    assert payload["currency"] == "INR"
    assert payload["txn_ref"] == ""
    assert payload["txn_note"] == ""


def test_malformed_amount_is_reported_without_crashing() -> None:
    report = app1.run_risk_engine(make_payload("upi://pay?pa=shop%40oksbi&am=abc"))

    assert_valid_report(report)
    finding = next(f for f in report["findings"] if f["rule"] == "Malformed amount field")
    assert finding["category"] == "format"
    assert finding["severity"] == "MEDIUM"
    assert "finite positive number" in finding["reason"]


def test_non_upi_input_is_reported_as_invalid_protocol() -> None:
    report = app1.run_risk_engine(make_payload("https://example.test/pay"))

    assert_valid_report(report)
    assert report["trust_score"] == 35
    assert report["verdict"] == "SUSPICIOUS INDICATORS"
    assert report["high"][0]["category"] == "format"
    assert "does not establish" in report["high"][0]["reason"]
    assert any(f["rule"] == "No malicious-account lookup" for f in report["info"])


def test_uri_that_only_shares_upi_pay_prefix_is_a_format_error() -> None:
    report = app1.run_risk_engine(make_payload("upi://payment?pa=shop%40oksbi"))

    assert any(f["category"] == "format" for f in report["findings"])
    assert report["high"][0]["rule"] == "Unexpected UPI URI structure"


def test_suspicious_indicators_appear_in_findings() -> None:
    payload = make_payload(
        "upi://pay?pa=alice%40oksbi&pn=KYC%20Helpdesk&tn=urgent"
    )
    report = app1.run_risk_engine(payload)

    assert_valid_report(report)
    keyword_finding = next(f for f in report["findings"] if f["rule"] == "Potentially concerning wording")
    assert keyword_finding["category"] == "indicator"
    assert keyword_finding["severity"] == "MEDIUM"
    assert keyword_finding["impact"] == -24
    assert "kyc" in keyword_finding["detail"].lower()
    assert "urgent" in keyword_finding["detail"].lower()


def test_legitimate_looking_prefilled_payment_has_no_amount_penalty() -> None:
    payload = make_payload(
        "upi://pay?pa=shop%40oksbi&pn=Corner%20Store&am=250"
        "&cu=INR&tr=SALE-7&mc=5411&sign=demo-signature"
    )
    report = app1.run_risk_engine(payload)

    assert_valid_report(report)
    assert report["account_class"]["label"] == "Unverified recipient"
    assert report["trust_score"] == 100
    amount_finding = next(f for f in report["findings"] if f["rule"] == "Pre-filled amount")
    assert amount_finding["category"] == "observation"
    assert amount_finding["severity"] == "INFO"
    assert amount_finding["impact"] == 0
    assert "common in legitimate" in amount_finding["reason"]
    assert report["verdict"] == "NO HIGH-RISK INDICATORS"


def test_risk_report_has_expected_structure_and_bounded_score() -> None:
    report = app1.run_risk_engine(make_payload("upi://pay?pa=shop%40oksbi&sign=s"))

    assert_valid_report(report)
    for finding in report["findings"]:
        assert set(finding) == {"rule", "category", "severity", "impact", "reason", "detail"}
        assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert finding["reason"]


def test_signature_mcc_and_familiar_handle_do_not_establish_legitimacy() -> None:
    unsigned = make_payload("upi://pay?pa=alice%40icici&mc=5411")
    signed = make_payload("upi://pay?pa=alice%40icici&mc=5411&sign=present")
    unsigned_report = app1.run_risk_engine(unsigned)
    signed_report = app1.run_risk_engine(signed)

    assert unsigned_report["trust_score"] == signed_report["trust_score"] == 100
    assert unsigned_report["account_class"] == signed_report["account_class"]
    assert all(f["impact"] == 0 for f in unsigned_report["info"])
    identity = next(f for f in unsigned_report["info"] if f["rule"] == "Recipient identity not verified")
    signature = next(f for f in unsigned_report["info"] if f["rule"] == "Signature not validated")
    assert "cannot confirm account ownership" in identity["reason"]
    assert "does not validate a signature" in signature["reason"]


def test_keyword_matching_uses_whole_words_and_does_not_call_it_a_known_match() -> None:
    payload = make_payload("upi://pay?pa=alice%40oksbi&pn=Supportive%20Services")
    report = app1.run_risk_engine(payload)

    assert not any(f["category"] == "indicator" for f in report["findings"])
    assert not any(f["category"] == "known_malicious_match" for f in report["findings"])
    assert any(f["rule"] == "No malicious-account lookup" for f in report["info"])


def test_external_url_in_note_is_only_a_cautious_indicator() -> None:
    report = app1.run_risk_engine(
        make_payload("upi://pay?pa=alice%40oksbi&tn=https%3A%2F%2Fexample.test")
    )
    url_finding = next(
        finding for finding in report["findings"]
        if finding["rule"] == "External URL text in payment metadata"
    )

    assert url_finding["category"] == "indicator"
    assert url_finding["impact"] < 0
    assert "does not establish" in url_finding["reason"]


def test_duplicate_parameters_and_non_finite_amount_are_format_findings() -> None:
    duplicate = make_payload("upi://pay?pa=a%40oksbi&pa=b%40oksbi")
    duplicate_report = app1.run_risk_engine(duplicate)
    assert duplicate["duplicate_params"] == ["pa"]
    assert any(f["rule"] == "Ambiguous duplicate parameters" for f in duplicate_report["findings"])

    for amount in ("NaN", "Infinity", "-1", "0"):
        report = app1.run_risk_engine(make_payload(f"upi://pay?pa=a%40oksbi&am={amount}"))
        assert any(f["rule"] == "Malformed amount field" for f in report["findings"])


def test_mcc_and_missing_optional_fields_add_no_risk_penalty() -> None:
    with_mcc = app1.run_risk_engine(make_payload("upi://pay?pa=shop%40oksbi&mc=5411"))
    without_mcc = app1.run_risk_engine(make_payload("upi://pay?pa=shop%40oksbi"))

    assert with_mcc["trust_score"] == without_mcc["trust_score"] == 100
    assert with_mcc["account_class"]["label"] == without_mcc["account_class"]["label"]


def test_amount_metadata_formatter_handles_large_and_non_finite_values() -> None:
    assert app1._format_report_amount("125.50") == "₹125.50"
    assert app1._format_report_amount("1e999") == "₹1E+999"
    assert app1._format_report_amount("Infinity") == "Invalid amount: Infinity"
