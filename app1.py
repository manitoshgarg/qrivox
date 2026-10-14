import streamlit as st
import html
import re
import json
import hashlib
import datetime
import logging
import sqlite3
import importlib
from pathlib import Path
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse, parse_qs, unquote
from PIL import Image, UnidentifiedImageError
from pyzbar.pyzbar import decode
import storage
import investigation_ui


logger = logging.getLogger(__name__)
LOGO_PATH = Path(__file__).resolve().parent / "assets" / "qrivox_logo.png"

# ============================================================
# MODULE 1: FORENSIC QR PARSER
# ============================================================

def parse_upi_payload(raw: str) -> dict:
    """Deep-parse a UPI string into structured components."""
    raw = raw.strip()
    decoded = unquote(raw)                 # Handle %XX-encoded characters
    parsed = urlparse(decoded)
    params_raw = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: v[0] for k, v in params_raw.items()}

    return {
        "raw": raw,
        "decoded": decoded,
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "params": params,
        "duplicate_params": [k for k, values in params_raw.items() if len(values) > 1],
        "vpa": params.get("pa", ""),
        "name": params.get("pn", ""),
        "amount": params.get("am", None),
        "currency": params.get("cu", "INR"),
        "txn_ref": params.get("tr", ""),
        "txn_note": params.get("tn", ""),
        "mc": params.get("mc", ""),
        "mode": params.get("mode", ""),
        "sign": params.get("sign", ""),
        "qr_hash": hashlib.sha256(raw.encode()).hexdigest()[:12].upper(),
        "scan_time": datetime.datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }


# ============================================================
# MODULE 2: EXPLAINABLE RULE-BASED REVIEW ENGINE
# ============================================================

SUSPICIOUS_KEYWORDS = (
    "aadhaar", "block", "expire", "helpdesk", "immediate", "kyc",
    "lottery", "otp", "pan", "suspend", "urgent", "verify", "winner",
)

def classify_account(payload: dict) -> dict:
    """Describe the app's verification limit; QR fields do not prove identity."""
    return {"label": "Unverified recipient", "color": "gray", "icon": "❔"}


def _finding(rule: str, category: str, severity: str, impact: int, reason: str) -> dict:
    return {
        "rule": rule,
        "category": category,
        "severity": severity,
        "impact": impact,
        "reason": reason,
        # Kept for compatibility with the existing report renderer and callers.
        "detail": reason,
    }


def _verification_findings() -> list:
    return [
        _finding(
            "Recipient identity not verified", "cannot_verify", "INFO", 0,
            "The payee address, familiar handle, and MCC are QR-provided text. "
            "This app cannot confirm account ownership or merchant registration.",
        ),
        _finding(
            "Signature not validated", "cannot_verify", "INFO", 0,
            "A signature field may be present or absent, but this app does not validate a signature. "
            "Neither state proves that the QR is authentic or tampered with.",
        ),
        _finding(
            "No malicious-account lookup", "cannot_verify", "INFO", 0,
            "This app has no sourced malicious-account database, so it cannot report a known-malicious match.",
        ),
    ]


def run_risk_engine(payload: dict) -> dict:
    """
    Deterministic heuristic score and explanations; this is not a probability
    of fraud and does not verify the payment recipient.
    """
    findings = []
    # Format errors describe URI structure; they do not by themselves prove fraud.
    if payload["scheme"].lower() != "upi" or payload["netloc"].lower() != "pay":
        findings.append(_finding(
            "Unexpected UPI URI structure", "format", "HIGH", -65,
            "Expected a UPI payment URI with scheme 'upi' and authority 'pay'. "
            "This format mismatch does not establish who created the QR or whether it is malicious.",
        ))
        findings.extend(_verification_findings())
        return _build_report(findings, payload, account_class=classify_account(payload))

    if not payload["vpa"].strip() or "@" not in payload["vpa"]:
        findings.append(_finding(
            "Missing or incomplete payee address", "format", "HIGH", -45,
            "The 'pa' field is missing or does not contain a UPI address separator (@). "
            "The intended recipient cannot be determined from this payload.",
        ))

    duplicates = payload.get("duplicate_params", [])
    if duplicates:
        findings.append(_finding(
            "Ambiguous duplicate parameters", "format", "MEDIUM", -25,
            f"The following query parameter(s) occur more than once: {duplicates}. "
            "Different payment apps may interpret duplicate values differently.",
        ))

    amount = payload.get("amount")
    if amount is not None:
        try:
            numeric_amount = Decimal(amount)
            if not numeric_amount.is_finite() or numeric_amount <= 0:
                raise InvalidOperation
        except (InvalidOperation, TypeError, ValueError):
            findings.append(_finding(
                "Malformed amount field", "format", "MEDIUM", -25,
                f"The amount value {amount!r} is not a finite positive number. "
                "Check the amount in your payment app before authorizing anything.",
            ))
        else:
            findings.append(_finding(
                "Pre-filled amount", "observation", "INFO", 0,
                f"The QR contains a pre-filled amount ({numeric_amount}). "
                "Fixed amounts are common in legitimate payment QRs and are not treated as a fraud signal.",
            ))

    # Exact whole-word matches are weak language indicators, not malicious-account matches.
    text = " ".join((payload.get("name", ""), payload.get("txn_note", ""), payload.get("vpa", ""))).lower()
    keyword_hits = [word for word in SUSPICIOUS_KEYWORDS if re.search(rf"(?<!\w){re.escape(word)}(?!\w)", text)]
    if keyword_hits:
        deduction = min(24, len(keyword_hits) * 8)
        findings.append(_finding(
            "Potentially concerning wording", "indicator", "LOW" if len(keyword_hits) == 1 else "MEDIUM",
            -deduction,
            f"The payee name, note, or address contains these exact word(s): {keyword_hits}. "
            "Such wording can also appear in legitimate payments and does not establish fraud.",
        ))

    if re.search(r"https?://", text):
        findings.append(_finding(
            "External URL text in payment metadata", "indicator", "MEDIUM", -20,
            "A payee name, note, or address contains an HTTP/HTTPS URL. "
            "This is a review signal only; it does not establish that the payment URI redirects or that the URL is malicious.",
        ))

    findings.extend(_verification_findings())
    return _build_report(findings, payload, account_class=classify_account(payload))


def _build_report(findings: list, payload: dict, account_class: dict) -> dict:
    total_deduction = sum(max(0, -f["impact"]) for f in findings)
    trust_score = max(0, min(100, 100 - total_deduction))

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high     = [f for f in findings if f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["severity"] == "MEDIUM"]
    low      = [f for f in findings if f["severity"] == "LOW"]

    if trust_score >= 85:
        verdict = ("NO HIGH-RISK INDICATORS", "#2563eb", "blue")
    elif trust_score >= 60:
        verdict = ("REVIEW DETAILS", "#f59e0b", "orange")
    elif trust_score >= 35:
        verdict = ("SUSPICIOUS INDICATORS", "#ef4444", "red")
    else:
        verdict = ("MULTIPLE HIGH-RISK SIGNALS", "#7f1d1d", "red")

    return {
        "trust_score": trust_score,
        "verdict": verdict[0],
        "verdict_color": verdict[1],
        "verdict_st_color": verdict[2],
        "findings": findings,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": [f for f in findings if f["severity"] == "INFO"],
        "account_class": account_class,
        "payload": payload,
        "score_note": "Deterministic rule-based score; not a calibrated fraud probability or identity verification.",
    }


# ============================================================
# MODULE 3: REPORT RENDERER
# ============================================================

SEVERITY_COLORS = {
    "CRITICAL": ("", "#fee2e2", "#991b1b"),
    "HIGH":     ("", "#ffedd5", "#9a3412"),
    "MEDIUM":   ("", "#fefce8", "#854d0e"),
    "LOW":      ("", "#eff6ff", "#1e40af"),
    "INFO":     ("", "#f3f4f6", "#374151"),
}


def _finding_next_step(finding: dict) -> str:
    """Return a cautious, rule-specific action without implying a verified threat."""
    recommendations = {
        "Unexpected UPI URI structure": (
            "Do not authorize from this payload alone. Check the recipient and amount shown in your official payment app."
        ),
        "Missing or incomplete payee address": (
            "Do not authorize until your official payment app shows the intended recipient and you can verify it."
        ),
        "Ambiguous duplicate parameters": (
            "Check the final recipient and amount shown by your official payment app; stop if either is unclear."
        ),
        "Malformed amount field": (
            "Confirm or enter the intended amount directly in your official payment app before authorizing."
        ),
        "Pre-filled amount": (
            "Compare the displayed amount with what you intend to pay in your official payment app."
        ),
        "Potentially concerning wording": (
            "Verify the payment request through a trusted, separate channel before proceeding."
        ),
        "External URL text in payment metadata": (
            "Do not use a URL in the QR metadata as proof of legitimacy; verify the recipient independently."
        ),
        "Recipient identity not verified": (
            "Confirm the recipient name and identifier in your official payment app before authorizing."
        ),
        "Signature not validated": (
            "Do not treat a present or absent signature field as authentication; verify the QR source independently."
        ),
        "No malicious-account lookup": (
            "This app cannot check accounts against a sourced threat database; verify the recipient independently."
        ),
    }
    return recommendations.get(
        finding.get("rule"),
        "Review this detail and verify the recipient and amount in your official payment app before authorizing.",
    )


def _why_this_result(report: dict) -> str:
    """Summarize the largest listed score impacts without overstating their meaning."""
    deductions = sorted(
        (finding for finding in report["findings"] if finding.get("impact", 0) < 0),
        key=lambda finding: finding["impact"],
    )
    if not deductions:
        return (
            "No finding reduced this rule-based score. Informational observations have zero score impact; "
            "this does not verify the recipient or guarantee payment safety."
        )
    leading = deductions[:3]
    details = ", ".join(
        f"{finding['rule']} (−{abs(finding['impact'])} points)" for finding in leading
    )
    return (
        f"The largest listed score impacts came from: {details}. These are heuristic review signals, "
        "not proof of fraud or a calibrated probability. Informational observations do not reduce the score."
    )


def _render_finding(finding: dict) -> None:
    _icon, bg, text_col = SEVERITY_COLORS[finding["severity"]]
    rule = html.escape(str(finding["rule"]))
    category = html.escape(str(finding["category"]))
    severity = html.escape(str(finding["severity"]))
    reason = html.escape(str(finding["reason"]))
    next_step = html.escape(_finding_next_step(finding))
    impact = finding.get("impact", 0)
    if impact < 0:
        impact_label = f"−{abs(impact)} points"
    elif impact > 0:
        impact_label = f"+{impact} points"
    else:
        impact_label = "No score impact (0 points)"

    st.markdown(
        f"""
        <div style="background:{bg}; border:1px solid rgba(100,116,139,.16);
             border-left:4px solid {text_col}; padding:14px 16px; border-radius:9px;
             margin:10px 0; color:#29384e; box-shadow:0 2px 8px rgba(20,35,59,.035);">
            <strong style="color:{text_col};">{rule}</strong>
            <span style="float:right; color:{text_col}; font-weight:700; font-size:.82rem;">Severity: {severity}</span>
            <div style="margin-top:8px;"><strong>What was detected:</strong> {rule} <span>({category})</span></div>
            <div><strong>Why it matters:</strong> {reason}</div>
            <div><strong>Score impact:</strong> {impact_label}</div>
            <div><strong>What to verify or do next:</strong> {next_step}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

def render_report(report: dict):
    p = report["payload"]
    s = report["trust_score"]
    verdict = report["verdict"]
    v_color = report["verdict_st_color"]

    st.markdown("---")

    # ── Top Row: Score + Verdict ──────────────────────────────────────────
    col_score, col_verdict = st.columns([1, 1])
    with col_score:
        delta_str = f"{s - 100} pts" if s < 100 else "No deductions"
        st.metric("Rule-Based Score", f"{s} / 100", delta=delta_str,
                  delta_color="normal" if s >= 85 else "inverse")

    with col_verdict:
        color_map = {"blue": "info", "orange": "warning", "red": "error"}
        fn = getattr(st, color_map[v_color])
        fn(f"**VERDICT: {verdict}**")
        st.caption(f"Recipient status: {report['account_class']['label']}")
        st.caption(report["score_note"])

    st.subheader("Payment details to verify")
    recipient_col, name_col, amount_col = st.columns(3)
    recipient_col.write("**Recipient identifier**")
    recipient_col.write(p.get("vpa") or "Not provided")
    name_col.write("**Payee name**")
    name_col.write(p.get("name") or "Not provided")
    amount_col.write("**Amount**")
    amount_col.write(
        f"{_format_report_amount(p.get('amount'))} {p.get('currency') or 'INR'}"
        if p.get("amount") not in (None, "")
        else "Not specified in QR"
    )
    st.info(
        "Verify the recipient and amount in your official payment app before authorizing. "
        "These values come from the QR and are not independently verified here."
    )

    st.markdown("##### Why this result?")
    st.write(_why_this_result(report))

    # ── Score Breakdown Bar ───────────────────────────────────────────────
    st.markdown("##### Risk Breakdown by Severity")
    breakdown_cols = st.columns(5)
    counts = {
        "Critical": len(report["critical"]),
        "High":     len(report["high"]),
        "Medium":   len(report["medium"]),
        "Low":      len(report["low"]),
        "Info":     len(report["info"]),
    }
    colors_bd = ["#991b1b", "#9a3412", "#854d0e", "#1e40af"]
    for i, (label, count) in enumerate(counts.items()):
        with breakdown_cols[i]:
            st.metric(label, count)

    # Keep scored warning signals distinct from observations and app limitations.
    warnings = [finding for finding in report["findings"] if finding["severity"] != "INFO"]
    observations = [finding for finding in report["findings"] if finding["severity"] == "INFO"]
    st.markdown("##### Warnings and review indicators")
    if warnings:
        for finding in warnings:
            _render_finding(finding)
    else:
        st.info("No warning indicators were recorded. This does not verify the recipient or guarantee safety.")

    st.markdown("##### Informational observations and limitations")
    if observations:
        for finding in observations:
            _render_finding(finding)
    else:
        st.caption("No informational observations were recorded.")

    # ── QR Metadata Card ─────────────────────────────────────────────────
    with st.expander("Full QR metadata"):
        meta = {
            "QR Fingerprint (SHA-256)": p["qr_hash"],
            "Scan Timestamp": p["scan_time"],
            "Payee VPA": p["vpa"] or "N/A",
            "Payee Name": p["name"] or "N/A",
            "Amount": _format_report_amount(p["amount"]),
            "Currency": p["currency"],
            "Transaction Ref": p["txn_ref"] or "None",
            "Transaction Note": p["txn_note"] or "None",
            "Merchant Category Code": p["mc"] or "Not present",
            "Mode": p["mode"] or "Not specified",
            "Digital Signature": "Present" if p["sign"] else "Absent",
        }
        for k, v in meta.items():
            c1, c2 = st.columns([1, 2])
            c1.caption(k)
            c2.write(v)

    # ── Raw Payload ───────────────────────────────────────────────────────
    with st.expander("Raw QR payload"):
        st.code(p["raw"], language="text")

    # ── Advice Box ───────────────────────────────────────────────────────
    st.markdown("##### Recommended action")
    advice = {
        "NO HIGH-RISK INDICATORS": ("No high-risk verdict was triggered by the rule-based score. Review any listed findings. This does not verify the recipient; check the payee name and amount in your payment app before authorizing.", "info"),
        "REVIEW DETAILS": ("Review the findings and verify the recipient independently before authorizing payment.", "warning"),
        "SUSPICIOUS INDICATORS": ("Some patterns need review. Do not rely on this score alone; confirm the payee through a trusted, separate channel.", "error"),
        "MULTIPLE HIGH-RISK SIGNALS": ("Several format or wording signals were found. Stop and verify the recipient and payment details independently.", "error"),
    }
    text, level = advice[verdict]
    getattr(st, level)(text)


def _format_report_amount(amount):
    if amount is None or amount == "":
        return "Dynamic (user-entered)"
    try:
        numeric_amount = Decimal(amount)
        if not numeric_amount.is_finite():
            raise InvalidOperation
        if numeric_amount and abs(numeric_amount.adjusted()) > 12:
            return f"₹{numeric_amount.normalize():E}"
        return f"₹{numeric_amount:,.2f}"
    except (InvalidOperation, TypeError, ValueError):
        return f"Invalid amount: {amount}"


# ============================================================
# MODULE 4: SESSION HISTORY
# ============================================================

def init_history():
    if "scan_history" not in st.session_state:
        try:
            storage.initialize_storage()
            st.session_state.scan_history = [
                _history_entry(row) for row in storage.get_recent_scans(limit=100)
            ]
            st.session_state.storage_warning = None
        except (sqlite3.Error, OSError, ValueError, storage.StorageError) as exc:
            logger.warning("Persistent scan history is unavailable: %s", exc)
            st.session_state.scan_history = []
            st.session_state.storage_warning = (
                "Persistent history is unavailable. Scans will remain available in this session only."
            )


def _history_entry(row: dict) -> dict:
    timestamp = datetime.datetime.fromisoformat(
        row["scanned_at_utc"].replace("Z", "+00:00")
    ).astimezone()
    fingerprint = row["fingerprint"]
    return {
        "time": timestamp.strftime("%d %b %Y, %I:%M %p"),
        "vpa": row["payee_vpa"],
        "score": row["risk_score"],
        "verdict": row["verdict"],
        "hash": fingerprint[:12].upper(),
    }


def _clear_scan_result():
    st.session_state.pop("scan_report", None)
    st.session_state.pop("current_scan_id", None)
    st.session_state.pop("scan_error", None)


def _manual_input_is_valid(value) -> bool:
    """Accept any non-blank text; malformed/non-UPI input is analyzed by the engine."""
    return isinstance(value, str) and bool(value.strip())


def _manual_input_changed():
    """Update button eligibility and clear a result made stale by edited input."""
    _clear_scan_result()
    st.session_state.manual_input_valid = _manual_input_is_valid(
        st.session_state.get("manual_payload", "")
    )


def decode_uploaded_qr(uploaded_file):
    """Return (image, payload, error) for an uploaded or camera-captured image."""
    try:
        img = Image.open(uploaded_file)
        img.load()
    except (UnidentifiedImageError, OSError, ValueError):
        return None, None, "This file is not a readable image. Please upload a PNG or JPG QR image."

    try:
        decoded_objs = decode(img)
    except Exception:
        return img, None, "The QR decoder could not read this image. Please try a clearer PNG or JPG."

    if not decoded_objs:
        return img, None, "No QR code detected. Please upload a clearer image."
    try:
        payload = decoded_objs[0].data.decode("utf-8")
    except UnicodeDecodeError:
        return img, None, "The QR code contains text that cannot be read as UTF-8."
    return img, payload, None


def decode_camera_capture(camera_capture):
    """Decode a captured image with the same decoder used for uploaded images."""
    if camera_capture is None:
        return None, None, None
    return decode_uploaded_qr(camera_capture)


def _store_scan(raw_payload):
    try:
        payload = parse_upi_payload(raw_payload)
        report = run_risk_engine(payload)
    except (TypeError, ValueError, UnicodeError):
        st.session_state.scan_error = "The supplied QR payload could not be read. Check the text and try again."
        return
    st.session_state.scan_error = None
    st.session_state.scan_report = report
    st.session_state.current_scan_id = None
    add_to_history(report)
    try:
        storage.initialize_storage()
        st.session_state.current_scan_id = storage.save_scan(report)
        st.session_state.storage_warning = None
    except (sqlite3.Error, OSError, ValueError, storage.StorageError) as exc:
        logger.exception("The scan was analyzed but could not be persisted: %s", exc)
        st.session_state.storage_warning = (
            "This scan was analyzed but was not saved to persistent history. "
            "It remains available for this session only."
        )

def add_to_history(report: dict):
    entry = {
        "time": report["payload"]["scan_time"],
        "vpa": report["payload"]["vpa"],
        "score": report["trust_score"],
        "verdict": report["verdict"],
        "hash": report["payload"]["qr_hash"],
    }
    # Each button click is a distinct scan event, including repeated payloads.
    st.session_state.scan_history.insert(0, entry)

def render_history():
    if not st.session_state.scan_history:
        st.info("No scans yet in this session.")
    else:
        for e in st.session_state.scan_history[:10]:
            scan_time = html.escape(str(e["time"]))
            verdict = html.escape(str(e["verdict"]))
            vpa = html.escape(str(e["vpa"] or "unknown"))
            score = html.escape(str(e["score"]))
            fingerprint = html.escape(str(e["hash"]))
            st.markdown(
                f"<div style='background:#fff;border:1px solid #e1e8f2;border-radius:9px;"
                f"padding:12px 15px;margin:8px 0;color:#29384e;'>"
                f"<div style='display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;'>"
                f"<strong>{verdict}</strong><span>Score <strong>{score}/100</strong></span>"
                f"<span>{vpa}</span></div>"
                f"<div style='font-size:.8rem;color:#64748b;margin-top:5px;'>"
                f"{scan_time} · Fingerprint {fingerprint}</div></div>",
                unsafe_allow_html=True,
            )
    st.markdown("#### Download a report from persisted history")
    try:
        persisted = storage.get_recent_scans(limit=100)
        if persisted:
            labels = {
                f"#{row['scan_id']} · {row['scanned_at_utc']} · {row['verdict']} · {row['fingerprint'][:12]}…": row["scan_id"]
                for row in persisted
            }
            selected_label = st.selectbox(
                "Choose a persisted scan", list(labels), key="history_report_scan"
            )
            _render_persisted_report_download(labels[selected_label], "history_report_download")
        else:
            st.info("No persisted scans are available for report generation.")
    except (sqlite3.Error, OSError, ValueError, storage.StorageError) as exc:
        logger.warning("Historical report selection is unavailable: %s", exc)
        st.warning("Reports from scan history are unavailable because local history could not be read.")


def _render_persisted_report_download(scan_id: int, key: str):
    try:
        scan_data = storage.get_scan_report_data(scan_id)
        if scan_data is None:
            st.warning("The selected scan is no longer available in persistent history.")
            return
        _render_pdf_download(scan_data, key)
    except (sqlite3.Error, OSError, ValueError, storage.StorageError) as exc:
        logger.warning("Historical report data could not be read: %s", exc)
        st.warning("This scan's stored report data could not be read.")


def _render_pdf_download(scan_data: dict, key: str):
    from uuid import uuid4
    report_id = str(uuid4()).upper()
    try:
        from forensic_report import ReportGenerationError, generate_pdf_report
        pdf_bytes, _ = generate_pdf_report(scan_data, report_id=report_id)
    except ImportError as exc:
        logger.exception("PDF report support is unavailable: %s", exc)
        st.warning("PDF report generation is unavailable. Install the dependencies listed in requirements.txt.")
        return
    except ReportGenerationError as exc:
        logger.exception("Forensic PDF generation failed: %s", exc)
        st.warning("The forensic report could not be generated. The scan record is unchanged.")
        return
    st.download_button(
        "Download Digital Forensic Report (PDF)",
        data=pdf_bytes,
        file_name=f"QRivox-Forensic-Report-{report_id}.pdf",
        mime="application/pdf",
        key=key,
        use_container_width=True,
    )


def _render_current_report_download(scan_report: dict):
    try:
        from forensic_report import ReportGenerationError, current_scan_data
        _render_pdf_download(current_scan_data(scan_report), "current_scan_report_download")
    except ImportError as exc:
        logger.exception("PDF report support is unavailable: %s", exc)
        st.warning("PDF report generation is unavailable. Install the dependencies listed in requirements.txt.")
    except ReportGenerationError as exc:
        logger.exception("Current scan could not be prepared for a PDF report: %s", exc)
        st.warning("The current scan result could not be prepared as a report.")


def render_analytics():
    """Render read-only analytics sourced directly from persistent SQLite history."""
    try:
        required_storage_apis = (
            "get_analytics_summary", "search_scan_history",
            "get_scan_summary", "get_scan_findings",
        )
        if any(not callable(getattr(storage, name, None)) for name in required_storage_apis):
            # A long-running Streamlit process can retain an older imported module
            # after storage.py changes. Refresh only if the dashboard API is absent.
            importlib.invalidate_caches()
            importlib.reload(storage)
        missing_apis = [
            name for name in required_storage_apis
            if not callable(getattr(storage, name, None))
        ]
        if missing_apis:
            raise AttributeError(
                "Storage module is missing analytics functions: " + ", ".join(missing_apis)
            )
        summary = storage.get_analytics_summary()
        if summary["total_scans"] == 0:
            st.info("No persisted scans yet. Run a scan to start building security history.")
            return

        st.caption(
            "Counts describe scans and rule findings recorded by this app. "
            "They do not measure fraud prevalence or detection accuracy."
        )
        metric_cols = st.columns(4)
        metric_cols[0].metric("Scan events", summary["total_scans"])
        metric_cols[1].metric("Unique QR fingerprints", summary["unique_fingerprints"])
        metric_cols[2].metric("Repeat scan events", summary["repeat_scan_events"])
        metric_cols[3].metric("Fingerprints repeated", summary["repeated_fingerprints"])

        st.subheader("Verdict distribution")
        st.bar_chart({row["verdict"]: row["count"] for row in summary["verdict_distribution"]})
        left, right = st.columns(2)
        with left:
            st.subheader("Scan activity by UTC date")
            st.line_chart({row["day_utc"]: row["count"] for row in summary["scan_activity"]})
        with right:
            st.subheader("Finding severity")
            st.bar_chart({row["severity"]: row["count"] for row in summary["finding_severity"]})
        st.subheader("Frequently triggered rules")
        if summary["frequent_rules"]:
            st.bar_chart({row["rule"]: row["count"] for row in summary["frequent_rules"]})
        else:
            st.info("No findings are recorded for the persisted scans.")

        st.subheader("Search and filter scan history")
        controls = st.columns(3)
        search = controls[0].text_input(
            "Fingerprint search", placeholder="Full or partial SHA-256 fingerprint", key="analytics_search"
        )
        verdict_options = ["All verdicts"] + [row["verdict"] for row in summary["verdict_distribution"]]
        selected_verdict = controls[1].selectbox("Verdict", verdict_options, key="analytics_verdict")
        severity_options = ["All severities"] + [row["severity"] for row in summary["finding_severity"]]
        selected_severity = controls[2].selectbox("Finding severity", severity_options, key="analytics_severity")
        rows = storage.search_scan_history(
            search=search,
            verdict=None if selected_verdict == "All verdicts" else selected_verdict,
            severity=None if selected_severity == "All severities" else selected_severity,
        )
        if rows:
            st.dataframe(
                [{
                    "Scan ID": row["scan_id"],
                    "Scanned at (UTC)": row["scanned_at_utc"],
                    "Fingerprint": row["fingerprint"],
                    "Score": row["risk_score"],
                    "Verdict": row["verdict"],
                } for row in rows],
                width="stretch",
                hide_index=True,
            )
            labels = {
                f"#{row['scan_id']} · {row['scanned_at_utc']} · {row['fingerprint'][:12]}… · {row['verdict']}": row["scan_id"]
                for row in rows
            }
            selected_label = st.selectbox("Inspect a scan", list(labels), key="analytics_scan_detail")
            scan_id = labels[selected_label]
            detail = storage.get_scan_summary(scan_id)
            if detail is not None:
                st.markdown(
                    f"**Scan #{detail['scan_id']}** · {detail['scanned_at_utc']} · "
                    f"Score {detail['risk_score']}/100 · {detail['verdict']}"
                )
                st.caption(f"Fingerprint: {detail['fingerprint']}")
                findings = storage.get_scan_findings(scan_id)
                if findings:
                    st.dataframe(
                        [{
                            "Rule": item["rule"],
                            "Severity": item["severity"],
                            "Explanation": item["reason"],
                            "Score impact": item["score_impact"],
                        } for item in findings],
                        width="stretch",
                        hide_index=True,
                    )
                else:
                    st.info("This scan has no associated findings.")
        else:
            st.info("No persisted scans match these search and filter settings.")
    except (sqlite3.Error, OSError, ValueError, AttributeError, storage.StorageError) as exc:
        logger.warning("Security analytics could not read persistent history: %s", exc)
        st.warning("Security analytics is unavailable because the local scan history could not be read.")


# ============================================================
# MODULE 5: APP SHELL
# ============================================================

def main():
    st.set_page_config(
        page_title="QRivox",
        page_icon=str(LOGO_PATH),
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    st.markdown("""
    <style>
    :root { color-scheme: light; }
    .stApp, [data-testid="stAppViewContainer"] { background: #F3F6FB; color: #14233F; }
    .block-container {
        width: 100%; max-width: none; box-sizing: border-box;
        /* Streamlit's toolbar is absolutely positioned over the app canvas.
           Leave enough normal-flow space for the brand header to start below it. */
        padding: 3.25rem clamp(1rem, 3vw, 2.5rem) 3rem;
    }
    [data-testid="stHeader"] { background: rgba(243, 246, 251, .96); }
    [data-testid="stToolbar"] { right: 1rem; }
    [data-testid="stImage"] img { max-width: 100%; height: auto; }
    div[data-testid="stMarkdownContainer"] p,
    [data-testid="stCaptionContainer"], [data-testid="stWidgetLabel"],
    [data-testid="stMarkdownContainer"] li { color: #64748B; }
    [data-testid="stWidgetLabel"] span, [data-testid="stWidgetLabel"] p { color: #64748B !important; }
    h1, h2, h3, h4, h5, h6 { color: #14233F !important; letter-spacing: -.015em; }
    hr { border-color: #DCE6F5; }

    [class*="st-key-qrivox-brand-header"] {
        max-width: 1180px; margin: 0 auto; padding: .35rem 0 .75rem;
    }
    [class*="st-key-qrivox-brand-header"] [data-testid="stImage"] img {
        display: block; width: 170px; max-width: 100%; height: auto;
    }
    .brand-lockup { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    .brand-title { color: #14233F; font-size: 1.8rem; font-weight: 750; line-height: 1.1; margin: 0; }
    .brand-subtitle { color: #64748B; font-size: .98rem; font-weight: 550; margin: .32rem 0 0; }
    .local-badge {
        display: inline-flex; align-items: center; white-space: nowrap;
        color: #2454c6; background: #eaf0ff; border: 1px solid #cddaff;
        border-radius: 999px; padding: .34rem .68rem; font-size: .68rem;
        font-weight: 750; letter-spacing: .09em;
    }
    .info-card {
        max-width: 1180px; margin: 0 auto 1.4rem; padding: 1.1rem 1.3rem;
        background: #FFFFFF; border: 1px solid #DCE6F5; border-radius: 13px;
        box-shadow: 0 3px 12px rgba(20, 35, 63, .045);
    }
    .info-card .eyebrow {
        color: #2864FF; font-size: .68rem; font-weight: 750;
        letter-spacing: .12em; text-transform: uppercase; margin-bottom: .3rem;
    }
    .info-card h2 { color: #14233F; font-size: 1.18rem; line-height: 1.25; margin: 0; }
    .info-card p { color: #64748B; margin: .32rem 0 0; }
    .info-card .safety-notice {
        color: #33445f; background: #f2f6ff; border: 1px solid #dce6f5;
        border-left: 3px solid #2864FF; border-radius: 7px;
        margin-top: .72rem; padding: .55rem .75rem; font-size: .84rem;
    }
    .section-intro { margin: .2rem 0 1rem; }
    .section-intro .eyebrow {
        color: #2864FF; font-size: .68rem; font-weight: 750;
        letter-spacing: .12em; text-transform: uppercase; margin-bottom: .25rem;
    }
    .section-intro h2 { color: #14233F; font-size: 1.3rem; margin: 0; }
    .section-intro p { color: #64748B; margin: .3rem 0 0; }

    [data-testid="stTabs"] { width: 100%; }
    [data-testid="stTabs"] [role="tablist"] {
        width: 100%; gap: .35rem; border-bottom: 1px solid #DCE6F5; padding-bottom: .1rem;
    }
    [data-testid="stTabs"] button[role="tab"] {
        color: #64748B; font-weight: 600; padding: .7rem .9rem;
        border-bottom: 2px solid transparent; min-height: 2.8rem;
    }
    [data-testid="stTabs"] button[role="tab"]:hover { color: #14233F; background: #edf3fc; }
    [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
        color: #2864FF; border-bottom-color: #2864FF; background: #fff;
    }
    [data-testid="stTabs"] [data-testid="stMarkdownContainer"] p { color: inherit; }
    button[data-testid="stTabsScrollLeft"], button[data-testid="stTabsScrollRight"] {
        background: #fff !important; border: 1px solid #DCE6F5 !important;
        border-radius: 7px; color: #64748B !important;
    }
    button[data-testid="stTabsScrollLeft"] svg,
    button[data-testid="stTabsScrollRight"] svg { fill: #64748B; }

    [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input {
        background: #FFFFFF; border: 1px solid #cbd5e1; border-radius: 9px;
        color: #14233F; line-height: 1.55;
    }
    [data-testid="stTextArea"] textarea::placeholder,
    [data-testid="stTextInput"] input::placeholder { color: #8795a9; }
    [data-testid="stTextArea"] textarea:focus,
    [data-testid="stTextInput"] input:focus {
        border-color: #2864FF; box-shadow: 0 0 0 2px rgba(40, 100, 255, .15);
    }
    [data-testid="stSelectbox"] [role="combobox"],
    [data-testid="stMultiSelect"] [role="combobox"] {
        background: #FFFFFF; border-color: #cbd5e1; color: #14233F;
    }
    [data-testid="stFileUploader"] { width: 100%; }
    [data-testid="stFileUploader"] section {
        width: 100%; box-sizing: border-box; background: #FFFFFF;
        border: 1px dashed #b9c9e0; border-radius: 11px;
    }
    [data-testid="stFileUploader"] section:hover { border-color: #2864FF; }
    [data-testid="stCameraInput"], [data-testid="stCameraInputWebcamComponent"] { width: 100%; }
    [data-testid="stCameraInput"] video {
        display: block; width: 100% !important; max-height: 440px;
        object-fit: contain; border-radius: 10px; background: #edf2f9;
        border: 1px solid #DCE6F5;
    }
    [data-testid="stCameraInputWebcamStyledBox"] {
        width: 100%; box-sizing: border-box; background: #edf2f9 !important;
        border: 1px solid #DCE6F5; border-radius: 10px; overflow: hidden;
    }
    [data-testid="stCameraInputButton"] {
        background: #FFFFFF !important; border: 1px solid #DCE6F5 !important;
        border-radius: 8px; color: #33445f !important;
    }
    [data-testid="stCameraInputButton"]:disabled {
        background: #f1f5fa !important; color: #7b8798 !important; opacity: 1 !important;
    }

    button[data-testid="stBaseButton-primary"] {
        background: #2864FF; border: 1px solid #2864FF; border-radius: 9px;
        color: #fff; font-weight: 650; min-height: 2.7rem;
    }
    button[data-testid="stBaseButton-primary"]:hover:not(:disabled) {
        background: #1d54e5; border-color: #1d54e5; color: #fff;
    }
    button[data-testid="stBaseButton-primary"]:disabled {
        background: #e8edf5 !important; border-color: #d6dfeb !important;
        color: #7b8798 !important; opacity: 1 !important; cursor: not-allowed;
    }
    button[data-testid="stBaseButton-secondary"],
    [data-testid="stDownloadButton"] button {
        background: #FFFFFF; border: 1px solid #DCE6F5; border-radius: 9px;
        color: #2454c6; font-weight: 600;
    }
    button[data-testid="stBaseButton-secondary"]:hover,
    [data-testid="stDownloadButton"] button:hover {
        border-color: #2864FF; color: #1d54e5; background: #f7f9fd;
    }
    [data-testid="stMetric"] {
        background: #FFFFFF; border: 1px solid #DCE6F5; border-radius: 11px;
        padding: .8rem 1rem; box-shadow: 0 2px 8px rgba(20, 35, 63, .035);
    }
    [data-testid="stMetricLabel"] p { color: #64748B !important; }
    [data-testid="stMetricValue"] { color: #14233F; font-size: 1.8rem !important; font-weight: 700; }
    [data-testid="stExpander"] { border-color: #DCE6F5; border-radius: 10px; background: #FFFFFF; }
    [data-testid="stDataFrame"] { border: 1px solid #DCE6F5; border-radius: 10px; }
    [data-testid="stAlert"] { border-radius: 10px; }
    [data-testid="stAlert"] p { color: #33445f; }
    [data-testid="stCheckbox"] label, [data-testid="stRadio"] label { color: #33445f; }
    [data-testid="stMarkdownContainer"] a { color: #2864FF; }

    @media (max-width: 700px) {
        .block-container { padding: 2.75rem .85rem 2rem; }
        [class*="st-key-qrivox-brand-header"] { padding: .25rem 0 .6rem; }
        [class*="st-key-qrivox-brand-header"] [data-testid="stHorizontalBlock"] {
            display: flex !important; flex-wrap: nowrap !important; align-items: center !important;
            gap: .65rem !important;
        }
        [class*="st-key-qrivox-brand-header"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child {
            flex: 0 0 92px !important; width: 92px !important; min-width: 0 !important;
        }
        [class*="st-key-qrivox-brand-header"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:last-child {
            flex: 1 1 auto !important; width: auto !important; min-width: 0 !important;
        }
        [class*="st-key-qrivox-brand-header"] [data-testid="stImage"] img { width: 92px; }
        .brand-title { font-size: 1.45rem; }
        .brand-subtitle { font-size: .85rem; }
        .brand-lockup { align-items: flex-start; flex-direction: column; gap: .4rem; }
        .info-card { padding: .95rem 1rem; }
        [data-testid="stTabs"] [role="tablist"] { gap: 0; overflow-x: auto; }
        [data-testid="stTabs"] button[role="tab"] { padding: .6rem .45rem; font-size: .8rem; }
    }
    </style>
    """, unsafe_allow_html=True)

    with st.container(key="qrivox-brand-header"):
        logo_col, identity_col = st.columns([1.1, 5.2], vertical_alignment="center", gap="medium")
        with logo_col:
            st.image(str(LOGO_PATH), width=170, caption=None)
        with identity_col:
            st.markdown("""
            <div class="brand-lockup">
                <div><div class="brand-title">QRivox</div>
                     <div class="brand-subtitle">UPI QR Security Screening</div></div>
                <span class="local-badge">LOCAL REVIEW</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-card">
        <div class="eyebrow">PAYMENT QR REVIEW</div>
        <h2>QRivox</h2>
        <p>Explainable, local review of UPI QR details and payment metadata.</p>
        <div class="safety-notice"><strong>Safety notice:</strong> Heuristic screening only. This app does not verify recipient identity or guarantee payment safety.</div>
    </div>
    """, unsafe_allow_html=True)

    init_history()

    # Input Tabs
    tab_cam, tab_manual, tab_history, tab_analytics, tab_investigation = st.tabs(
        [":material/qr_code_scanner: Scan QR Image", ":material/edit_note: Manual / Paste",
         ":material/history: Scan History", ":material/analytics: Security Analytics",
         ":material/manage_search: Investigation Workspace"]
    )

    with tab_cam:
        st.markdown("""
        <div class="section-intro"><div class="eyebrow">Image input</div>
        <h2>Scan with your webcam</h2><p>Allow camera access when prompted, position a clear QR code in view, then capture it to begin review.</p></div>
        """, unsafe_allow_html=True)
        st.caption(
            "Allow camera access when your browser asks. If the camera is unavailable "
            "or permission is denied, use the image upload below. Only the decoded "
            "payment metadata and findings are saved; the captured image and raw "
            "payload are not stored in scan history."
        )
        st.info("If your browser cannot open the camera or permission is denied, continue with image upload below.")
        camera_capture = st.camera_input(
            "Capture a clear image of the QR code",
            key="camera_qr_capture",
            on_change=_clear_scan_result,
        )
        camera_payload = None
        if camera_capture is not None:
            camera_image, camera_payload, camera_error = decode_camera_capture(camera_capture)
            if camera_image is not None:
                st.image(camera_image, width=240, caption="Captured QR image")
            if camera_error:
                st.error(camera_error)
            elif camera_payload is not None:
                st.success(f"QR decoded successfully — {len(camera_payload)} characters")
        if st.button(
            ":material/center_focus_strong: Analyze Captured QR",
            type="primary",
            use_container_width=True,
            key="scan_camera",
            disabled=not camera_payload,
        ) and camera_payload:
            _store_scan(camera_payload)

        st.divider()
        st.markdown("""
        <div class="section-intro"><div class="eyebrow">Alternative input</div>
        <h2>Upload an image</h2><p>Use a saved QR screenshot or a clear photo of the code.</p></div>
        """, unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload a QR code image (PNG / JPG)",
            type=["png", "jpg", "jpeg"],
            help="Upload a screenshot or photo of any UPI QR code.",
            on_change=_clear_scan_result,
        )
        image_payload = None
        if uploaded_file:
            img, image_payload, image_error = decode_uploaded_qr(uploaded_file)
            if img is not None:
                st.image(img, width=240, caption="QR image")
            if image_error:
                st.error(image_error)
            elif image_payload is not None:
                st.success(f"QR decoded successfully — {len(image_payload)} characters")
        if st.button(":material/qr_code_scanner: Run Forensic Scan", type="primary", use_container_width=True,
                     key="scan_uploaded", disabled=not image_payload):
            _store_scan(image_payload)

    with tab_manual:
        st.markdown("""
        <div class="section-intro"><div class="eyebrow">Text input</div>
        <h2>Review payment text</h2><p>Paste the text decoded from a QR code to inspect its payment fields and rule findings.</p></div>
        """, unsafe_allow_html=True)
        st.caption(
            "Paste text from a QR code. Any non-empty input can be reviewed; "
            "format problems are shown in the report rather than blocking analysis."
        )
        st.session_state.setdefault("manual_input_valid", False)
        manual_payload = st.text_area(
            "Paste UPI string here",
            placeholder="upi://pay?pa=merchant@oksbi&pn=Shop&am=500&cu=INR",
            height=130,
            help="Paste the raw text extracted from a QR code. Empty or whitespace-only text cannot be scanned.",
            key="manual_payload",
            on_change=_manual_input_changed,
        )
        manual_input_valid = _manual_input_is_valid(manual_payload)
        st.session_state.manual_input_valid = manual_input_valid
        if st.button(":material/qr_code_scanner: Run Forensic Scan", type="primary", use_container_width=True,
                     key="scan_manual", disabled=not manual_input_valid):
            _store_scan(manual_payload)

    with tab_history:
        render_history()

    with tab_analytics:
        render_analytics()

    with tab_investigation:
        investigation_ui.render_investigation_workspace()

    if st.session_state.get("storage_warning"):
        st.warning(st.session_state.storage_warning)
    if st.session_state.get("scan_error"):
        st.error(st.session_state.scan_error)
    if st.session_state.get("scan_report"):
        render_report(st.session_state.scan_report)
        _render_current_report_download(st.session_state.scan_report)

    # Footer
    st.markdown("---")
    st.caption(
        "QRivox ·"
        " Heuristic screening only · Verify the recipient before payment"
    )


if __name__ == "__main__":
    main()
