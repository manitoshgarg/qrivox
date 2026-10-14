"""Streamlit rendering for the QR Investigation Workspace (read-only; never writes scan history)."""

from __future__ import annotations

import logging
import sqlite3
import importlib

import streamlit as st

import investigation
import storage

logger = logging.getLogger(__name__)
_READ_ERRORS = (sqlite3.Error, OSError, ValueError, AttributeError, storage.StorageError)
_VIEWS = ("QR timeline", "Compare two scans", "Recurring payee addresses")
_STORAGE_APIS = (
    "get_fingerprint_summaries",
    "get_scans_for_fingerprint",
    "get_scan_findings",
    "get_recent_scans",
    "get_scan_report_data",
    "get_payee_groups",
    "get_scans_for_payee",
)


def _refresh_storage_api_if_needed() -> None:
    """Refresh a stale in-process storage import after a code update."""
    global _READ_ERRORS
    missing = [name for name in _STORAGE_APIS if not callable(getattr(storage, name, None))]
    if missing:
        # Streamlit can keep this module object alive across a code update. Reload
        # only when a required function is absent; this does not touch the DB.
        importlib.invalidate_caches()
        importlib.reload(storage)
        # reload redefines the module's exception class too.
        _READ_ERRORS = (sqlite3.Error, OSError, ValueError, AttributeError, storage.StorageError)
        missing = [name for name in _STORAGE_APIS if not callable(getattr(storage, name, None))]
    if missing:
        raise AttributeError("Storage module is missing investigation functions: " + ", ".join(missing))


def render_investigation_workspace() -> None:
    st.caption(
        "Investigate the scan history recorded by this app: repeated QR payloads, how results changed, "
        "and how two scans differ. " + investigation.NO_EXTERNAL_REPORTS_NOTE
    )
    view = st.radio("Investigation view", _VIEWS, horizontal=True, key="investigation_view")
    reveal = st.checkbox(
        "Show full payee details (masked by default)", value=False, key="investigation_reveal"
    )
    try:
        _refresh_storage_api_if_needed()
        if view == _VIEWS[0]:
            _render_timeline(reveal)
        elif view == _VIEWS[1]:
            _render_compare(reveal)
        else:
            _render_payee_groups(reveal)
    except _READ_ERRORS as exc:
        logger.warning("Investigation Workspace could not read persistent history: %s", exc)
        st.warning(
            "The Investigation Workspace is unavailable because local scan history could not be read. "
            "If the app was just updated, restart Streamlit."
        )


def _show_findings(title: str, findings: list) -> None:
    st.markdown(f"**{title}**")
    if not findings:
        st.caption("None")
    for finding in findings:
        impact = finding.get("score_impact", finding.get("impact", 0))
        st.text(
            f"• {finding.get('rule')} ({finding.get('severity')}, {impact:+d} points) — "
            f"{investigation.evidence_basis(finding)['label']}"
        )


def _render_timeline(reveal: bool) -> None:
    search = st.text_input(
        "Fingerprint search", placeholder="Full or partial SHA-256 fingerprint (hex)",
        key="investigation_fp_search",
    )
    try:
        summaries = storage.get_fingerprint_summaries(search=search, limit=200)
    except ValueError:
        st.info("Fingerprint search accepts hexadecimal characters only (0-9 and a-f).")
        return
    if not summaries:
        st.info("No persisted scans match. Run a scan first, or clear the search box.")
        return
    if st.checkbox("Only QR fingerprints scanned more than once", key="investigation_repeated_only"):
        summaries = [row for row in summaries if row["scan_count"] > 1]
        if not summaries:
            st.info("No fingerprint has been scanned more than once yet.")
            return
    labels = {
        row["fingerprint"]: (
            f"{row['fingerprint'][:12].upper()}… · {row['scan_count']} scan(s) · "
            f"last {investigation.format_utc(row['last_seen_utc'])}"
        )
        for row in summaries
    }
    selected = st.selectbox("QR fingerprint", list(labels), format_func=labels.get, key="investigation_fp_select")
    scans = storage.get_scans_for_fingerprint(selected)
    if not scans:
        st.warning("The selected fingerprint is no longer in persistent history.")
        return
    findings_by_scan = {scan["scan_id"]: storage.get_scan_findings(scan["scan_id"]) for scan in scans}
    timeline = investigation.build_timeline(scans, findings_by_scan)
    overview = investigation.timeline_overview(scans, timeline)

    st.caption(f"Full fingerprint (SHA-256): {selected}")
    cols = st.columns(4)
    cols[0].metric("Scan events", overview["scan_count"])
    cols[1].metric("First scan (UTC)", investigation.format_utc(overview["first_seen_utc"]))
    cols[2].metric("Last scan (UTC)", investigation.format_utc(overview["last_seen_utc"]))
    cols[3].metric("Findings changed", "Yes" if overview["findings_changed"] else "No")
    if overview["scan_count"] > 1:
        st.info(f"This QR text was scanned {overview['scan_count']} times. {investigation.FINGERPRINT_NOTE}")
    else:
        st.info(f"This QR text has been scanned once. {investigation.FINGERPRINT_NOTE}")
    if overview["findings_changed"]:
        st.warning(
            "Findings differ between scans of identical QR text. This reflects a change in this app's rules "
            "or stored records between scan dates, not a change in the QR."
        )

    st.dataframe(
        [{
            "#": index,
            "Scan ID": entry["scan_id"],
            "Scanned (UTC)": investigation.format_utc(entry["scanned_at_utc"]),
            "Since previous": investigation.format_gap(entry["seconds_since_previous"]),
            "Score": entry["risk_score"],
            "Verdict": entry["verdict"],
            "Changes": investigation.describe_changes(entry),
        } for index, entry in enumerate(timeline, start=1)],
        width="stretch", hide_index=True,
    )

    latest = scans[-1]
    payee = latest.get("payee_vpa") or investigation.NOT_PROVIDED if reveal else investigation.mask_vpa(latest.get("payee_vpa"))
    st.markdown("##### Evidence in the latest scan")
    st.text(f"Payee address: {payee}")
    latest_findings = findings_by_scan[latest["scan_id"]]
    if not latest_findings:
        st.caption("No findings were recorded for the latest scan.")
    for finding in latest_findings:
        basis = investigation.evidence_basis(finding)
        with st.expander(f"{finding['rule']} · {finding['severity']} · {finding['score_impact']:+d} points"):
            st.text(f"Evidence basis: {basis['label']}")
            st.text(basis["explanation"])
            st.text(f"Recorded explanation: {finding['reason']}")

    summary = investigation.build_investigation_summary(
        selected, scans, findings_by_scan, reveal_payee=reveal
    )
    st.download_button(
        "Download investigation summary (Markdown)", data=summary.encode("utf-8"),
        file_name=f"QRivox-Investigation-{selected[:12].upper()}.md", mime="text/markdown",
        key="investigation_timeline_download", width="stretch",
    )


def _render_compare(reveal: bool) -> None:
    rows = storage.get_recent_scans(limit=200)
    if len(rows) < 2:
        st.info("Run at least two scans to compare them.")
        return
    labels = {
        row["scan_id"]: (
            f"#{row['scan_id']} · {investigation.format_utc(row['scanned_at_utc'])} · "
            f"{row['verdict']} · {row['fingerprint'][:12].upper()}"
        )
        for row in rows
    }
    ids = list(labels)
    col_a, col_b = st.columns(2)
    a_id = col_a.selectbox("Scan A", ids, format_func=labels.get, key="investigation_scan_a")
    b_id = col_b.selectbox("Scan B", ids, index=1, format_func=labels.get, key="investigation_scan_b")
    if a_id == b_id:
        st.info("Choose two different scan events to compare.")
        return
    scan_a, scan_b = storage.get_scan_report_data(a_id), storage.get_scan_report_data(b_id)
    if scan_a is None or scan_b is None:
        st.warning("One of the selected scans is no longer in persistent history.")
        return
    result = investigation.compare_scans(scan_a, scan_b, mask_payee=not reveal)

    (st.success if result["same_fingerprint"] else st.info)(
        "Identical QR text (fingerprints match). " if result["same_fingerprint"]
        else "Different QR text (fingerprints differ). "
    )
    cols = st.columns(3)
    cols[0].metric("Score A", result["score_a"])
    cols[1].metric("Score B", result["score_b"], delta=result["score_delta"])
    cols[2].metric("Fields that differ", result["differing_field_count"])
    st.dataframe(
        [{"Field": f["label"], "Scan A": f["scan_a"], "Scan B": f["scan_b"],
          "Differs": "Yes" if f["differs"] else "No"} for f in result["fields"]],
        width="stretch", hide_index=True,
    )
    diff = result["findings"]
    _show_findings("Findings only in scan A", diff["only_in_a"])
    _show_findings("Findings only in scan B", diff["only_in_b"])
    st.markdown("**Findings that changed**")
    if not diff["changed"]:
        st.caption("None")
    for item in diff["changed"]:
        st.text(f"• {item['rule']}: severity/score impact or explanation differs between the scans")
    _show_findings("Findings present in both, unchanged", diff["unchanged"])
    for note in result["notes"]:
        st.caption(note)
    summary = investigation.build_comparison_summary(scan_a, scan_b, result)
    st.download_button(
        "Download comparison (Markdown)", data=summary.encode("utf-8"),
        file_name=f"QRivox-Comparison-{a_id}-vs-{b_id}.md", mime="text/markdown",
        key="investigation_compare_download", width="stretch",
    )


def _render_payee_groups(reveal: bool) -> None:
    groups = storage.get_payee_groups(min_fingerprints=2, limit=50)
    if not groups:
        st.info("No payee address has appeared under more than one QR fingerprint in the recorded history.")
        return
    st.caption(investigation.PAYEE_NOTE + " Payee addresses are compared case-insensitively.")
    labels = {
        group["payee_key"]: (
            f"{group['payee_key'] if reveal else investigation.mask_vpa(group['payee_key'])} · "
            f"{group['distinct_fingerprints']} QR payloads · {group['scan_count']} scans"
        )
        for group in groups
    }
    selected = st.selectbox("Payee address", list(labels), format_func=labels.get, key="investigation_payee_select")
    variants = investigation.group_payee_variants(storage.get_scans_for_payee(selected))
    varying = investigation.varying_fields(variants)
    st.info(
        "Stored fields that vary across these QR payloads: " + (", ".join(varying) or "none")
        + ". This describes recorded data; it does not indicate intent."
    )
    table = []
    for variant in variants:
        row = {
            "Fingerprint": variant["fingerprint"][:12].upper(),
            "Scans": variant["scan_count"],
            "First scan (UTC)": investigation.format_utc(variant["first_seen_utc"]),
            "Last scan (UTC)": investigation.format_utc(variant["last_seen_utc"]),
            "Amount": variant.get("amount") or investigation.NOT_PROVIDED,
            "Currency": variant.get("currency") or investigation.NOT_PROVIDED,
            "MCC": variant.get("merchant_category_code") or investigation.NOT_PROVIDED,
            "Mode": variant.get("mode") or investigation.NOT_PROVIDED,
            "Latest score": variant["latest_score"],
            "Latest verdict": variant["latest_verdict"],
        }
        if reveal:
            row["Payee name"] = variant.get("payee_name") or investigation.NOT_PROVIDED
        table.append(row)
    st.dataframe(table, width="stretch", hide_index=True)
