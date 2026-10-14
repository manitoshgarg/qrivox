"""Pure helpers for the QR Investigation Workspace (no Streamlit, no database access).

Everything here describes stored scan records and this app's own heuristic findings.
Nothing here verifies a recipient, a QR source, or fraud.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

NOT_PROVIDED = "Not provided"

FINGERPRINT_NOTE = (
    "Matching SHA-256 fingerprints show that two scans came from identical QR text (after leading and "
    "trailing whitespace was trimmed). They do not show that the QR is authentic, that its source is "
    "trustworthy, or that a payment is safe or fraudulent."
)
NO_EXTERNAL_REPORTS_NOTE = (
    "This app has no connected source of user reports, bank data, NPCI data or scam intelligence. "
    "Nothing here is a verified or reported match; findings are local heuristics."
)
PAYEE_NOTE = (
    "A payee address that appears under several QR payloads is common for merchants who issue a new QR "
    "per bill or amount. It is a pattern in this local history, not evidence of fraud."
)

COMPARED_FIELDS = (
    ("payee_vpa", "Payee address"),
    ("payee_name", "Payee name"),
    ("amount", "Amount"),
    ("currency", "Currency"),
    ("merchant_category_code", "Merchant category code"),
    ("mode", "Mode"),
)
VARIANT_FIELDS = COMPARED_FIELDS[1:]

_EVIDENCE_BASIS = {
    "format": (
        "Heuristic: format rule",
        "Compares the payload structure with the patterns this app expects. A mismatch is not proof of fraud.",
    ),
    "indicator": (
        "Heuristic: wording or URL indicator",
        "Matches a fixed keyword list or URL pattern. Such text can also appear in legitimate payments.",
    ),
    "observation": (
        "Observation (informational)",
        "Describes a value present in the QR. It has no score impact and is not a warning.",
    ),
    "cannot_verify": (
        "Not verifiable by this app",
        "States something this app has no source to check, such as recipient identity or signatures.",
    ),
}
_UNCLASSIFIED = (
    "Heuristic: unclassified",
    "Recorded by an older or unknown rule category; interpret with the same caution as other heuristics.",
)


def evidence_basis(finding: dict[str, Any]) -> dict[str, str]:
    category = str(finding.get("category", "")).lower()
    label, explanation = _EVIDENCE_BASIS.get(category, _UNCLASSIFIED)
    return {"label": label, "explanation": explanation}


def mask_vpa(value: Any) -> str:
    """Show only the start of the local part, e.g. 'sh***@example.test'."""
    if not isinstance(value, str) or not value.strip():
        return NOT_PROVIDED
    local, separator, handle = value.strip().partition("@")
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}***@{handle}" if separator else f"{visible}***"


def parse_scan_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def format_utc(value: Any) -> str:
    parsed = parse_scan_time(value)
    if parsed is None:
        return str(value) if value else NOT_PROVIDED
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_gap(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    total = int(max(0, seconds))
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


# ---------------------------------------------------------------- findings


def _impact(finding: dict[str, Any]) -> int:
    value = finding.get("score_impact", finding.get("impact", 0))
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _reason(finding: dict[str, Any]) -> str:
    return str(finding.get("reason", finding.get("detail", "")))


def _finding_map(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for finding in findings or []:
        if isinstance(finding, dict):
            mapping.setdefault(str(finding.get("rule", "")), finding)
    return mapping


def _signature(finding: dict[str, Any]) -> tuple[str, int, str]:
    return (str(finding.get("severity", "")), _impact(finding), _reason(finding))


def diff_findings(findings_a: list[dict[str, Any]], findings_b: list[dict[str, Any]]) -> dict[str, list]:
    """Compare two finding lists by rule name (works for engine and stored finding shapes)."""
    a, b = _finding_map(findings_a), _finding_map(findings_b)
    changed, unchanged = [], []
    for rule, before in a.items():
        after = b.get(rule)
        if after is None:
            continue
        if _signature(before) != _signature(after):
            changed.append({"rule": rule, "before": before, "after": after})
        else:
            unchanged.append(after)
    return {
        "only_in_a": [f for rule, f in a.items() if rule not in b],
        "only_in_b": [f for rule, f in b.items() if rule not in a],
        "changed": changed,
        "unchanged": unchanged,
    }


# ---------------------------------------------------------------- timeline


def build_timeline(scans: list[dict[str, Any]], findings_by_scan: dict[int, list]) -> list[dict[str, Any]]:
    """`scans` must be chronological. Each entry describes change since the previous scan."""
    entries: list[dict[str, Any]] = []
    previous: tuple[dict[str, Any], list] | None = None
    for scan in scans:
        findings = findings_by_scan.get(scan["scan_id"], [])
        entry: dict[str, Any] = {
            "scan_id": scan["scan_id"],
            "scanned_at_utc": scan["scanned_at_utc"],
            "risk_score": scan["risk_score"],
            "verdict": scan["verdict"],
            "is_first": previous is None,
            "score_change": None,
            "verdict_change": None,
            "added_rules": [],
            "removed_rules": [],
            "changed_rules": [],
            "seconds_since_previous": None,
        }
        if previous is not None:
            prev_scan, prev_findings = previous
            diff = diff_findings(prev_findings, findings)
            entry["added_rules"] = [str(f.get("rule", "")) for f in diff["only_in_b"]]
            entry["removed_rules"] = [str(f.get("rule", "")) for f in diff["only_in_a"]]
            entry["changed_rules"] = [item["rule"] for item in diff["changed"]]
            entry["score_change"] = scan["risk_score"] - prev_scan["risk_score"]
            if scan["verdict"] != prev_scan["verdict"]:
                entry["verdict_change"] = (prev_scan["verdict"], scan["verdict"])
            then, now = parse_scan_time(prev_scan["scanned_at_utc"]), parse_scan_time(scan["scanned_at_utc"])
            if then and now:
                entry["seconds_since_previous"] = (now - then).total_seconds()
        entry["has_changes"] = bool(
            entry["added_rules"] or entry["removed_rules"] or entry["changed_rules"]
            or entry["score_change"] or entry["verdict_change"]
        )
        entries.append(entry)
        previous = (scan, findings)
    return entries


def describe_changes(entry: dict[str, Any]) -> str:
    if entry["is_first"]:
        return "First recorded scan of this payload"
    parts = []
    if entry["score_change"]:
        parts.append(f"score {entry['score_change']:+d}")
    if entry["verdict_change"]:
        parts.append(f"verdict {entry['verdict_change'][0]} → {entry['verdict_change'][1]}")
    if entry["added_rules"]:
        parts.append("new: " + ", ".join(entry["added_rules"]))
    if entry["removed_rules"]:
        parts.append("no longer present: " + ", ".join(entry["removed_rules"]))
    if entry["changed_rules"]:
        parts.append("changed: " + ", ".join(entry["changed_rules"]))
    return "; ".join(parts) or "No change"


def timeline_overview(scans: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    if not scans:
        raise ValueError("At least one scan is required.")
    scores = [scan["risk_score"] for scan in scans]
    return {
        "scan_count": len(scans),
        "first_seen_utc": scans[0]["scanned_at_utc"],
        "last_seen_utc": scans[-1]["scanned_at_utc"],
        "min_score": min(scores),
        "max_score": max(scores),
        "verdicts": sorted({scan["verdict"] for scan in scans}),
        "findings_changed": any(
            entry["added_rules"] or entry["removed_rules"] or entry["changed_rules"] for entry in timeline
        ),
    }


# -------------------------------------------------------------- comparison


def _norm(value: Any) -> str:
    return "" if value is None else str(value).strip()


def compare_scans(scan_a: dict[str, Any], scan_b: dict[str, Any], mask_payee: bool = True) -> dict[str, Any]:
    """Compare two records from storage.get_scan_report_data. Differences use real values;
    `mask_payee` only affects how the payee address is displayed."""
    fields = []
    for key, label in COMPARED_FIELDS:
        norm_a, norm_b = _norm(scan_a.get(key)), _norm(scan_b.get(key))
        shown_a, shown_b = norm_a or NOT_PROVIDED, norm_b or NOT_PROVIDED
        if key == "payee_vpa" and mask_payee:
            shown_a, shown_b = mask_vpa(norm_a), mask_vpa(norm_b)
        fields.append({"field": key, "label": label, "scan_a": shown_a, "scan_b": shown_b,
                       "differs": norm_a != norm_b})
    same_fingerprint = scan_a.get("fingerprint") == scan_b.get("fingerprint")
    notes = []
    if same_fingerprint:
        notes.append(
            "Both scans came from identical QR text. Any finding or score difference reflects a change in "
            "this app's rules or stored records between scan dates, not a change in the QR."
        )
    else:
        notes.append(
            "The fingerprints differ, so the QR text differs. A hash comparison does not show how much it "
            "differs or which version is genuine."
        )
    notes.append(
        "Field differences are facts about stored fields. They are not evidence of tampering or fraud."
    )
    return {
        "same_fingerprint": same_fingerprint,
        "score_a": scan_a["risk_score"],
        "score_b": scan_b["risk_score"],
        "score_delta": scan_b["risk_score"] - scan_a["risk_score"],
        "verdict_a": scan_a["verdict"],
        "verdict_b": scan_b["verdict"],
        "verdict_changed": scan_a["verdict"] != scan_b["verdict"],
        "fields": fields,
        "differing_field_count": sum(1 for f in fields if f["differs"]),
        "findings": diff_findings(scan_a.get("findings", []), scan_b.get("findings", [])),
        "notes": notes,
    }


# ----------------------------------------------------------- payee variants


def group_payee_variants(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group scans of one payee address by fingerprint (one row per distinct QR payload)."""
    ordered = sorted(scans, key=lambda s: (str(s.get("scanned_at_utc", "")), int(s.get("scan_id", 0))))
    groups: dict[str, dict[str, Any]] = {}
    for scan in ordered:
        entry = groups.get(scan["fingerprint"])
        if entry is None:
            entry = groups[scan["fingerprint"]] = {
                "fingerprint": scan["fingerprint"],
                "scan_count": 0,
                "first_seen_utc": scan["scanned_at_utc"],
                **{key: scan.get(key) for key, _ in VARIANT_FIELDS},
            }
        entry["scan_count"] += 1
        entry["last_seen_utc"] = scan["scanned_at_utc"]
        entry["latest_score"] = scan["risk_score"]
        entry["latest_verdict"] = scan["verdict"]
    return sorted(groups.values(), key=lambda e: (e["last_seen_utc"], e["fingerprint"]), reverse=True)


def varying_fields(variants: list[dict[str, Any]]) -> list[str]:
    return [
        label for key, label in VARIANT_FIELDS
        if len({_norm(variant.get(key)) for variant in variants}) > 1
    ]


# ------------------------------------------------------------ Markdown export


def _md(value: Any) -> str:
    text = NOT_PROVIDED if value in (None, "") else str(value)
    return " ".join(text.replace("|", "\\|").split())


def _finding_line(finding: dict[str, Any]) -> str:
    return (f"{_md(finding.get('rule'))} ({_md(finding.get('severity'))}, {_impact(finding):+d} points) "
            f"— {evidence_basis(finding)['label']}")


def _stamp(generated_at: datetime | None) -> str:
    moment = generated_at or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_investigation_summary(
    fingerprint: str, scans: list[dict[str, Any]], findings_by_scan: dict[int, list],
    *, reveal_payee: bool = False, generated_at: datetime | None = None,
) -> str:
    if not scans:
        raise ValueError("At least one scan is required for an investigation summary.")
    timeline = build_timeline(scans, findings_by_scan)
    overview = timeline_overview(scans, timeline)
    latest = scans[-1]
    payee = _md(latest.get("payee_vpa")) if reveal_payee else mask_vpa(latest.get("payee_vpa"))
    lines = [
        "# QR Investigation Summary", "",
        f"Generated: {_stamp(generated_at)}",
        f"QR fingerprint (SHA-256): `{fingerprint}`",
        f"Payee address (latest scan): {payee}", "",
        "## Scope and limits", "",
        f"- {FINGERPRINT_NOTE}",
        f"- {NO_EXTERNAL_REPORTS_NOTE}",
        "- Scores are deterministic heuristics, not calibrated fraud probabilities.",
        "- Raw QR payloads, notes, signatures and transaction references are not stored or included.", "",
        "## Overview", "",
        f"- Scan events: {overview['scan_count']}",
        f"- First scan: {format_utc(overview['first_seen_utc'])}",
        f"- Last scan: {format_utc(overview['last_seen_utc'])}",
        f"- Score range: {overview['min_score']}–{overview['max_score']}",
        f"- Verdicts recorded: {_md(', '.join(overview['verdicts']))}",
    ]
    if overview["findings_changed"]:
        lines.append("- Findings differ between scans of identical QR text, which reflects a change in this "
                     "app's rules or stored records between scan dates.")
    lines += ["", "## Timeline", "",
              "| # | Scan ID | Scanned (UTC) | Since previous | Score | Verdict | Changes |",
              "|---|---|---|---|---|---|---|"]
    for index, entry in enumerate(timeline, start=1):
        lines.append(
            f"| {index} | {entry['scan_id']} | {format_utc(entry['scanned_at_utc'])} | "
            f"{format_gap(entry['seconds_since_previous'])} | {entry['risk_score']} | "
            f"{_md(entry['verdict'])} | {_md(describe_changes(entry))} |"
        )
    lines += ["", "## Findings in the latest scan", ""]
    latest_findings = findings_by_scan.get(latest["scan_id"], [])
    if not latest_findings:
        lines.append("No findings were recorded for the latest scan.")
    for position, finding in enumerate(latest_findings, start=1):
        basis = evidence_basis(finding)
        lines += [f"{position}. **{_finding_line(finding)}**",
                  f"   - Basis: {basis['explanation']}",
                  f"   - Recorded explanation: {_md(_reason(finding))}"]
    return "\n".join(lines) + "\n"


def build_comparison_summary(
    scan_a: dict[str, Any], scan_b: dict[str, Any], comparison: dict[str, Any],
    *, generated_at: datetime | None = None,
) -> str:
    lines = [
        "# QR Scan Comparison", "",
        f"Generated: {_stamp(generated_at)}", "",
        "## Scans compared", "",
        f"- Scan A: #{scan_a['scan_id']} · {format_utc(scan_a['scanned_at_utc'])} · "
        f"score {comparison['score_a']} · {_md(comparison['verdict_a'])}",
        f"  - Fingerprint: `{scan_a['fingerprint']}`",
        f"- Scan B: #{scan_b['scan_id']} · {format_utc(scan_b['scanned_at_utc'])} · "
        f"score {comparison['score_b']} · {_md(comparison['verdict_b'])}",
        f"  - Fingerprint: `{scan_b['fingerprint']}`",
        f"- Score change A→B: {comparison['score_delta']:+d}",
        f"- Identical QR text: {'yes' if comparison['same_fingerprint'] else 'no'}", "",
        "## Stored field comparison", "",
        "| Field | Scan A | Scan B | Differs |", "|---|---|---|---|",
    ]
    for item in comparison["fields"]:
        lines.append(f"| {item['label']} | {_md(item['scan_a'])} | {_md(item['scan_b'])} | "
                     f"{'yes' if item['differs'] else 'no'} |")
    diff = comparison["findings"]
    for title, items in (("Only in scan A", diff["only_in_a"]), ("Only in scan B", diff["only_in_b"])):
        lines += ["", f"## {title}", ""]
        lines += [f"- {_finding_line(f)}" for f in items] or ["- None"]
    lines += ["", "## Changed between scans", ""]
    lines += [
        f"- {_md(item['rule'])}: {_md(item['before'].get('severity'))}/{_impact(item['before']):+d} → "
        f"{_md(item['after'].get('severity'))}/{_impact(item['after']):+d}"
        for item in diff["changed"]
    ] or ["- None"]
    lines += ["", "## Notes and limits", ""]
    lines += [f"- {note}" for note in comparison["notes"]]
    lines += [f"- {NO_EXTERNAL_REPORTS_NOTE}", "- Scores are heuristics, not fraud probabilities."]
    return "\n".join(lines) + "\n"