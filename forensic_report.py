"""Generate downloadable PDF reports from scan records without changing storage."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from uuid import uuid4
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image as ReportImage
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class ReportGenerationError(RuntimeError):
    """Raised when a scan record cannot be rendered as a PDF report."""


_FONT_NAME = "QRivoxUnicode"
_LOGO_PATH = Path(__file__).resolve().parent / "assets" / "qrivox_logo.png"


def _font_name() -> str:
    """Use a local Unicode TrueType font when available, with a built-in fallback."""
    if _FONT_NAME in pdfmetrics.getRegisteredFontNames():
        return _FONT_NAME
    candidate_paths = (
        Path("C:/Windows/Fonts/Nirmala.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
    )
    for font_path in candidate_paths:
        if font_path.is_file():
            try:
                pdfmetrics.registerFont(TTFont(_FONT_NAME, str(font_path)))
                return _FONT_NAME
            except (OSError, ValueError):
                continue
    return "Helvetica"


def _text(value: Any, default: str = "Not available") -> str:
    if value is None or value == "":
        return default
    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    # Escape user-controlled payment metadata and finding text before ReportLab's
    # small XML-like Paragraph parser sees it.
    text = _text(value)
    font = pdfmetrics.getFont(style.fontName)
    if isinstance(font, TTFont):
        cmap = font.face.charToGlyph
        text = "".join(
            char if ord(char) in cmap else f"\\u{ord(char):04x}"
            for char in text
        )
    else:
        try:
            text.encode("cp1252")
        except UnicodeEncodeError:
            text = text.encode("ascii", "backslashreplace").decode("ascii")
    return Paragraph(escape(text), style)


def _classification(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "")).lower()
    severity = str(finding.get("severity", "")).upper()
    if category == "cannot_verify":
        return "Information / verification limitation"
    if category == "observation" or severity == "INFO":
        return "Informational observation"
    if category == "indicator":
        return "Suspicious indicator; not a verified match"
    if category == "format":
        return "Format validation finding"
    return "Finding; interpretation is limited by the stated methodology"


def current_scan_data(scan_report: dict[str, Any]) -> dict[str, Any]:
    """Project an in-memory result into the same safe fields used for stored scans."""
    try:
        payload = scan_report["payload"]
        raw = payload["raw"]
        import hashlib

        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        scan_time = payload.get("scan_time")
        scanned_at = _text(scan_time)
        findings = [
            {
                "rule": finding.get("rule", "Unlabeled finding"),
                "category": finding.get("category", ""),
                "severity": finding.get("severity", "INFO"),
                "reason": finding.get("reason", finding.get("detail", "No explanation recorded.")),
                "score_impact": finding.get("impact", 0),
            }
            for finding in scan_report.get("findings", [])
        ]
        return {
            "scan_id": None,
            "scanned_at_utc": scanned_at,
            "fingerprint": fingerprint,
            "risk_score": scan_report["trust_score"],
            "verdict": scan_report["verdict"],
            "payee_vpa": payload.get("vpa"),
            "payee_name": payload.get("name"),
            "amount": payload.get("amount"),
            "currency": payload.get("currency"),
            "merchant_category_code": payload.get("mc"),
            "mode": payload.get("mode"),
            "findings": findings,
        }
    except (KeyError, AttributeError, TypeError, UnicodeError) as exc:
        raise ReportGenerationError("The current scan result is incomplete and cannot be reported.") from exc


def generate_pdf_report(
    scan: dict[str, Any], report_id: str | None = None
) -> tuple[bytes, str]:
    """Build a PDF in memory and return (PDF bytes, report ID)."""
    try:
        if not isinstance(scan, dict):
            raise ValueError("A scan record must be a dictionary.")
        score = scan.get("risk_score")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError("The stored score must be an integer between 0 and 100.")
        findings = scan.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("Scan findings must be a list.")

        report_id = report_id or str(uuid4()).upper()
        font = _font_name()
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="QRTitle", parent=styles["Title"], fontName=font,
            fontSize=20, leading=25, textColor=colors.HexColor("#12304A"),
            alignment=TA_CENTER, spaceAfter=5 * mm,
        ))
        styles.add(ParagraphStyle(
            name="QRHeading", parent=styles["Heading2"], fontName=font,
            fontSize=12, leading=16, textColor=colors.HexColor("#12304A"),
            spaceBefore=4 * mm, spaceAfter=2 * mm,
        ))
        styles.add(ParagraphStyle(
            name="QRBody", parent=styles["BodyText"], fontName=font,
            fontSize=9, leading=13, wordWrap="CJK", spaceAfter=2 * mm,
        ))
        styles.add(ParagraphStyle(
            name="QRSmall", parent=styles["BodyText"], fontName=font,
            fontSize=8, leading=11, textColor=colors.HexColor("#374151"),
        ))
        styles.add(ParagraphStyle(
            name="QRFinding", parent=styles["Heading3"], fontName=font,
            fontSize=10, leading=13, textColor=colors.HexColor("#12304A"),
            spaceBefore=3 * mm, spaceAfter=1 * mm,
        ))

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
            topMargin=17 * mm, bottomMargin=17 * mm,
            title="QRivox Digital Forensic Report",
            author="QRivox",
        )
        report_logo = ReportImage(
            str(_LOGO_PATH), width=72 * mm, height=24 * mm,
            kind="proportional", mask="auto",
        )
        report_logo.hAlign = "CENTER"
        story = [
            report_logo,
            Spacer(1, 2 * mm),
            _paragraph("Digital Forensic Scan Report", styles["Heading2"]),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1D6B8A")),
            Spacer(1, 4 * mm),
        ]
        report_stamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        overview = [
            [_paragraph("Report ID", styles["QRSmall"]), _paragraph(report_id, styles["QRBody"])],
            [_paragraph("Scan timestamp", styles["QRSmall"]), _paragraph(scan.get("scanned_at_utc"), styles["QRBody"])],
            [_paragraph("Report generated (UTC)", styles["QRSmall"]), _paragraph(report_stamp, styles["QRBody"])],
            [_paragraph("Full SHA-256 QR fingerprint", styles["QRSmall"]), _paragraph(scan.get("fingerprint"), styles["QRSmall"])],
            [_paragraph("Rule-based score", styles["QRSmall"]), _paragraph(f"{score} / 100", styles["QRBody"])],
            [_paragraph("Verdict", styles["QRSmall"]), _paragraph(scan.get("verdict"), styles["QRBody"])],
        ]
        overview_table = Table(overview, colWidths=[52 * mm, 122 * mm], repeatRows=0, hAlign="LEFT")
        overview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF4F7")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story += [_paragraph("Scan summary", styles["QRHeading"]), overview_table]

        story.append(_paragraph("Available payment metadata", styles["QRHeading"]))
        metadata = (
            ("Payee address", scan.get("payee_vpa")),
            ("Payee name", scan.get("payee_name")),
            ("Amount", scan.get("amount")),
            ("Currency", scan.get("currency")),
            ("Merchant category code", scan.get("merchant_category_code")),
            ("Mode", scan.get("mode")),
        )
        metadata_table = Table(
            [[_paragraph(label, styles["QRSmall"]), _paragraph(value, styles["QRBody"])] for label, value in metadata],
            colWidths=[52 * mm, 122 * mm], hAlign="LEFT",
        )
        metadata_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(metadata_table)

        story.append(_paragraph("Findings in recorded order", styles["QRHeading"]))
        if findings:
            for position, finding in enumerate(findings, start=1):
                if not isinstance(finding, dict):
                    raise ValueError("Each finding must be a dictionary.")
                impact = finding.get("score_impact", finding.get("impact", 0))
                if isinstance(impact, bool) or not isinstance(impact, int):
                    raise ValueError("Finding score impact must be an integer.")
                rule = _text(finding.get("rule"), "Unlabeled finding")
                story.append(_paragraph(f"{position}. {rule}", styles["QRFinding"]))
                details = [
                    [
                        _paragraph("Classification", styles["QRSmall"]),
                        _paragraph(_classification(finding), styles["QRBody"]),
                    ],
                    [
                        _paragraph("Severity", styles["QRSmall"]),
                        _paragraph(finding.get("severity"), styles["QRBody"]),
                    ],
                    [
                        _paragraph("Score impact", styles["QRSmall"]),
                        _paragraph(f"{impact:+d} points", styles["QRBody"]),
                    ],
                    [
                        _paragraph("Explanation", styles["QRSmall"]),
                        _paragraph(finding.get("reason", finding.get("detail", "No explanation recorded.")), styles["QRBody"]),
                    ],
                ]
                detail_table = Table(
                    details, colWidths=[38 * mm, 136 * mm], hAlign="LEFT", splitInRow=1
                )
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D7DEE6")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.extend([detail_table, Spacer(1, 2 * mm)])
        else:
            story.append(_paragraph("No findings were recorded for this scan.", styles["QRBody"]))

        story.append(_paragraph("Recommended next steps", styles["QRHeading"]))
        next_steps = [
            "Confirm the displayed recipient and amount in your payment app before authorizing a transaction.",
            "For concerning indicators or format findings, pause and verify payment details through a trusted, separate channel.",
            "Treat informational findings as statements about what this application cannot verify, not as evidence of fraud.",
        ]
        for step in next_steps:
            story.append(_paragraph("• " + step, styles["QRBody"]))

        story.append(_paragraph("Detection methodology and limitations", styles["QRHeading"]))
        limitations = (
            "This report records a deterministic, rule-based review of the scan and findings saved at scan time. "
            "Historical findings are reproduced from the database; the current risk engine is not rerun. "
            "Format errors, informational observations, and suspicious wording indicators are described separately. "
            "No sourced malicious-account database or identity-verification service is connected, so this report "
            "does not assert a verified malicious match. The score is not a calibrated probability of fraud. "
            "Analysis is automated, does not independently verify the recipient, and cannot guarantee transaction safety."
        )
        story.append(_paragraph(limitations, styles["QRBody"]))

        def page_footer(canvas, document):
            canvas.saveState()
            canvas.setFont(font, 8)
            canvas.setFillColor(colors.HexColor("#64748B"))
            canvas.drawString(18 * mm, 10 * mm, "QRivox · Automated review · Not recipient verification")
            canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
        return buffer.getvalue(), report_id
    except ReportGenerationError:
        raise
    except Exception as exc:
        raise ReportGenerationError(f"The PDF report could not be generated: {exc}") from exc
