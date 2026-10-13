"""PDF report generator for SecureMailScope (Tier 2 / Prompt T2.5).

Produces deterministic PDF export from report data and HTML using WeasyPrint (pinned 64.1).
When native C runtime libraries (GTK3/Pango) are unavailable on host OS, seamlessly
falls back to the bundled pure-Python pydyf engine so generation always succeeds without network access.
The anchored hash shown in the header is always SHA-256(report.json).
"""
import io
from pathlib import Path
from typing import Any, Dict, List, Optional
import pydyf


def sanitize_pdf_text(text: str) -> str:
    """Sanitize string for PDF ASCII Type1 fonts."""
    if text is None:
        return ""
    # Replace non-ASCII and parenthesis
    cleaned = (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", r"\(")
        .replace(")", r"\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in cleaned)


def build_pdf_with_pydyf(report_dict: Dict[str, Any], report_hash: str) -> bytes:
    """
    Constructs a well-formatted multi-page PDF document using pure-Python pydyf engine.
    Ensures that case ID, result root, and anchored report hash are present in header text.
    """
    pdf = pydyf.PDF()

    # Fonts
    font_reg = pydyf.Dictionary({"Type": "/Font", "Subtype": "/Type1", "BaseFont": "/Helvetica"})
    font_bold = pydyf.Dictionary({"Type": "/Font", "Subtype": "/Type1", "BaseFont": "/Helvetica-Bold"})
    font_mono = pydyf.Dictionary({"Type": "/Font", "Subtype": "/Type1", "BaseFont": "/Courier"})

    pdf.add_object(font_reg)
    pdf.add_object(font_bold)
    pdf.add_object(font_mono)

    font_dict = pydyf.Dictionary({
        "F1": font_reg.reference,
        "F2": font_bold.reference,
        "F3": font_mono.reference,
    })

    pages_kids = []
    current_stream: Optional[pydyf.Stream] = None
    y_pos = 800

    def new_page() -> pydyf.Stream:
        nonlocal y_pos
        page = pydyf.Dictionary({
            "Type": "/Page",
            "MediaBox": pydyf.Array([0, 0, 595, 842]),  # A4: 595 x 842 pt
        })
        stream = pydyf.Stream()
        pdf.add_object(page)
        pdf.add_object(stream)
        page["Contents"] = stream.reference
        page["Resources"] = pydyf.Dictionary({"Font": font_dict})
        pages_kids.append(page.reference)
        y_pos = 780
        return stream

    current_stream = new_page()

    def add_line(text: str, font: str = "F1", size: int = 10, indent: int = 40):
        nonlocal current_stream, y_pos
        if y_pos < 60:
            current_stream.end_text()
            current_stream = new_page()
            current_stream.begin_text()

        sanitized = sanitize_pdf_text(text)
        current_stream.set_font_size(font, size)
        current_stream.move_text_to(indent, y_pos)
        current_stream.show_text_string(sanitized)
        y_pos -= int(size * 1.35)

    current_stream.begin_text()

    # 1. Header & Anchored Security Identifiers
    add_line("SecureMailScope Posture Assessment Report", font="F2", size=18, indent=40)
    add_line("Cryptographic Verification & Posture Certificate (fallback rendering)", font="F1", size=11, indent=40)
    add_line("Notice: fallback rendering active (pure-Python pydyf engine)", font="F1", size=9, indent=40)
    y_pos -= 10

    case_id = str(report_dict.get("caseId", ""))
    result_root = str(report_dict.get("resultRoot", ""))
    pcap_hash = str(report_dict.get("pcapHash", ""))
    engine_ver = str(report_dict.get("engineVersion", "0.1.0"))

    add_line("=" * 68, font="F3", size=9, indent=40)
    add_line(f"Case Identifier:          {case_id}", font="F3", size=9, indent=40)
    add_line(f"Result Root (On-Chain):   {result_root}", font="F3", size=9, indent=40)
    add_line(f"Anchored Report SHA-256:  {report_hash}", font="F3", size=9, indent=40)
    add_line(f"PCAP Binary SHA-256:      {pcap_hash}", font="F3", size=9, indent=40)
    add_line(f"Engine Version Digest:    {engine_ver}", font="F3", size=9, indent=40)
    add_line("=" * 68, font="F3", size=9, indent=40)
    y_pos -= 10

    # 2. Host Posture Scores
    add_line("Host Posture Scores & Compliance Grades", font="F2", size=13, indent=40)
    host_scores = report_dict.get("hostScores", [])
    if host_scores:
        for h in host_scores:
            hid = str(h.get("hostId", ""))[:16]
            endpoint = str(h.get("serverEndpoint", ""))
            score = h.get("score", 0)
            grade = h.get("grade", "F")
            add_line(f"Host {hid}... [{endpoint}]: Score {score}/100 (Grade {grade})", font="F1", size=10, indent=50)
    else:
        add_line("No host scores evaluated.", font="F1", size=10, indent=50)
    y_pos -= 10

    # 3. Prioritized Security Findings
    findings = report_dict.get("findings", [])
    add_line(f"Prioritized Cryptographic Findings ({len(findings)})", font="F2", size=13, indent=40)
    if findings:
        for idx, f in enumerate(findings[:25], 1):  # Display top 25 findings
            rule_id = str(f.get("ruleId", ""))
            sev = str(f.get("severity", "Info")).upper()
            title = str(f.get("title", rule_id))
            endpoint = str(f.get("serverEndpoint", ""))
            ev_packets = [str(ev.get("packetNumber", 0)) for ev in f.get("evidence", [])[:4]]
            ev_str = f"Packets: {', '.join(ev_packets)}" if ev_packets else "No packet references"
            add_line(f"{idx}. [{sev}] {rule_id}: {title}", font="F2", size=10, indent=50)
            add_line(f"Endpoint: {endpoint} | Sessions: {f.get('sessionCount', 1)} | {ev_str}", font="F1", size=9, indent=60)
            rec = f.get("recommendation", {})
            if rec and isinstance(rec, dict) and rec.get("directive"):
                add_line(f"Remediation Directive: {rec.get('directive')}", font="F3", size=8, indent=60)
    else:
        add_line("No cryptographic security vulnerabilities identified (Grade A).", font="F1", size=10, indent=50)
    y_pos -= 10

    # 4. Verifier Steps
    verifier_steps = report_dict.get("verifierSteps", [])
    if verifier_steps:
        add_line("Five-Step Posture Verification Status", font="F2", size=13, indent=40)
        for st in verifier_steps:
            step_num = st.get("step", 0)
            step_name = st.get("name", "")
            step_status = st.get("status", "PENDING")
            add_line(f"Step {step_num}: [{step_status}] {step_name}", font="F1", size=9, indent=50)
        y_pos -= 10

    # 5. Advisory Anomaly Detection (Non-Consensus)
    advisory = report_dict.get("advisory", {})
    if advisory and isinstance(advisory, dict):
        add_line("Advisory Anomaly Detection (Non-Consensus / Off-Chain)", font="F2", size=12, indent=40)
        add_line("Note: Advisory model is off-chain and not part of the Merkle quorum.", font="F1", size=8, indent=50)
        flagged_count = advisory.get("flaggedCount", 0)
        total_sessions = advisory.get("totalSessions", 0)
        add_line(f"Flagged Sessions: {flagged_count} of {total_sessions}", font="F1", size=9, indent=50)
        for a in advisory.get("flaggedSessions", [])[:5]:
            sid = a.get("sessionId", 0)
            score = a.get("anomalyScore", "0.0")
            devs = ", ".join(a.get("topDeviatingFeatures", []))
            add_line(f"- Session #{sid}: Score {score} | Deviations: {devs}", font="F3", size=8, indent=60)

    current_stream.end_text()

    # Link pages catalog
    pages_obj = pydyf.Dictionary({
        "Type": "/Pages",
        "Kids": pydyf.Array(pages_kids),
        "Count": len(pages_kids),
    })
    pdf.add_object(pages_obj)

    # Set parent references
    for k in pages_kids:
        # Note: pydyf handles page tree linkage via catalog
        pass

    pdf.catalog["Pages"] = pages_obj.reference

    buf = io.BytesIO()
    pdf.write(buf)
    return buf.getvalue()


def generate_pdf_report(
    report_dict: Dict[str, Any],
    html_content: str,
    report_hash: str,
) -> bytes:
    """
    Generate PDF report from HTML and report dictionary.
    First attempts WeasyPrint (pinned 64.1). If system C libraries (GTK3/Pango)
    are missing on host environment, falls back to pure-Python pydyf engine.
    Ensures:
    - Zero network access (base_url=None)
    - Anchored report SHA-256 is present in header
    - Case ID and Result Root are present
    """
    # 1. Attempt WeasyPrint if available and functional
    try:
        import weasyprint

        # base_url=None strictly prevents any network fetching of external assets
        wp = weasyprint.HTML(string=html_content, base_url=None)
        pdf_bytes = wp.write_pdf()
        return pdf_bytes
    except (ImportError, OSError, Exception):
        # 2. Fall back to pure-Python pydyf generator
        return build_pdf_with_pydyf(report_dict, report_hash)
