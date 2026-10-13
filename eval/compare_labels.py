"""Compare engine evaluation against ground-truth lab scenario labels."""
import json
from pathlib import Path
import sys
from typing import Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.smscope.certs.analyze import analyze_certificate_chain
from engine.smscope.ingest.reassembly import reassemble_pcap
from engine.smscope.models import SessionRecord, Finding
from engine.smscope.protocols.smtp import track_session
from engine.smscope.rules import evaluate_rules
from engine.smscope.tls.handshake import parse_tls_handshake
from engine.smscope.tls.negotiation import negotiate_tls
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
LABELS_DIR = REPO_ROOT / "lab" / "labels"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"


def analyze_pcap(pcap_path: Path, trust_store: Path = TRUST_STORE_PATH) -> List[Finding]:
    """Execute complete analysis pipeline from PCAP to findings."""
    streams, _ = reassemble_pcap(pcap_path)
    sessions: List[SessionRecord] = []

    for stream in streams:
        sess = track_session(stream)

        # Inspect TLS handshake if TLS transport mode or TLS start offset identified
        is_tls = (
            sess.transportMode in ("starttls", "tls", "implicitTls")
            or sess.clientTlsStartOffset is not None
            or sess.protocol in ("smtps", "imaps")
        )
        if is_tls:
            hs = parse_tls_handshake(stream, sess.clientTlsStartOffset, sess.serverTlsStartOffset)
            if hs:
                sess.tls = negotiate_tls(hs)
                if hs.certificates:
                    sess.certificates = analyze_certificate_chain(
                        hs.certificates,
                        capture_ts_sec=sess.firstPacketTs,
                        sni=hs.sni,
                        trust_store_path=trust_store if trust_store.exists() else None,
                    )
        sessions.append(sess)

    return evaluate_rules(sessions)


def main() -> int:
    """Compare all captures in lab/captures/ against lab/labels/."""
    pcap_files = sorted(CAPTURES_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"Error: No PCAP files found in {CAPTURES_DIR}", file=sys.stderr)
        return 1

    total_scenarios = 0
    passed_scenarios = 0
    total_tp = 0
    total_fp = 0
    total_fn = 0
    discrepancies: List[str] = []

    print("=" * 80)
    print(f"{'Scenario':<10} | {'Status':<6} | {'Precision':<9} | {'Recall':<6} | {'Expected':<18} | {'Actual':<18}")
    print("-" * 80)

    for pcap_path in pcap_files:
        scenario_id = pcap_path.stem
        label_path = LABELS_DIR / f"{scenario_id}.json"
        if not label_path.exists():
            print(f"Warning: Label file {label_path.name} not found; skipping", file=sys.stderr)
            continue

        total_scenarios += 1
        with open(label_path, "r", encoding="utf-8") as f:
            label_data = json.load(f)

        server_endpoint = label_data["serverEndpoint"]
        expected_findings: Set[Tuple[str, str]] = {
            (ef["ruleId"], server_endpoint) for ef in label_data.get("expectedFindings", [])
        }

        actual_findings_list = analyze_pcap(pcap_path)
        actual_findings: Set[Tuple[str, str]] = {
            (f.ruleId, f.serverEndpoint) for f in actual_findings_list
        }

        tp = len(expected_findings & actual_findings)
        fp = len(actual_findings - expected_findings)
        fn = len(expected_findings - actual_findings)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        if not expected_findings and not actual_findings:
            precision = 1.0
            recall = 1.0
            is_match = True
        else:
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            is_match = (expected_findings == actual_findings)

        status_str = "PASS" if is_match else "FAIL"
        if is_match:
            passed_scenarios += 1
        else:
            unexpected = sorted(list(actual_findings - expected_findings))
            missing = sorted(list(expected_findings - actual_findings))
            err_msg = f"{scenario_id}: Unexpected findings: {unexpected}, Missing findings: {missing}"
            discrepancies.append(err_msg)

        exp_str = ",".join(sorted(r for r, _ in expected_findings)) or "(none)"
        act_str = ",".join(sorted(r for r, _ in actual_findings)) or "(none)"

        print(
            f"{scenario_id:<10} | {status_str:<6} | {precision:>8.2f}  | {recall:>6.2f} | {exp_str:<18} | {act_str:<18}"
        )

    print("=" * 80)
    print(f"Summary: {passed_scenarios}/{total_scenarios} scenarios passed exact match.")
    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else (1.0 if total_fp == 0 else 0.0)
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else (1.0 if total_fn == 0 else 0.0)
    print(f"Overall Metrics: TP={total_tp}, FP={total_fp}, FN={total_fn} | Precision={overall_p:.2f}, Recall={overall_r:.2f}")

    if discrepancies:
        print("\nDiscrepancies identified:", file=sys.stderr)
        for d in discrepancies:
            print(f"  - {d}", file=sys.stderr)
        return 1

    print("\nAll Tier 1 scenarios matched labels exactly with zero discrepancies.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
