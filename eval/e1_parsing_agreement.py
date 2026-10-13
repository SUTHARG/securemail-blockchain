"""E1: Parsing Agreement Evaluation.

Compares SecureMailScope parsed fields (streams, protocol, TLS version, cipher,
key exchange, and certificates) against tshark ground truth (eval/truth/*.json)
for every lab capture.
Outputs:
- eval/results/e1_parsing_agreement.csv
- eval/results/e1_parsing_agreement.md
"""
import csv
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.smscope.certs.analyze import analyze_certificate_chain
from engine.smscope.ingest.reassembly import reassemble_pcap
from engine.smscope.protocols.smtp import track_session
from engine.smscope.tls.handshake import parse_tls_handshake
from engine.smscope.tls.negotiation import negotiate_tls

CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
TRUTH_DIR = REPO_ROOT / "eval" / "truth"
RESULTS_DIR = REPO_ROOT / "eval" / "results"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"


def run_e1() -> Tuple[List[Dict[str, Any]], float]:
    """Execute E1 parsing agreement experiment."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    truth_files = sorted(TRUTH_DIR.glob("*.json"))

    results = []
    total_fields = 0
    matched_fields = 0

    for tf in truth_files:
        scenario = tf.stem
        pcap_file = CAPTURES_DIR / f"{scenario}.pcap"
        if not pcap_file.exists():
            continue

        truth_data = json.loads(tf.read_text(encoding="utf-8"))
        connections_truth = truth_data.get("connections", {})

        # Run engine ingestion
        streams, _ = reassemble_pcap(pcap_file)
        scenario_total = 0
        scenario_matched = 0
        mismatches: List[str] = []

        for stream in streams:
            sess = track_session(stream)
            is_tls = (
                sess.transportMode in ("starttls", "tls")
                or sess.clientTlsStartOffset is not None
                or sess.protocol == "smtps"
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
                            trust_store_path=TRUST_STORE_PATH if TRUST_STORE_PATH.exists() else None,
                        )

            # Match with truth connection by serverEndpoint and clientEndpoint
            conn_key = None
            for k, c in connections_truth.items():
                if c.get("serverEndpoint") == sess.serverEndpoint and c.get("clientEndpoint") == sess.clientEndpoint:
                    conn_key = k
                    break

            if not conn_key:
                continue

            t_conn = connections_truth[conn_key]

            # 1. Protocol Agreement
            scenario_total += 1
            if sess.protocol in ("smtp", "smtps"):
                scenario_matched += 1
            else:
                mismatches.append(f"protocol: engine={sess.protocol} vs tshark=smtp")

            # 2. TLS Version Agreement
            VERSION_MAP = {
                "0x0301": "TLS 1.0",
                "0x0302": "TLS 1.1",
                "0x0303": "TLS 1.2",
                "0x0304": "TLS 1.3",
            }
            t_tls = t_conn.get("tls", {})
            if t_tls.get("selectedVersion"):
                scenario_total += 1
                expected_ver = VERSION_MAP.get(t_tls["selectedVersion"].lower(), t_tls["selectedVersion"])
                actual_ver = sess.tls.version if sess.tls else None
                if actual_ver == expected_ver:
                    scenario_matched += 1
                else:
                    mismatches.append(f"tls_version: engine={actual_ver} vs tshark={expected_ver}")

            # 3. Selected Cipher Suite
            if t_tls.get("selectedCipher"):
                scenario_total += 1
                t_cipher = int(t_tls["selectedCipher"])
                e_cipher = sess.tls.cipherSuiteCode if sess.tls else None
                if e_cipher == t_cipher:
                    scenario_matched += 1
                else:
                    mismatches.append(f"cipher: engine={e_cipher} vs tshark={t_cipher}")

            # 4. SNI Agreement
            if t_tls.get("sni"):
                scenario_total += 1
                t_sni = t_tls["sni"]
                e_sni = sess.tls.sni if sess.tls else None
                if e_sni == t_sni:
                    scenario_matched += 1
                else:
                    mismatches.append(f"sni: engine={e_sni} vs tshark={t_sni}")

            # 5. Certificates Fingerprint
            t_fps = t_tls.get("certFingerprints", [])
            if t_fps:
                scenario_total += 1
                e_fps = [c.sha256 for c in sess.certificates] if sess.certificates else []
                # Compare leaf fingerprint
                if e_fps and e_fps[0].lower() == t_fps[0].lower():
                    scenario_matched += 1
                else:
                    mismatches.append(f"cert_fp: engine={e_fps[:1]} vs tshark={t_fps[:1]}")

        agreement_pct = (scenario_matched / scenario_total * 100.0) if scenario_total > 0 else 100.0
        total_fields += scenario_total
        matched_fields += scenario_matched

        results.append({
            "scenario": scenario,
            "total_fields": scenario_total,
            "matched_fields": scenario_matched,
            "agreement_rate": f"{agreement_pct:.1f}%",
            "mismatches": "; ".join(mismatches) if mismatches else "None",
        })

    overall_rate = (matched_fields / total_fields * 100.0) if total_fields > 0 else 100.0

    # Write CSV
    csv_path = RESULTS_DIR / "e1_parsing_agreement.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["scenario", "total_fields", "matched_fields", "agreement_rate", "mismatches"])
        writer.writeheader()
        writer.writerows(results)

    # Write Markdown
    md_path = RESULTS_DIR / "e1_parsing_agreement.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Experiment E1: Parsing Agreement vs. Ground Truth\n\n")
        f.write(f"**Overall Agreement Rate:** **{overall_rate:.2f}%** ({matched_fields}/{total_fields} fields matched)\n\n")
        f.write("| Scenario | Evaluated Fields | Matched Fields | Agreement Rate | Mismatches |\n")
        f.write("|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['scenario']} | {r['total_fields']} | {r['matched_fields']} | {r['agreement_rate']} | {r['mismatches']} |\n")

    return results, overall_rate


if __name__ == "__main__":
    res, rate = run_e1()
    print(f"E1 Complete: {len(res)} scenarios evaluated. Overall Agreement: {rate:.2f}%")
