"""Command-line interface for SecureMailScope engine."""
import argparse
import sys
from pathlib import Path

from engine.smscope.ingest import ingest, EmptyCaptureError, IngestError
from engine.smscope.protocols import process_protocols
from engine.smscope.tls import process_tls
from engine.smscope.certs import process_certs
from engine.smscope.rules import evaluate_rules
from engine.smscope.results import process_results


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser for smscope CLI."""
    parser = argparse.ArgumentParser(
        prog="smscope",
        description="SecureMailScope: Cryptographic Security Posture Assessment Engine",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze email PCAP traffic and output cryptographic findings and proofs",
    )
    analyze_parser.add_argument(
        "pcap",
        type=str,
        help="Path to email PCAP capture file",
    )
    analyze_parser.add_argument(
        "--org-secret-hex",
        required=True,
        type=str,
        help="Hex-encoded organization secret for host pseudonymization",
    )
    analyze_parser.add_argument(
        "--out",
        required=True,
        type=str,
        help="Output directory to write canonical results",
    )
    analyze_parser.add_argument(
        "--case-id",
        type=str,
        default="",
        help="Optional case identifier (defaults to empty string)",
    )
    analyze_parser.add_argument(
        "--trust-store",
        type=str,
        default=None,
        help="Optional path to custom CA trust store file or directory",
    )
    analyze_parser.add_argument(
        "--ruleset",
        type=str,
        default=None,
        help="Optional path to ruleset.yaml file",
    )

    return parser


def main(args=None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.command == "analyze":
        pcap_path = Path(parsed.pcap)
        out_dir = Path(parsed.out)
        trust_store_path = Path(parsed.trust_store) if parsed.trust_store else None
        ruleset_path = Path(parsed.ruleset) if parsed.ruleset else None

        # Validate org secret hex
        try:
            org_secret = bytes.fromhex(parsed.org_secret_hex)
        except ValueError:
            sys.stderr.write(f"Error: Invalid hex string for --org-secret-hex: {parsed.org_secret_hex}\n")
            return 1

        from engine.smscope.limits import LimitExceededError

        try:
            # 1. Ingest stage
            try:
                streams, pcap_sha256 = ingest(pcap_path)
            except EmptyCaptureError as e:
                sys.stderr.write(f"Error: No mail sessions found in capture: {e}\n")
                return 2
            except FileNotFoundError as e:
                sys.stderr.write(f"Error: {e}\n")
                return 1
            except IngestError as e:
                sys.stderr.write(f"Error: Ingest failed: {e}\n")
                return 1

            # 2. Protocols stage
            sessions = process_protocols(streams)
            if not sessions:
                sys.stderr.write(f"Error: No mail sessions found in capture: {pcap_path}\n")
                return 2

            # 3. TLS analysis stage
            sessions = process_tls(sessions)

            # 4. Certificates stage
            sessions = process_certs(sessions, trust_store_path)

            # 5. Rule evaluation stage
            findings = evaluate_rules(sessions, ruleset_path)

            # 6. Scoring, Merkle packaging, and canonical output generation
            process_results(
                sessions=sessions,
                findings=findings,
                org_secret=org_secret,
                pcap_sha256=pcap_sha256,
                out_dir=out_dir,
                case_id=parsed.case_id,
            )

            return 0
        except LimitExceededError as e:
            sys.stderr.write(f"Limit exceeded: {e.limit_name} - {e.detail}\n")
            return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
