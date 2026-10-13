"""Lab Client for SecureMailScope.

CLI arguments:
  --scenario <ID>
  --mode starttls|implicit|plain
  --auth yes|no
  --max-tls 1.0|1.2|1.3
  --server-name <name>
  [--host <ip>]
  [--port <port>]
  [--ca-cert <path>]
"""
import argparse
import smtplib
import ssl
import sys
import time
from pathlib import Path

PLANTED_USER = "labuser"
PLANTED_PASS = "LabPass-123!"

TEST_MESSAGES = [
    (
        "sender1@lab.local",
        ["recipient1@lab.local"],
        "Subject: Lab Test Message 1\r\nFrom: sender1@lab.local\r\nTo: recipient1@lab.local\r\n\r\nTest payload 1 for scenario assessment.\r\n",
    ),
    (
        "sender2@lab.local",
        ["recipient2@lab.local"],
        "Subject: Lab Test Message 2\r\nFrom: sender2@lab.local\r\nTo: recipient2@lab.local\r\n\r\nTest payload 2 for scenario assessment.\r\n",
    ),
]


def create_ssl_context(max_tls: str, ca_cert_path: Path, server_name: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Configure TLS version bounds
    if max_tls == "1.0":
        if hasattr(ssl.TLSVersion, "TLSv1"):
            context.maximum_version = ssl.TLSVersion.TLSv1
            context.minimum_version = ssl.TLSVersion.TLSv1
            # Allow legacy security level for TLS 1.0 if supported by OpenSSL
            try:
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass
    elif max_tls == "1.2":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif max_tls == "1.3":
        context.maximum_version = ssl.TLSVersion.TLSv1_3

    if ca_cert_path and ca_cert_path.exists():
        context.load_verify_locations(str(ca_cert_path))
    else:
        # If no custom trust store, don't fail handshake outright so traffic is captured
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


def run_client(
    scenario: str,
    mode: str,
    auth: str,
    max_tls: str,
    server_name: str,
    host: str = "172.28.0.10",
    port: int = None,
    ca_cert: str = None,
):
    print(f"[*] Running lab client: scenario={scenario}, mode={mode}, auth={auth}, max_tls={max_tls}, server_name={server_name}")
    
    if port is None:
        port = 465 if mode == "implicit" else 25

    ca_path = Path(ca_cert) if ca_cert else Path(__file__).resolve().parents[1] / "ca" / "out" / "client_trust.crt"
    context = None
    if mode in ["starttls", "implicit"]:
        context = create_ssl_context(max_tls, ca_path, server_name)

    # Allow server time to bind if starting concurrently
    smtp = None
    for attempt in range(10):
        try:
            if mode == "implicit":
                smtp = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
            else:
                smtp = smtplib.SMTP(host, port, timeout=10)
            break
        except Exception as e:
            time.sleep(1)
    else:
        raise ConnectionError(f"Could not connect to {host}:{port}")

    try:
        smtp.ehlo(server_name)

        if mode == "starttls":
            print("[*] Sending STARTTLS...")
            smtp.starttls(context=context)
            smtp.ehlo(server_name)

        if auth == "yes":
            print(f"[*] Authenticating with planted credentials: {PLANTED_USER}")
            try:
                smtp.login(PLANTED_USER, PLANTED_PASS)
            except Exception as e:
                print(f"[!] Authentication result: {e}")

        # Send test messages
        for idx, (sender, recipients, msg) in enumerate(TEST_MESSAGES, start=1):
            print(f"[*] Sending test message {idx} from {sender} to {recipients}...")
            try:
                smtp.sendmail(sender, recipients, msg)
            except Exception as e:
                print(f"[!] Message delivery note: {e}")

        print("[+] Test messages completed.")
    finally:
        try:
            smtp.quit()
        except Exception:
            try:
                smtp.close()
            except Exception:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureMailScope Lab Client")
    parser.add_argument("--scenario", required=True, help="Scenario identifier (e.g. S01a)")
    parser.add_argument("--mode", required=True, choices=["starttls", "implicit", "plain"], help="Transport mode")
    parser.add_argument("--auth", required=True, choices=["yes", "no"], help="Whether to authenticate")
    parser.add_argument("--max-tls", default="1.2", choices=["1.0", "1.2", "1.3"], help="Maximum TLS version allowed")
    parser.add_argument("--server-name", default="172.28.0.10", help="Target server name")
    parser.add_argument("--host", default="172.28.0.10", help="Mailserver host IP")
    parser.add_argument("--port", type=int, default=None, help="Mailserver port")
    parser.add_argument("--ca-cert", default=None, help="Path to CA certificate trust store")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        run_client(
            scenario=args.scenario,
            mode=args.mode,
            auth=args.auth,
            max_tls=args.max_tls,
            server_name=args.server_name,
            host=args.host,
            port=args.port,
            ca_cert=args.ca_cert,
        )
        return 0
    except Exception as e:
        sys.stderr.write(f"Error running lab client: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
