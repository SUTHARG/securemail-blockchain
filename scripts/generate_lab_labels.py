"""Generate label JSON files for all SecureMailScope lab scenarios."""
import json
from pathlib import Path

LABELS = [
    {
        "scenario": "S01a",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [],
        "comment": "Valid TLS 1.2 with ECDHE and valid 2048-bit certificate; clean session",
    },
    {
        "scenario": "S01b",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R19"}],
        "comment": "TLS 1.3 negotiated; encrypted certificates not observable",
    },
    {
        "scenario": "S02",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R06"}, {"ruleId": "R09"}],
        "comment": "TLS 1.0 negotiated; static RSA key exchange lacks forward secrecy",
    },
    {
        "scenario": "S03",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R08"}, {"ruleId": "R09"}],
        "comment": "3DES cipher suite negotiated; static RSA key exchange lacks forward secrecy",
    },
    {
        "scenario": "S04",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R11"}],
        "comment": "Expired certificate at capture time",
    },
    {
        "scenario": "S05",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R01"}, {"ruleId": "R02"}],
        "comment": "No STARTTLS offered and cleartext authentication used",
    },
    {
        "scenario": "S06",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R03"}],
        "comment": "STARTTLS offered but client ignored and continued in plaintext",
    },
    {
        "scenario": "S07",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R09"}],
        "comment": "Static RSA key exchange (AES256-GCM-SHA384) without forward secrecy",
    },
    {
        "scenario": "S08",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R12"}],
        "comment": "Weak RSA 1024-bit public key",
    },
    {
        "scenario": "S09",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R13"}],
        "comment": "Weak SHA-1 signature algorithm on certificate",
    },
    {
        "scenario": "S10",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R16"}],
        "comment": "Self-signed leaf certificate",
    },
    {
        "scenario": "S11",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R15"}],
        "comment": "Unknown issuer / certificate from CA absent from trust store",
    },
    {
        "scenario": "S12",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [{"ruleId": "R19"}],
        "comment": "TLS 1.3 only; encrypted certificates not observable",
    },
    {
        "scenario": "S13",
        "serverEndpoint": "172.28.0.10:465",
        "expectedFindings": [],
        "comment": "Implicit TLS on port 465, TLS 1.2, valid certificate; clean session",
    },
    {
        "scenario": "X01",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [],
        "comment": "Stress capture with packet reordering and duplication; clean session",
    },
    {
        "scenario": "X02",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [],
        "comment": "Stress capture with TCP MSS clamped to 100; clean session",
    },
    {
        "scenario": "X03",
        "serverEndpoint": "172.28.0.10:25",
        "expectedFindings": [],
        "comment": "Stress capture with 5% packet loss; clean session",
    },
]

def main():
    repo_root = Path(__file__).resolve().parents[1]
    labels_dir = repo_root / "lab" / "labels"
    labels_dir.mkdir(parents=True, exist_ok=True)

    for item in LABELS:
        file_path = labels_dir / f"{item['scenario']}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(item, f, indent=2)
        print(f"[+] Wrote {file_path.name}")

if __name__ == "__main__":
    main()
