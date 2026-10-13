"""Generates engine/smscope/tls/ciphers_generated.py from official IANA registry."""
import csv
import io
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

IANA_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
OUTPUT_FILE = Path(__file__).resolve().parents[1] / "engine" / "smscope" / "tls" / "ciphers_generated.py"


def parse_cipher_properties(name: str):
    """Parses properties from standard IANA TLS cipher suite name."""
    if not name or "Reserved" in name or "Unassigned" in name:
        return None

    # TLS 1.3 suites (RFC 8446)
    if name in (
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ):
        bulk = name.replace("TLS_", "").rsplit("_", 1)[0]
        return {
            "name": name,
            "kxType": "tls13",
            "authentication": "tls13",
            "bulkCipher": bulk,
            "macOrAead": "AEAD",
            "forwardSecrecy": True,
            "weakClass": None,
        }

    # Weak class determination
    weak_class = None
    if "NULL" in name:
        weak_class = "NULL"
    elif "EXPORT" in name or "_EXP_" in name:
        weak_class = "EXPORT"
    elif "anon" in name or "AODH" in name or "ADH" in name or "AECDH" in name:
        weak_class = "anon"
    elif "RC4" in name:
        weak_class = "RC4"
    elif "3DES" in name or "DES_CBC3" in name:
        weak_class = "3DES"
    elif "_DES_" in name or "DES_CBC" in name:
        weak_class = "DES"

    if "_WITH_" not in name:
        return {
            "name": name,
            "kxType": "other",
            "authentication": "other",
            "bulkCipher": "unknown",
            "macOrAead": "unknown",
            "forwardSecrecy": None,
            "weakClass": weak_class,
        }

    prefix, suffix = name.split("_WITH_", 1)
    prefix_clean = prefix.replace("TLS_", "").replace("SSL_", "")

    # Key Exchange and Authentication
    kx_type = "other"
    auth = "other"

    if "anon" in prefix_clean:
        kx_type = "anon"
        auth = "anon"
    elif prefix_clean.startswith("ECDHE_"):
        kx_type = "ECDHE"
        auth = prefix_clean.split("_", 1)[1]
    elif prefix_clean.startswith("DHE_"):
        kx_type = "DHE"
        auth = prefix_clean.split("_", 1)[1]
    elif prefix_clean.startswith("ECDH_"):
        kx_type = "ECDH"
        auth = prefix_clean.split("_", 1)[1]
    elif prefix_clean.startswith("DH_"):
        kx_type = "DH"
        auth = prefix_clean.split("_", 1)[1]
    elif prefix_clean.startswith("RSA_"):
        kx_type = "RSA"
        auth = prefix_clean.split("_", 1)[1]
    elif prefix_clean == "RSA":
        kx_type = "RSA"
        auth = "RSA"
    elif prefix_clean.startswith("PSK"):
        kx_type = "PSK"
        auth = "PSK"
    elif "PSK" in prefix_clean:
        kx_type = prefix_clean.split("_")[0]
        auth = "PSK"

    # Forward Secrecy
    if kx_type in ("DHE", "ECDHE", "tls13"):
        forward_secrecy = True
    elif kx_type in ("RSA", "DH", "ECDH", "PSK"):
        forward_secrecy = False
    else:
        forward_secrecy = None

    # Bulk Cipher and MAC/AEAD
    if "GCM" in suffix or "CCM" in suffix or "POLY1305" in suffix:
        mac_aead = "AEAD"
        bulk_cipher = suffix.rsplit("_", 1)[0] if suffix.count("_") >= 2 else suffix
    else:
        parts = suffix.rsplit("_", 1)
        if len(parts) == 2:
            bulk_cipher = parts[0]
            mac_aead = parts[1]
        else:
            bulk_cipher = suffix
            mac_aead = "unknown"

    return {
        "name": name,
        "kxType": kx_type,
        "authentication": auth,
        "bulkCipher": bulk_cipher,
        "macOrAead": mac_aead,
        "forwardSecrecy": forward_secrecy,
        "weakClass": weak_class,
    }


def main():
    print(f"[+] Fetching IANA TLS Parameters from: {IANA_URL}")
    retrieval_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        req = urllib.request.Request(IANA_URL, headers={"User-Agent": "SecureMailScope-Engine/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            csv_text = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Network fetch failed: {e}. Checking for local fallback...")
        sys.exit(1)

    reader = csv.reader(io.StringIO(csv_text))
    header = next(reader)

    ciphers_by_code = {}

    for row in reader:
        if len(row) < 2:
            continue
        val_str = row[0].strip()
        desc = row[1].strip()

        # Matches "0x00,0x2F" or similar
        m = re.match(r"^0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})$", val_str)
        if not m:
            continue

        b1 = int(m.group(1), 16)
        b2 = int(m.group(2), 16)
        code = (b1 << 8) | b2

        props = parse_cipher_properties(desc)
        if props:
            ciphers_by_code[code] = props

    print(f"[+] Parsed {len(ciphers_by_code)} valid cipher suites.")

    lines = [
        f'"""IANA TLS Cipher Suites registry (generated).',
        f'Source URL: {IANA_URL}',
        f'Retrieved on: {retrieval_date}',
        f'Do not edit manually; re-generate with scripts/gen_cipher_table.py',
        f'"""',
        'from typing import Dict, Any, Optional',
        '',
        'CIPHER_SUITES: Dict[int, Dict[str, Any]] = {',
    ]

    for code in sorted(ciphers_by_code.keys()):
        p = ciphers_by_code[code]
        fs_str = "True" if p["forwardSecrecy"] is True else ("False" if p["forwardSecrecy"] is False else "None")
        wc_str = f'"{p["weakClass"]}"' if p["weakClass"] else "None"
        code_hex = f"0x{code:04X}"

        lines.append(f'    {code_hex}: {{')
        lines.append(f'        "name": "{p["name"]}",')
        lines.append(f'        "kxType": "{p["kxType"]}",')
        lines.append(f'        "authentication": "{p["authentication"]}",')
        lines.append(f'        "bulkCipher": "{p["bulkCipher"]}",')
        lines.append(f'        "macOrAead": "{p["macOrAead"]}",')
        lines.append(f'        "forwardSecrecy": {fs_str},')
        lines.append(f'        "weakClass": {wc_str},')
        lines.append(f'    }},')

    lines.append('}')
    lines.append('')
    lines.append('def get_cipher_properties(code: int) -> Optional[Dict[str, Any]]:')
    lines.append('    return CIPHER_SUITES.get(code)')
    lines.append('')

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
