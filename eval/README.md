# SecureMailScope: Evaluation & Ground-Truth Extraction

This directory contains ground-truth extraction tools and reference datasets used to validate the forensic analysis engine against independent packet dissections from `tshark` (Wireshark).

---

## 1. Ground-Truth Extractor (`eval/tshark_truth.py`)

`eval/tshark_truth.py` runs `tshark` against a raw PCAP file to extract canonical ground truth per TCP connection, keyed deterministically by 5-tuple and first frame number: `(client endpoint, server endpoint, first frame number)`.

### Extracted Information
- **TCP Stream Reassembly**: Raw client and server byte streams (`tshark -z follow,tcp,raw,<stream>`).
- **SMTP Protocol Events**: Parsed commands (`EHLO`, `STARTTLS`, `AUTH`, `MAIL FROM`, etc.) and response codes (`220`, `250`, etc.).
- **TLS Handshake Parameters**:
  - Handshake message types list.
  - ClientHello legacy version.
  - `supported_versions` extension values.
  - Offered cipher suite codes.
  - Server Name Indication (SNI).
  - ServerHello selected cipher suite and version.
  - JA3 and JA3S fingerprints (if exposed by installed tshark).
  - SHA-256 fingerprints of presented X.509 certificates.
- **Environment Metadata**: Exact `tshark` version string and input PCAP SHA-256.

---

## 2. Usage

To extract ground truth for a single PCAP capture:
```bash
python eval/tshark_truth.py lab/captures/S01a.pcap --out eval/truth/S01a.json
```

If `--out` is omitted, the ground-truth JSON is written to `eval/truth/<pcap_stem>.json` by default.

### Batch Regeneration for All Captures
```bash
# Windows PowerShell
Get-ChildItem lab\captures\*.pcap | ForEach-Object {
    python eval\tshark_truth.py $_.FullName
}

# Linux / Bash
for pcap in lab/captures/*.pcap; do
    python eval/tshark_truth.py "$pcap"
done
```

---

## 3. Directory Layout

- `eval/tshark_truth.py`: Ground-truth extractor script.
- `eval/truth/`: Directory containing generated ground-truth JSON files for all lab scenarios (`S01a.json`, `S05.json`, `X02.json`, etc.).
- `eval/README.md`: Documentation for evaluation workflows.
