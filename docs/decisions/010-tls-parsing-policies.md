# Decision 010: TLS Record Layer and Handshake Parsing Policies

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` section 4.4 and Prompt 5.4 specify TLS parsing up to the point of encryption. The parser processes client-to-server and server-to-client reassembled byte streams starting at their respective TLS start offsets. To ensure robust, crash-free operation on arbitrary network captures (including malformed, fuzz-tested, or truncated traffic), boundary checks, encryption cutoff points, and error reporting conventions must be clearly documented.

## Decisions

1. **Encryption Cutoff Conditions**:
   - In TLS 1.2 and earlier: Handshake record inspection ceases after a `ChangeCipherSpec` record (`content_type = 20`) is observed from the respective direction.
   - In TLS 1.3: As defined in RFC 8446, all handshake messages following the `ServerHello` (e.g. `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`) are encrypted under handshake traffic keys. Therefore, handshake parsing on the server stream stops immediately after the `ServerHello` message.
   - Any records appearing after the encryption cutoff are counted in `encryptedRecordCount` without attempting decryption.

2. **Error Handling & Exception Suppression**:
   - All length fields (record lengths, handshake message lengths, extension lengths, vector lengths) are strictly bounds-checked.
   - If a length exceeds the available bytes or stream boundaries, a `TlsParseError(kind="truncated" | "malformed", offset=..., frame=...)` entry is appended to the handshake record, and parsing stops gracefully.
   - The parser never raises uncaught exceptions out of the module.

3. **Message Types Parsed**:
   - `ClientHello` (1): extracts legacy version, random (32 bytes), session ID, cipher suite codes, and extensions (`server_name`, `supported_groups`, `ec_point_formats`, `signature_algorithms`, `alpn`, `supported_versions`, `key_share`, `psk_key_exchange_modes`).
   - `ServerHello` (2): extracts version, random, session ID, selected cipher code, and extensions (`supported_versions`, `key_share`, `pre_shared_key`).
   - `HelloRetryRequest`: detected when `ServerHello.random` equals the 32-byte constant defined in RFC 8446 Section 4.1.3 (`cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`).
   - `Certificate` (11): extracts the ordered list of raw DER certificate byte blobs.
   - `ServerKeyExchange` (12): stores the raw parameter bytes and determines parameter type (`ec_diffie_hellman`, `diffie_hellman`, or `rsa`).
   - `CertificateStatus` (22): stores OCSP status type and raw response.
   - `Alert` (21): if observed in cleartext prior to encryption, records fatal/warning alerts.

4. **Negotiated Version Resolution**:
   - If the `ServerHello` includes the `supported_versions` extension (type 43 / `0x002b`), the version value inside that extension is the negotiated version.
   - Otherwise, the legacy `version` field of the `ServerHello` represents the negotiated version.

5. **Data Structures**:
   - The parser outputs a `TlsHandshake` dataclass consolidating parsed client and server messages, negotiated parameters, and parse errors without interpreting cipher properties or validating certificates (reserved for Prompts 5.5 and 5.6).

## Consequences
- Guarantees crash immunity against malformed, oversized, or truncated TLS streams.
- Preserves accurate frame and offset mappings for diagnostic and security auditing.
- Matches Wireshark/tshark dissections across all lab captures.
