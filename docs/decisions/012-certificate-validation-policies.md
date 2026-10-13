# Decision 012: Certificate Analysis, Chain Building, and Validation Policies

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` Section 4.5 and Prompt 5.6 require passive, deterministic evaluation of X.509 certificates observable in TLS 1.2 and earlier sessions. To guarantee consistency across independent validator nodes without runtime network dependencies, the analysis engine must parse certificates, verify signatures, build certification paths, and evaluate validity intervals strictly using packet capture timestamps.

## Decisions

1. **Passive, Offline X.509 Parsing**:
   - Implemented via the pinned `cryptography` library in `engine/smscope/certs/analyze.py`.
   - The engine never queries online CRL distribution points or OCSP responders at runtime, adhering strictly to Rule 5 (`AGENT_RULES.md`).
   - Recorded fields: `sha256` (lowercase hex), `subject`, `issuer`, `notBefore` and `notAfter` (integer epoch seconds), `keyAlgorithm` (`RSA`, `EC`, `Ed25519`, `Ed448`, `DSA`), `keySize` (modulus length or curve size), `signatureAlgorithm`, `san` (dNSName and iPAddress), `isCa` (BasicConstraints CA boolean), and `verdicts` (sorted list of strings).

2. **Capture Timestamp Validity Reference**:
   - Certificate validity (`notBefore` and `notAfter`) is strictly evaluated against the capture timestamp (integer seconds) of the packet carrying the `Certificate` handshake message, NEVER against the local machine clock (`datetime.now()` / `time.time()`), adhering strictly to Rule 2 (`AGENT_RULES.md`).
   - Verdicts: `"expired"` if `capture_ts > notAfter`; `"notYetValid"` if `capture_ts < notBefore`.

3. **Weak Key and Signature Thresholds**:
   - `"weakKey"`: Assigned if RSA public key size $< 2048$ bits, or EC curve size $< 224$ bits.
   - `"weakSignature"`: Assigned if the certificate's signature algorithm uses MD5 or SHA-1 (evaluated on non-root certificates; root trust anchors are not penalized as their signature is not verified against an external authority).

4. **Deterministic Chain Building and Trust Store Anchoring**:
   - Trust store directory or file is loaded from configuration (`trustStorePath`, default `lab/ca/out/client_trust.crt`). Certificates in directories are loaded in deterministic sorted filename order.
   - Chains are reconstructed from presented certificates and anchored in the trust store by iteratively locating the issuer, verifying the cryptographic signature using the issuer's public key, and enforcing `isCa = True` on all intermediate and root authorities.
   - Chain verdicts:
     - `"valid"`: Cryptographic path successfully verified to an anchor in the trust store and not expired at capture time.
     - `"unknownIssuer"`: Incomplete chain or trust anchor absent from the trust store. Per specification, `unknownIssuer` is never conflated with invalid/corrupt certificates.
     - `"selfSigned"`: Leaf certificate whose subject equals its issuer and whose signature validates with its own public key.

5. **Server Name Indication (SNI) Matching**:
   - Compared strictly against Subject Alternative Names (`san`):
     - For DNS hostnames: exact case-insensitive match or single-label leftmost wildcard match (`*.example.com` matches `host.example.com`, but not `sub.host.example.com` or `example.com`).
     - For IP literals: matched against `iPAddress` SAN entries.
   - Strictly prohibits fallback to Subject Common Name (`CN`), complying with RFC 6125.
   - If SNI is omitted in `ClientHello`, the name check is marked not evaluable (no mismatch verdict generated).
   - If SNI is present and does not match any SAN entry, `"hostnameMismatch"` is recorded.

6. **Verdict Sorting**:
   - All verdicts per certificate are deduplicated and output as a deterministic, lexicographically sorted list of strings.

## Consequences
- Guarantees byte-identical certificate metadata and verdicts across all validator environments.
- Matches OpenSSL CLI verification behavior (`openssl x509 -text`, `openssl verify -CAfile ...`) across all test scenarios.
- Feeds deterministic findings directly to Tier 1 detection rules R11, R12, R13, R15, and R16.
