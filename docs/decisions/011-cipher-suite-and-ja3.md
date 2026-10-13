# Decision 011: Cipher Suite Taxonomy, JA3 Fingerprinting, and Resumption Logic

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` sections 4.4 and 4.6 and Prompt 5.5 require deterministic evaluation of cipher suites, key exchange mechanisms, forward secrecy properties, TLS session resumption, and JA3/JA3S client/server fingerprinting. To guarantee reproducible outputs across independent validator nodes without runtime network dependencies, the registry of TLS cipher suites is pre-compiled from official IANA data, and the evaluation rules for forward secrecy, weak ciphers, and fingerprinting are formally specified.

## Decisions

1. **Offline IANA Cipher Suites Registry**:
   - The cipher suite table is generated offline via `scripts/gen_cipher_table.py` fetching the official IANA TLS Parameters CSV (`https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv`) and committed to `engine/smscope/tls/ciphers_generated.py`.
   - The analysis engine never downloads external resources at runtime, strictly complying with `AGENT_RULES.md` rule 5 (passive engine).
   - Each cipher suite entry defines: `name`, `kxType`, `authentication`, `bulkCipher`, `macOrAead`, `forwardSecrecy`, and `weakClass`.

2. **Key Exchange and Forward Secrecy Taxonomy**:
   - `kxType` categories: `RSA`, `DHE`, `ECDHE`, `DH`, `ECDH`, `PSK`, `anon`, `tls13`, and `other`.
   - `forwardSecrecy`:
     - `True` for ephemeral key exchanges: `DHE`, `ECDHE`, and TLS 1.3 (`tls13`).
     - `False` for static key exchanges: `RSA`, static `DH`, static `ECDH`, and plain `PSK`.
     - `None` for unclassified or unknown cipher suites.
   - `weakClass`:
     - `NULL`: unencrypted suites containing `NULL`.
     - `EXPORT`: export-grade suites containing `EXPORT` or `EXP`.
     - `anon`: anonymous unauthenticated suites containing `anon` or `AODH` or `ADH` or `AECDH`.
     - `RC4`: suites using the RC4 stream cipher.
     - `DES`: single DES block cipher suites.
     - `3DES`: Triple-DES block cipher suites (`3DES`, `DES-CBC3`, `EDH-DSS-DES-CBC3`).
     - `None`: standard strong suites.

3. **Key Exchange Group and DH Parameters**:
   - `kxGroupOrDhBits`:
     - In TLS 1.3: the selected group integer code from `ServerHello.key_share` (or named curve ID).
     - In TLS 1.2 ECDHE: the named curve code from `ServerKeyExchange`.
     - In TLS 1.2 DHE: the bit length of the prime modulus $p$ from `ServerKeyExchange`.
     - In all other configurations (e.g. static RSA): `0`.

4. **Session Resumption and Certificate Observability**:
   - `resumed`:
     - TLS 1.2: `True` if `ServerHello.session_id` echoes a non-empty client `session_id` AND no `Certificate` handshake message was presented.
     - TLS 1.3: `True` if `ServerHello` contains the `pre_shared_key` extension.
     - `False` otherwise.
   - `certObservable`:
     - `False` with reason `"tls13"` if negotiated version is TLS 1.3 (`0x0304`).
     - `False` with reason `"resumed"` if session was resumed without full certificate exchange.
     - `True` with reason `None` when cleartext certificates are observable on the wire.

5. **JA3 and JA3S Fingerprinting**:
   - JA3 format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats` joined by dashes in decimal.
   - JA3S format: `SSLVersion,Cipher,Extensions` joined by dashes in decimal.
   - RFC 8701 GREASE values (`0x0a0a`, `0x1a1a`, `0x2a2a`, `0x3a3a`, `0x4a4a`, `0x5a5a`, `0x6a6a`, `0x7a7a`, `0x8a8a`, `0x9a9a`, `0xaaaa`, `0xbaba`, `0xcaca`, `0xdada`, `0xeaea`, `0xfafa`) are filtered out of all components before hashing.
   - Hash algorithm: MD5 of the ASCII string representation, lowercase hex.
   - MD5 is used strictly as the standardized fingerprint format (per the JA3 specification) and not for security verification.

## Consequences
- Guarantees byte-identical fingerprinting and negotiation metadata across all captures.
- Matches Wireshark/tshark field extractions for JA3, JA3S, and cipher parameters.
- Establishes precise indicators for downstream security posture rules (R06, R07, R08, R09, R10, R19).
