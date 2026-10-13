"""X.509 certificate chain parsing, validation, and forensic analysis."""
import ipaddress
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa

from engine.smscope.models import CertificateInfo

OID_SHORT = {
    x509.NameOID.COMMON_NAME: "CN",
    x509.NameOID.ORGANIZATION_NAME: "O",
    x509.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    x509.NameOID.COUNTRY_NAME: "C",
    x509.NameOID.STATE_OR_PROVINCE_NAME: "ST",
    x509.NameOID.LOCALITY_NAME: "L",
}


def format_name(name: x509.Name) -> str:
    """Formats an X.509 Name into standard RFC/OpenSSL string representation."""
    parts = []
    for attr in name:
        short_key = OID_SHORT.get(attr.oid, attr.oid._name)
        parts.append(f"{short_key}={attr.value}")
    return ", ".join(parts)


def extract_key_info(cert: x509.Certificate) -> Tuple[str, int, Optional[str]]:
    """Extracts keyAlgorithm, keySize in bits, and curve name (if EC)."""
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size, None
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "EC", pubkey.curve.key_size, pubkey.curve.name
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", 448, "ed448"
    elif isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size, None
    return type(pubkey).__name__, 0, None


def extract_san(cert: x509.Certificate) -> Tuple[List[str], List[str], List[str]]:
    """Extracts all SAN strings, dNSNames, and iPAddresses."""
    all_sans: List[str] = []
    san_dns: List[str] = []
    san_ips: List[str] = []

    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = ext.value
        for name in san_val:
            if isinstance(name, x509.DNSName):
                dns_str = name.value
                san_dns.append(dns_str)
                all_sans.append(dns_str)
            elif isinstance(name, x509.IPAddress):
                ip_str = str(name.value)
                san_ips.append(ip_str)
                all_sans.append(ip_str)
    except x509.ExtensionNotFound:
        pass

    return sorted(all_sans), san_dns, san_ips


def check_sni_match(san_dns: List[str], san_ips: List[str], sni: str) -> bool:
    """
    Checks if SNI matches SANs per RFC 6125:
    - IP literals match against iPAddress SANs.
    - DNS names match dNSName SANs with single-label leftmost wildcard (*.) only.
    - No fallback to CN.
    """
    try:
        target_ip = ipaddress.ip_address(sni)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        for ip_str in san_ips:
            try:
                if ipaddress.ip_address(ip_str) == target_ip:
                    return True
            except ValueError:
                if ip_str == sni:
                    return True
        return False
    else:
        sni_lower = sni.lower()
        sni_parts = sni_lower.split(".")
        for dns in san_dns:
            dns_lower = dns.lower()
            if dns_lower == sni_lower:
                return True
            if dns_lower.startswith("*."):
                wildcard_suffix = dns_lower[2:]
                # Single-label leftmost wildcard:
                # E.g. *.example.com matches mail.example.com, not sub.mail.example.com or example.com
                if len(sni_parts) >= 2 and "." not in sni_parts[0]:
                    if ".".join(sni_parts[1:]) == wildcard_suffix:
                        return True
        return False


def verify_signature(cert: x509.Certificate, issuer_pubkey: Any) -> bool:
    """Verifies that cert's signature was signed by issuer_pubkey."""
    try:
        if isinstance(issuer_pubkey, rsa.RSAPublicKey):
            pad = padding.PKCS1v15()
            sig_oid_name = cert.signature_algorithm_oid._name.lower()
            if "pss" in sig_oid_name and cert.signature_hash_algorithm is not None:
                pad = padding.PSS(
                    mgf=padding.MGF1(cert.signature_hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                )
            issuer_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                pad,
                cert.signature_hash_algorithm,
            )
            return True
        elif isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
            if cert.signature_hash_algorithm is not None:
                issuer_pubkey.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
                return True
        elif isinstance(issuer_pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_pubkey.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        elif isinstance(issuer_pubkey, dsa.DSAPublicKey):
            if cert.signature_hash_algorithm is not None:
                issuer_pubkey.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm,
                )
                return True
    except Exception:
        return False
    return False


def is_self_signed(cert: x509.Certificate) -> bool:
    """Returns True if subject equals issuer and signature verifies with own public key."""
    if cert.subject != cert.issuer:
        return False
    return verify_signature(cert, cert.public_key())


def is_ca_cert(cert: x509.Certificate) -> bool:
    """Returns True if BasicConstraints indicates CA."""
    try:
        bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(bc.ca)
    except x509.ExtensionNotFound:
        return False


def load_trust_store(trust_store_path: Optional[Union[str, Path]] = None) -> List[x509.Certificate]:
    """
    Loads trusted root certificates from a file or directory in deterministic sorted order.
    """
    if trust_store_path is None:
        trust_store_path = Path("lab/ca/out/client_trust.crt")
    else:
        trust_store_path = Path(trust_store_path)

    trusted: List[x509.Certificate] = []
    if not trust_store_path.exists():
        return trusted

    if trust_store_path.is_file():
        content = trust_store_path.read_bytes()
        try:
            trusted.extend(x509.load_pem_x509_certificates(content))
        except Exception:
            try:
                trusted.append(x509.load_der_x509_certificate(content))
            except Exception:
                pass
    elif trust_store_path.is_dir():
        for f in sorted(trust_store_path.iterdir()):
            if f.suffix.lower() in [".crt", ".pem"]:
                content = f.read_bytes()
                try:
                    trusted.extend(x509.load_pem_x509_certificates(content))
                except Exception:
                    try:
                        trusted.append(x509.load_der_x509_certificate(content))
                    except Exception:
                        pass

    return trusted


def analyze_certificate_chain(
    der_certs: List[bytes],
    capture_ts_sec: int,
    sni: Optional[str] = None,
    trust_store_path: Optional[Union[str, Path]] = None,
) -> List[CertificateInfo]:
    """
    Parses and verifies certificate list from TLS Certificate message.
    Evaluates validity against capture_ts_sec strictly, never machine clock.
    """
    if not der_certs:
        return []

    parsed_certs: List[x509.Certificate] = []
    from engine.smscope.limits import check_certificate_length
    for b in der_certs:
        check_certificate_length(len(b))
        try:
            parsed_certs.append(x509.load_der_x509_certificate(b))
        except Exception:
            continue

    if not parsed_certs:
        return []

    trusted_roots = load_trust_store(trust_store_path)
    trusted_fingerprints: Set[str] = {
        r.fingerprint(hashes.SHA256()).hex().lower() for r in trusted_roots
    }

    result: List[CertificateInfo] = []

    for idx, cert in enumerate(parsed_certs):
        try:
            is_leaf = (idx == 0)
            sha256 = cert.fingerprint(hashes.SHA256()).hex().lower()
            subject = format_name(cert.subject)
            issuer = format_name(cert.issuer)
            not_before = int(cert.not_valid_before_utc.timestamp())
            not_after = int(cert.not_valid_after_utc.timestamp())
            key_algo, key_size, _ = extract_key_info(cert)
            sig_algo = cert.signature_algorithm_oid._name
            san_strings, san_dns, san_ips = extract_san(cert)
            is_ca = is_ca_cert(cert)

            verdicts: List[str] = []

            # 1. Validity interval vs capture timestamp
            if capture_ts_sec > not_after:
                verdicts.append("expired")
            if capture_ts_sec < not_before:
                verdicts.append("notYetValid")

            # 2. Key strength
            if key_algo == "RSA" and key_size < 2048:
                verdicts.append("weakKey")
            elif key_algo == "EC" and key_size < 224:
                verdicts.append("weakKey")

            # 3. Weak signature (MD5 or SHA-1 on non-root cert)
            sig_lower = sig_algo.lower()
            if any(bad in sig_lower for bad in ["md5", "sha1", "sha-1"]):
                if not is_ca or cert.subject != cert.issuer:
                    verdicts.append("weakSignature")

            # 4. Name check against SNI (evaluated on leaf certificate only)
            if is_leaf and sni is not None:
                if not check_sni_match(san_dns, san_ips, sni):
                    verdicts.append("hostnameMismatch")

            # 5. Chain verification and trust store anchoring
            self_signed = is_self_signed(cert)
            if self_signed:
                verdicts.append("selfSigned")
                if sha256 in trusted_fingerprints:
                    if "expired" not in verdicts and "notYetValid" not in verdicts:
                        verdicts.append("valid")
                else:
                    verdicts.append("unknownIssuer")
            else:
                # Build chain to trusted root
                current = cert
                anchored = False
                visited: Set[bytes] = {current.signature}

                while True:
                    # Check if current cert is issued by a trusted root
                    issuer_root = None
                    for root in trusted_roots:
                        if root.subject == current.issuer and verify_signature(current, root.public_key()):
                            issuer_root = root
                            break

                    if issuer_root is not None:
                        anchored = True
                        break

                    # Otherwise check if issuer is in presented certificates
                    next_cert = None
                    for cand in parsed_certs:
                        if cand.subject == current.issuer and is_ca_cert(cand):
                            if verify_signature(current, cand.public_key()):
                                next_cert = cand
                                break

                    if next_cert is not None and next_cert.signature not in visited:
                        visited.add(next_cert.signature)
                        current = next_cert
                    else:
                        break

                if anchored:
                    if "expired" not in verdicts and "notYetValid" not in verdicts:
                        verdicts.append("valid")
                else:
                    verdicts.append("unknownIssuer")

            result.append(
                CertificateInfo(
                    sha256=sha256,
                    subject=subject,
                    issuer=issuer,
                    notBefore=not_before,
                    notAfter=not_after,
                    keyAlgorithm=key_algo,
                    keySize=key_size,
                    signatureAlgorithm=sig_algo,
                    san=san_strings,
                    isCa=is_ca,
                    verdicts=sorted(list(set(verdicts))),
                )
            )
        except Exception:
            continue

    return result
