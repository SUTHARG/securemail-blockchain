from pathlib import Path
from typing import List, Optional, Union
from engine.smscope.models import SessionRecord
from engine.smscope.certs.analyze import (
    analyze_certificate_chain,
    check_sni_match,
    format_name,
    load_trust_store,
)

DEFAULT_TRUST_STORE = Path(__file__).resolve().parents[3] / "lab" / "ca" / "out" / "client_trust.crt"


def process_certs(
    sessions: List[SessionRecord],
    trust_store_path: Optional[Union[str, Path]] = None,
) -> List[SessionRecord]:
    """Parses and verifies certificate chains against packet capture timestamp."""
    if trust_store_path is None:
        trust_store_path = DEFAULT_TRUST_STORE if DEFAULT_TRUST_STORE.exists() else None

    for sess in sessions:
        raw_certs = getattr(sess, "_raw_certificates", None)
        sni = getattr(sess, "_sni", None)
        if raw_certs:
            sess.certificates = analyze_certificate_chain(
                raw_certs,
                capture_ts_sec=sess.firstPacketTs,
                sni=sni,
                trust_store_path=trust_store_path,
            )
    return sessions
