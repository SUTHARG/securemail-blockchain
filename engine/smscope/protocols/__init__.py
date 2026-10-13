"""Protocols stage for SecureMailScope."""
from typing import List, Union
from engine.smscope.ingest.reassembly import Stream
from engine.smscope.models import SessionRecord
from engine.smscope.protocols.identify import ProtocolIdentification, identify
from engine.smscope.protocols.smtp import track_smtp, track_session, track_imap, track_pop3


def process_protocols(items: Union[List[Stream], List[SessionRecord]]) -> List[SessionRecord]:
    """Identifies mail protocols and tracks sessions for all streams."""
    if not items:
        return []
    if isinstance(items[0], SessionRecord):
        return items

    sessions: List[SessionRecord] = []
    for stream in items:
        ident = identify(stream)
        if ident.protocol in ("smtp", "smtps"):
            sess = track_smtp(stream, ident)
            sess.stream = stream
            sessions.append(sess)
        elif ident.protocol == "imap":
            sess = track_imap(stream)
            sess.stream = stream
            sessions.append(sess)
        elif ident.protocol == "pop3":
            sess = track_pop3(stream)
            sess.stream = stream
            sessions.append(sess)
    return sessions
