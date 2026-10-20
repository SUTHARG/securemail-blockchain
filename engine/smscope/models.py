"""Typed dataclass models for SecureMailScope pipeline."""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Union, Dict, Any


@dataclass
class CleartextAuth:
    mechanism: str
    packetNumber: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "packetNumber": self.packetNumber,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CleartextAuth":
        return cls(
            mechanism=data["mechanism"],
            packetNumber=int(data["packetNumber"]),
        )


@dataclass
class StarttlsInfo:
    offered: bool
    attempted: bool
    outcome: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offered": self.offered,
            "attempted": self.attempted,
            "outcome": self.outcome,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StarttlsInfo":
        return cls(
            offered=bool(data["offered"]),
            attempted=bool(data["attempted"]),
            outcome=str(data["outcome"]),
        )


@dataclass
class TlsInfo:
    certObservable: bool
    version: Optional[str] = None
    cipherSuiteCode: Optional[int] = None
    cipherSuiteName: Optional[str] = None
    kxType: Optional[str] = None
    kxGroupOrDhBits: Optional[Union[int, str]] = None
    forwardSecrecy: Optional[bool] = None
    resumed: Optional[bool] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    sni: Optional[str] = None
    certNotObservableReason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "cipherSuiteCode": self.cipherSuiteCode,
            "cipherSuiteName": self.cipherSuiteName,
            "kxType": self.kxType,
            "kxGroupOrDhBits": self.kxGroupOrDhBits,
            "forwardSecrecy": self.forwardSecrecy,
            "resumed": self.resumed,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "sni": self.sni,
            "certObservable": self.certObservable,
            "certNotObservableReason": self.certNotObservableReason,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["TlsInfo"]:
        if data is None:
            return None
        return cls(
            version=data.get("version"),
            cipherSuiteCode=data.get("cipherSuiteCode"),
            cipherSuiteName=data.get("cipherSuiteName"),
            kxType=data.get("kxType"),
            kxGroupOrDhBits=data.get("kxGroupOrDhBits"),
            forwardSecrecy=data.get("forwardSecrecy"),
            resumed=data.get("resumed"),
            ja3=data.get("ja3"),
            ja3s=data.get("ja3s"),
            sni=data.get("sni"),
            certObservable=bool(data["certObservable"]),
            certNotObservableReason=data.get("certNotObservableReason"),
        )


@dataclass
class CertificateInfo:
    sha256: str
    subject: str
    issuer: str
    notBefore: int
    notAfter: int
    keyAlgorithm: str
    keySize: int
    signatureAlgorithm: str
    san: List[str]
    isCa: bool
    verdicts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "notBefore": self.notBefore,
            "notAfter": self.notAfter,
            "keyAlgorithm": self.keyAlgorithm,
            "keySize": self.keySize,
            "signatureAlgorithm": self.signatureAlgorithm,
            "san": list(self.san),
            "isCa": self.isCa,
            "verdicts": list(self.verdicts),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CertificateInfo":
        return cls(
            sha256=str(data["sha256"]),
            subject=str(data["subject"]),
            issuer=str(data["issuer"]),
            notBefore=int(data["notBefore"]),
            notAfter=int(data["notAfter"]),
            keyAlgorithm=str(data["keyAlgorithm"]),
            keySize=int(data["keySize"]),
            signatureAlgorithm=str(data["signatureAlgorithm"]),
            san=list(data.get("san", [])),
            isCa=bool(data["isCa"]),
            verdicts=list(data.get("verdicts", [])),
        )


@dataclass
class SessionRecord:
    sessionId: int
    clientEndpoint: str
    serverEndpoint: str
    protocol: str
    protocolSource: str
    transportMode: str
    streamComplete: bool
    firstPacketTs: int
    starttls: StarttlsInfo
    cleartextAuth: List[CleartextAuth] = field(default_factory=list)
    tls: Optional[TlsInfo] = None
    certificates: List[CertificateInfo] = field(default_factory=list)
    clientTlsStartOffset: Optional[int] = None
    serverTlsStartOffset: Optional[int] = None
    stream: Optional[Any] = field(default=None, repr=False)
    starttls_offered_frame: Optional[int] = None
    starttls_attempted_frame: Optional[int] = None
    starttls_outcome_frame: Optional[int] = None

    streamContiguous: Optional[bool] = None
    streamTerminated: Optional[bool] = None
    confirmedComplete: Optional[bool] = None

    def __post_init__(self):
        """
        Stream Completion Semantics:
        - streamContiguous: True if every delivered byte follows TCP sequence space continuously without gaps or drops.
        - streamTerminated: True if capture contains evidence that connection ended (FIN delivered in both directions or RST).
        - confirmedComplete: True if stream is BOTH contiguous AND cleanly terminated teardown was observed.
        - streamComplete: Backwards-compatible contiguity flag.
        """
        if self.streamContiguous is None:
            if self.stream is not None:
                self.streamContiguous = getattr(self.stream, "contiguous", getattr(self.stream, "complete", self.streamComplete))
            else:
                self.streamContiguous = self.streamComplete
        if self.streamTerminated is None:
            if self.stream is not None:
                self.streamTerminated = getattr(self.stream, "terminated", False)
            else:
                self.streamTerminated = False
        if self.confirmedComplete is None:
            if self.stream is not None:
                self.confirmedComplete = getattr(self.stream, "confirmed_complete", bool(self.streamContiguous and self.streamTerminated))
            else:
                self.confirmedComplete = bool(self.streamContiguous and self.streamTerminated)

    @property
    def tlsStartOffset(self) -> Optional[int]:
        return self.clientTlsStartOffset

    def to_dict(self, include_extended: bool = False) -> Dict[str, Any]:
        """
        Serializes SessionRecord.
        When include_extended is True, also serializes streamContiguous, streamTerminated, and confirmedComplete.
        Defaults to False to preserve baseline schema/test compatibility. Use to_extended_dict() for full telemetry.
        """
        d = {
            "sessionId": self.sessionId,
            "clientEndpoint": self.clientEndpoint,
            "serverEndpoint": self.serverEndpoint,
            "protocol": self.protocol,
            "protocolSource": self.protocolSource,
            "transportMode": self.transportMode,
            "streamComplete": self.streamComplete,
            "firstPacketTs": self.firstPacketTs,
            "starttls": self.starttls.to_dict(),
            "cleartextAuth": [c.to_dict() for c in self.cleartextAuth],
            "tls": self.tls.to_dict() if self.tls is not None else None,
            "certificates": [c.to_dict() for c in self.certificates],
        }
        if include_extended:
            d["streamContiguous"] = bool(self.streamContiguous)
            d["streamTerminated"] = bool(self.streamTerminated)
            d["confirmedComplete"] = bool(self.confirmedComplete)
        return d

    def to_extended_dict(self) -> Dict[str, Any]:
        """Serialize with explicit completion, contiguity, and termination flags."""
        return self.to_dict(include_extended=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionRecord":
        stream_comp = bool(data["streamComplete"])
        stream_cont = bool(data.get("streamContiguous", stream_comp))
        stream_term = bool(data.get("streamTerminated", False))
        confirmed_comp = bool(data.get("confirmedComplete", stream_cont and stream_term))

        return cls(
            sessionId=int(data["sessionId"]),
            clientEndpoint=str(data["clientEndpoint"]),
            serverEndpoint=str(data["serverEndpoint"]),
            protocol=str(data["protocol"]),
            protocolSource=str(data["protocolSource"]),
            transportMode=str(data["transportMode"]),
            streamComplete=stream_comp,
            firstPacketTs=int(data["firstPacketTs"]),
            starttls=StarttlsInfo.from_dict(data["starttls"]),
            cleartextAuth=[CleartextAuth.from_dict(c) for c in data.get("cleartextAuth", [])],
            tls=TlsInfo.from_dict(data.get("tls")),
            certificates=[CertificateInfo.from_dict(c) for c in data.get("certificates", [])],
            streamContiguous=stream_cont,
            streamTerminated=stream_term,
            confirmedComplete=confirmed_comp,
        )


@dataclass
class Evidence:
    sessionId: int
    packetNumber: int
    note: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sessionId": self.sessionId,
            "packetNumber": self.packetNumber,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(
            sessionId=int(data["sessionId"]),
            packetNumber=int(data["packetNumber"]),
            note=str(data["note"]),
        )


@dataclass
class Finding:
    findingId: str
    ruleId: str
    severity: str
    serverEndpoint: str
    sortedSessionIds: List[int]
    sessionCount: int
    evidence: List[Evidence]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findingId": self.findingId,
            "ruleId": self.ruleId,
            "severity": self.severity,
            "serverEndpoint": self.serverEndpoint,
            "sortedSessionIds": list(self.sortedSessionIds),
            "sessionCount": self.sessionCount,
            "evidence": [e.to_dict() for e in self.evidence],
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            findingId=str(data["findingId"]),
            ruleId=str(data["ruleId"]),
            severity=str(data["severity"]),
            serverEndpoint=str(data["serverEndpoint"]),
            sortedSessionIds=[int(s) for s in data["sortedSessionIds"]],
            sessionCount=int(data["sessionCount"]),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", [])],
            details=dict(data.get("details", {})),
        )


@dataclass
class HostScore:
    hostId: str
    serverEndpoint: str
    score: int
    grade: str
    findingsDigest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostId": self.hostId,
            "serverEndpoint": self.serverEndpoint,
            "score": self.score,
            "grade": self.grade,
            "findingsDigest": self.findingsDigest,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostScore":
        return cls(
            hostId=str(data["hostId"]),
            serverEndpoint=str(data["serverEndpoint"]),
            score=int(data["score"]),
            grade=str(data["grade"]),
            findingsDigest=str(data["findingsDigest"]),
        )


@dataclass
class CaseManifest:
    caseId: str
    pcapSha256: str
    engineVersion: str
    rulesetHash: str
    resultRoot: str
    findingCount: int
    hostCount: int
    reportHash: Optional[str] = None
    txHashes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caseId": self.caseId,
            "pcapSha256": self.pcapSha256,
            "engineVersion": self.engineVersion,
            "rulesetHash": self.rulesetHash,
            "resultRoot": self.resultRoot,
            "findingCount": self.findingCount,
            "hostCount": self.hostCount,
            "reportHash": self.reportHash,
            "txHashes": dict(self.txHashes),
        }
