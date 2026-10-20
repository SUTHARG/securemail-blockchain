"""Scoring, Merkle packaging, and canonical output generation for SecureMailScope."""
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from engine.smscope.models import SessionRecord, Finding, HostScore, CaseManifest
from engine.smscope.results.canonical import canonical_json
from engine.smscope.results.hashing import (
    host_id_hex,
    findings_digest,
    finding_leaf,
    host_score_leaf,
)
from engine.smscope.results.merkle import MerkleTree
from engine.smscope.rules.ruleset_hash import compute_ruleset_hash

SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 20,
    "Medium": 8,
    "Low": 2,
    "Info": 0,
}


def compute_exposure_factor(session_count: int) -> int:
    """Integer exposure factor from affected session count (Section 4.7)."""
    if session_count <= 1:
        return 1
    elif session_count <= 9:
        return 2
    else:
        return 3


def compute_grade(score: int) -> str:
    """Grade boundaries (Section 4.7)."""
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def score_host(
    server_endpoint: str,
    findings: List[Finding],
    org_secret: bytes,
) -> HostScore:
    """Calculate integer score and grade for a single host."""
    host_findings = [f for f in findings if f.serverEndpoint == server_endpoint]
    total_deductions = 0
    finding_ids = []

    for f in host_findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0)
        exposure = compute_exposure_factor(f.sessionCount)
        total_deductions += weight * exposure
        finding_ids.append(f.findingId)

    score = max(0, 100 - total_deductions)
    grade = compute_grade(score)
    h_id = host_id_hex(org_secret, server_endpoint)
    f_digest = findings_digest(finding_ids)

    return HostScore(
        hostId=h_id,
        serverEndpoint=server_endpoint,
        score=score,
        grade=grade,
        findingsDigest=f_digest,
    )


def process_results(
    sessions: List[SessionRecord],
    findings: List[Finding],
    org_secret: bytes,
    pcap_sha256: str,
    out_dir: Path,
    case_id: str = "",
    ruleset_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Score hosts, build Merkle tree, and write canonical output files."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Identify all unique serverEndpoints from sessions
    endpoints = sorted(list({s.serverEndpoint for s in sessions}))

    # 2. Score each host
    host_scores: List[HostScore] = [
        score_host(endpoint, findings, org_secret) for endpoint in endpoints
    ]
    # Sort host scores by hostId for determinism
    host_scores.sort(key=lambda h: h.hostId)

    # 3. Build Merkle leaves
    leaves_bytes: List[bytes] = []
    leaves_info: List[Dict[str, str]] = []

    # Finding leaves
    for f in findings:
        f_dict = f.to_dict()
        f_leaf = finding_leaf(f_dict)
        leaves_bytes.append(f_leaf)
        leaves_info.append({
            "id": f.findingId,
            "leafHash": f_leaf.hex(),
            "type": "finding",
        })

    # Host score leaves
    host_leaf_map: Dict[str, bytes] = {}
    for h in host_scores:
        h_leaf = host_score_leaf(h.hostId, h.findingsDigest, h.score)
        leaves_bytes.append(h_leaf)
        host_leaf_map[h.hostId] = h_leaf
        leaves_info.append({
            "id": h.hostId,
            "leafHash": h_leaf.hex(),
            "type": "host_score",
        })

    # 4. Build Merkle tree
    tree = MerkleTree(leaves_bytes)
    result_root = tree.root_hex

    # Sort leaves by leafHash ascending (matches Merkle tree leaf byte order)
    sorted_leaves_info = sorted(leaves_info, key=lambda item: item["leafHash"])

    # 5. Compute per-host inclusion proofs
    host_proofs: Dict[str, List[str]] = {}
    for h in host_scores:
        h_leaf = host_leaf_map[h.hostId]
        proof_hex = tree.proof_hex(h_leaf)
        host_proofs[h.hostId] = proof_hex

    # 6. Build Manifest
    if ruleset_hash is None:
        ruleset_hash = compute_ruleset_hash()

    engine_version = os.environ.get("ENGINE_IMAGE_DIGEST", "dev")

    manifest = CaseManifest(
        caseId=case_id,
        pcapSha256=pcap_sha256,
        engineVersion=engine_version,
        rulesetHash=ruleset_hash,
        resultRoot=result_root,
        findingCount=len(findings),
        hostCount=len(host_scores),
        reportHash=None,
        txHashes={},
    )

    # 7. Write all output files in canonical JSON
    legacy_sessions = os.environ.get("SMSCOPE_LEGACY_SESSIONS", "").lower() in ("1", "true", "yes")
    sessions_payload = [
        s.to_dict(include_extended=not legacy_sessions)
        for s in sorted(sessions, key=lambda s: s.sessionId)
    ]
    findings_payload = [f.to_dict() for f in sorted(findings, key=lambda f: f.findingId)]
    host_scores_payload = [h.to_dict() for h in host_scores]
    result_payload = {
        "leaves": sorted_leaves_info,
        "resultRoot": result_root,
    }
    manifest_payload = manifest.to_dict()

    file_payloads = {
        "sessions.json": sessions_payload,
        "findings.json": findings_payload,
        "host_scores.json": host_scores_payload,
        "result.json": result_payload,
        "host_proofs.json": host_proofs,
        "manifest.json": manifest_payload,
    }

    for filename, payload in file_payloads.items():
        canonical_bytes = canonical_json(payload)
        with open(out_dir / filename, "wb") as f:
            f.write(canonical_bytes)

    return {
        "resultRoot": result_root,
        "manifest": manifest_payload,
        "hostScores": host_scores_payload,
        "findings": findings_payload,
    }
