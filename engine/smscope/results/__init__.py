"""Results library, canonical JSON, hashing, Merkle tree and pipeline module."""
from engine.smscope.results.canonical import canonical_json
from engine.smscope.results.hashing import (
    finding_id,
    findings_digest,
    host_id,
    host_id_hex,
    finding_leaf,
    host_score_leaf,
    node,
)
from engine.smscope.results.merkle import MerkleTree, build_tree, verify
from engine.smscope.results.pipeline import (
    score_host,
    compute_exposure_factor,
    compute_grade,
    process_results,
    SEVERITY_WEIGHTS,
)

__all__ = [
    "canonical_json",
    "finding_id",
    "findings_digest",
    "host_id",
    "host_id_hex",
    "finding_leaf",
    "host_score_leaf",
    "node",
    "MerkleTree",
    "build_tree",
    "verify",
    "score_host",
    "compute_exposure_factor",
    "compute_grade",
    "process_results",
    "SEVERITY_WEIGHTS",
]
