"""Ruleset hashing calculation for SecureMailScope."""
import hashlib
from pathlib import Path
from typing import Optional


def compute_ruleset_hash(ruleset_path: Optional[Path] = None, rules_dir: Optional[Path] = None) -> str:
    """Compute rulesetHash = SHA-256(bytes of ruleset.yaml + bytes of rules/ files sorted by path)."""
    if ruleset_path is None:
        ruleset_path = Path(__file__).resolve().parents[3] / "ruleset" / "ruleset.yaml"
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parent

    h = hashlib.sha256()
    with open(ruleset_path, "rb") as f:
        h.update(f.read())

    # Find all source files under engine/smscope/rules/ sorted by posix path
    rule_files = []
    for p in rules_dir.rglob("*"):
        if p.is_file() and not p.name.endswith(".pyc") and "__pycache__" not in p.parts:
            rel_path = p.relative_to(rules_dir).as_posix()
            rule_files.append((rel_path, p))

    rule_files.sort(key=lambda item: item[0])

    for _, file_path in rule_files:
        with open(file_path, "rb") as f:
            h.update(f.read())

    return h.hexdigest()
