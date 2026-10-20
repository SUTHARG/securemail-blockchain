"""Regression tests proving backend tests cannot write to data/smscope.db or data/cases/."""
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import create_case, get_case
from backend.storage import get_case_dir, write_case_json

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_DATA_DIR = REPO_ROOT / "data"
REAL_DB = REAL_DATA_DIR / "smscope.db"
REAL_CASES_DIR = REAL_DATA_DIR / "cases"


def test_representative_backend_operations_do_not_pollute_real_data():
    """Verify case creation and storage access are completely redirected away from real data/."""
    # Ensure config paths are NOT pointing to real data
    assert config.DB_PATH.resolve() != REAL_DB.resolve()
    assert config.CASES_DIR.resolve() != REAL_CASES_DIR.resolve()

    # Capture initial row count and directory listing of real data
    initial_db_cases = set()
    if REAL_DB.exists():
        conn = sqlite3.connect(REAL_DB)
        initial_db_cases = set(r[0] for r in conn.execute("SELECT id FROM cases").fetchall())
        conn.close()

    initial_case_dirs = set()
    if REAL_CASES_DIR.exists():
        initial_case_dirs = set(d.name for d in REAL_CASES_DIR.iterdir() if d.is_dir())

    # Perform representative backend test actions
    case_id = f"test_isolation_check_{uuid.uuid4().hex[:12]}"
    pcap_sha = hashlib.sha256(b"isolation_test_pcap").hexdigest()

    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="uploaded")
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy_encrypted_data")
    write_case_json(case_id, "manifest.json", {"caseId": case_id, "pcapSha256": pcap_sha})

    # The case MUST exist in the isolated test environment
    assert get_case(case_id) is not None
    assert (case_dir / "manifest.json").exists()

    # The case MUST NOT exist in the real database or real cases directory
    if REAL_DB.exists():
        conn = sqlite3.connect(REAL_DB)
        current_db_cases = set(r[0] for r in conn.execute("SELECT id FROM cases").fetchall())
        conn.close()
        assert current_db_cases == initial_db_cases, "New case leaked into real data/smscope.db!"

    if REAL_CASES_DIR.exists():
        current_case_dirs = set(d.name for d in REAL_CASES_DIR.iterdir() if d.is_dir())
        assert current_case_dirs == initial_case_dirs, "New directory leaked into real data/cases/!"
        assert not (REAL_CASES_DIR / case_id).exists()
