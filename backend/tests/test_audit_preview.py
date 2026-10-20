"""Unit tests for scripts/audit_test_reg_cases.py verifying both preview states:
1. When verified backups are present.
2. When no backup exists.
3. Ensuring preview mode remains strictly read-only in both states.
"""
import io
import sys
from pathlib import Path
import pytest

import scripts.audit_test_reg_cases as audit_script

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_audit_preview_with_existing_backup(tmp_path, monkeypatch, capsys):
    """Preview mode detects and reports existing verified backups without writing."""
    import sqlite3
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    db_file = backup_dir / "smscope_backup_20261020_000000.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE cases (id TEXT)")
    conn.commit()
    conn.close()

    monkeypatch.setattr(audit_script, "BACKUPS_DIR", backup_dir)
    audit_script.audit_test_records(preview_only=True)
    captured = capsys.readouterr().out

    assert "[PREVIEW MODE ONLY]" in captured
    assert "Verified existing backup(s) found" in captured
    assert "smscope_backup_" in captured
    assert "integrity: ok" in captured


def test_audit_preview_with_no_backups(tmp_path, monkeypatch, capsys):
    """Preview mode accurately reports when no backups exist in the target directory."""
    empty_backup_dir = tmp_path / "empty_backups"
    empty_backup_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(audit_script, "BACKUPS_DIR", empty_backup_dir)

    audit_script.audit_test_records(preview_only=True)
    captured = capsys.readouterr().out

    assert "[PREVIEW MODE ONLY]" in captured
    assert "No previous backup files found" in captured
    # Ensure no files were created in the empty backup directory
    assert list(empty_backup_dir.iterdir()) == []
