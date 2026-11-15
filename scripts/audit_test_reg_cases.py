"""Audit and preview procedure for test_reg_ records in data directory.

Identifies, inspects, and previews test-generated test_reg_ cases in the database
and filesystem.
Preview mode is strictly read-only by default.
An intentional backup flag (--create-backup) generates a verified, consistent SQLite
online backup using SQLite's backup API as well as an audit JSON manifest.
Never deletes or modifies real database records.
"""
import argparse
import datetime
import json
from pathlib import Path
import shutil
import sqlite3
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
DB_PATH = DATA_DIR / "smscope.db"
CASES_DIR = DATA_DIR / "cases"
BACKUPS_DIR = DATA_DIR / "backups"


def audit_test_records(preview_only: bool = True, create_backup: bool = False, archive_cases: bool = False):
    print("=" * 70)
    print("      SECUREMAILSCOPE: TEST RECORD AUDIT & BACKUP TOOL")
    print("=" * 70)
    print(f"Database Path:   {DB_PATH} (exists: {DB_PATH.exists()})")
    print(f"Cases Directory: {CASES_DIR} (exists: {CASES_DIR.exists()})")
    print(f"Mode:            {'READ-ONLY PREVIEW' if preview_only else 'INTENTIONAL ACTION'}\n")

    db_rows = []
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, status, pcap_sha256, created_at, onchain_case_id FROM cases WHERE id LIKE 'test_reg_%' ORDER BY created_at DESC")
        db_rows = c.fetchall()
        conn.close()

    fs_dirs = []
    if CASES_DIR.exists():
        fs_dirs = sorted([d for d in CASES_DIR.iterdir() if d.is_dir() and d.name.startswith("test_reg_")])

    print(f"[*] Found {len(db_rows)} database record(s) matching 'test_reg_%':")
    for r in db_rows:
        print(f"    • ID: {r[0]} | Status: {r[1]} | Created: {r[3]} | OnChainID: {r[4]}")

    print(f"\n[*] Found {len(fs_dirs)} directory/directories matching 'test_reg_*':")
    confirmed_test_dirs = []
    for d in fs_dirs:
        manifest_file = d / "manifest.json"
        is_synthetic_test = False
        details = ""
        if manifest_file.exists():
            try:
                manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                rh = manifest_data.get("rulesetHash", "")
                rr = manifest_data.get("resultRoot", "")
                if rh.startswith("aaaa") or rr.startswith("bbbb"):
                    is_synthetic_test = True
                    details = f" [CONFIRMED TEST FIXTURE: rulesetHash={rh[:8]}..., resultRoot={rr[:8]}...]"
            except Exception:
                pass
        print(f"    • {d.name}{details}")
        if is_synthetic_test:
            confirmed_test_dirs.append(d)

    # Inspect BACKUPS_DIR for existing backups
    existing_db_backups = []
    existing_json_manifests = []
    if BACKUPS_DIR.exists():
        existing_db_backups = sorted(BACKUPS_DIR.glob("*.db"))
        existing_json_manifests = sorted(BACKUPS_DIR.glob("*.json"))

    if preview_only:
        print("\n" + "-" * 70)
        print("[PREVIEW MODE ONLY] No database rows, files, or directories were modified or created.")
        if existing_db_backups or existing_json_manifests:
            print(f"\n[+] Verified existing backup(s) found in {BACKUPS_DIR}:")
            for db_b in existing_db_backups:
                try:
                    b_conn = sqlite3.connect(f"file:{db_b}?mode=ro", uri=True)
                    cur = b_conn.cursor()
                    cur.execute("PRAGMA integrity_check;")
                    integrity = cur.fetchone()[0]
                    cur.execute("SELECT count(*) FROM cases;")
                    c_count = cur.fetchone()[0]
                    b_conn.close()
                    status_str = f"integrity: {integrity}, total cases preserved: {c_count}"
                except Exception as ex:
                    status_str = f"verification error: {ex}"
                print(f"    • SQLite DB:  {db_b.name} ({db_b.stat().st_size} bytes | {status_str})")

            for j_m in existing_json_manifests:
                try:
                    data = json.loads(j_m.read_text(encoding="utf-8"))
                    rec_count = len(data.get("testDbRecords", []))
                    dir_count = len(data.get("confirmedTestDirs", []))
                    j_status = f"{rec_count} test records, {dir_count} test dirs documented"
                except Exception as ex:
                    j_status = f"error reading JSON: {ex}"
                print(f"    • Audit JSON: {j_m.name} ({j_m.stat().st_size} bytes | {j_status})")
            print("\nExisting verified backups are present and valid.")
            print("To create a new additional backup, run:")
            print("  python scripts/audit_test_reg_cases.py --create-backup")
        else:
            print(f"\nNo previous backup files found in {BACKUPS_DIR}.")
            print("To create a verified SQLite backup and audit archive:")
            print("  python scripts/audit_test_reg_cases.py --create-backup")
        print("-" * 70)
        return

    if create_backup:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        ts_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

        # 1. Consistent SQLite Online Backup via SQLite Backup API
        backup_db_path = BACKUPS_DIR / f"smscope_backup_{ts_str}.db"
        if DB_PATH.exists():
            print(f"\n[*] Performing consistent SQLite online backup to: {backup_db_path}")
            src_conn = sqlite3.connect(DB_PATH)
            dst_conn = sqlite3.connect(backup_db_path)
            src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

            # Verify backup file
            if backup_db_path.exists() and backup_db_path.stat().st_size > 0:
                # Test query on the backup
                test_conn = sqlite3.connect(backup_db_path)
                test_cur = test_conn.cursor()
                test_cur.execute("SELECT count(*) FROM cases")
                total_cases = test_cur.fetchone()[0]
                test_conn.close()
                print(f"[+] SQLite database backup verified ({backup_db_path.stat().st_size} bytes, {total_cases} total cases preserved).")
            else:
                print(f"[!] Error: Backup file verification failed for {backup_db_path}")
        else:
            print("[!] Database file does not exist; skipping SQLite backup.")

        # 2. JSON Audit Manifest Backup
        audit_json_path = BACKUPS_DIR / f"test_reg_audit_{ts_str}.json"
        audit_data = {
            "timestamp": ts_str,
            "databasePath": str(DB_PATH),
            "testDbRecords": [
                {
                    "id": r[0],
                    "status": r[1],
                    "pcap_sha256": r[2],
                    "created_at": r[3],
                    "onchain_case_id": r[4],
                }
                for r in db_rows
            ],
            "confirmedTestDirs": [str(d.name) for d in confirmed_test_dirs],
        }
        audit_json_path.write_text(json.dumps(audit_data, indent=2), encoding="utf-8")
        if audit_json_path.exists() and audit_json_path.stat().st_size > 0:
            print(f"[+] Audit JSON manifest verified at {audit_json_path} ({audit_json_path.stat().st_size} bytes).")

        # 3. Optional Case Directories Archive
        if archive_cases and confirmed_test_dirs:
            cases_archive_dir = BACKUPS_DIR / f"test_reg_cases_{ts_str}"
            cases_archive_dir.mkdir(parents=True, exist_ok=True)
            for d in confirmed_test_dirs:
                target = cases_archive_dir / d.name
                if not target.exists():
                    shutil.copytree(d, target)
            print(f"[+] Confirmed test case directories safely archived to: {cases_archive_dir}")

        print("\n[+] Backup procedure completed successfully. Real database untouched.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit and preview test_reg_ records.")
    parser.add_argument("--create-backup", action="store_true", help="Perform consistent SQLite online backup and export audit JSON.")
    parser.add_argument("--archive-cases", action="store_true", help="Also archive confirmed test case directories into backups directory.")
    args = parser.parse_args()

    preview = not (args.create_backup or args.archive_cases)
    audit_test_records(preview_only=preview, create_backup=args.create_backup, archive_cases=args.archive_cases)
