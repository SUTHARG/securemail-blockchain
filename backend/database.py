"""SQLite database operations for SecureMailScope API."""
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional

import backend.config as config


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open SQLite connection with row factory enabled."""
    target_path = db_path or config.DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize SQLite database tables strictly according to Section 3 and 8."""
    conn = get_connection(db_path)
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                pcap_sha256 TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                engine_version TEXT NOT NULL,
                onchain_case_id TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_runs (
                case_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                error TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS chain_txs (
                case_id TEXT NOT NULL,
                step TEXT NOT NULL,
                nonce INTEGER,
                tx_hash TEXT,
                status TEXT NOT NULL,
                retries INTEGER NOT NULL DEFAULT 0,
                raw_tx TEXT,
                PRIMARY KEY (case_id, step),
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                case_id TEXT,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS validator_keys (
                validator_id TEXT PRIMARY KEY,
                public_key_hex TEXT NOT NULL,
                registered_at INTEGER NOT NULL
            );
            """
        )
    conn.close()

    try:
        conn = get_connection(db_path)
        with conn:
            conn.execute("ALTER TABLE cases ADD COLUMN onchain_case_id TEXT")
        conn.close()
    except Exception:
        pass

    try:
        conn = get_connection(db_path)
        with conn:
            conn.execute("ALTER TABLE chain_txs ADD COLUMN raw_tx TEXT")
        conn.close()
    except Exception:
        pass


def add_audit_entry(
    actor: str,
    action: str,
    case_id: Optional[str] = None,
    detail: str = "",
    db_path: Optional[Path] = None,
) -> None:
    """Log an operational audit log entry (Rule 4: no credentials/payloads)."""
    conn = get_connection(db_path)
    now = int(time.time())
    with conn:
        conn.execute(
            """
            INSERT INTO audit_log (at, actor, action, case_id, detail)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, actor, action, case_id, detail),
        )
    conn.close()


def create_case(
    case_id: str,
    pcap_sha256: str,
    status: str = "uploaded",
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Insert a new case record."""
    conn = get_connection(db_path)
    now = int(time.time())
    with conn:
        conn.execute(
            """
            INSERT INTO cases (id, status, pcap_sha256, created_at, engine_version)
            VALUES (?, ?, ?, ?, ?)
            """,
            (case_id, status, pcap_sha256, now, config.ENGINE_VERSION),
        )
    conn.close()
    return {
        "id": case_id,
        "status": status,
        "pcap_sha256": pcap_sha256,
        "created_at": now,
        "engine_version": config.ENGINE_VERSION,
    }


def get_case(case_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetch case by ID."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def list_all_cases(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Fetch all cases ordered by created_at DESC."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_case_status(case_id: str, status: str, db_path: Optional[Path] = None) -> None:
    """Update case status state machine."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
    conn.close()


def record_analysis_run(
    case_id: str,
    status: str,
    started_at: int,
    finished_at: Optional[int] = None,
    error: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    """Insert or update analysis run record."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO analysis_runs (case_id, status, started_at, finished_at, error)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                status=excluded.status,
                started_at=excluded.started_at,
                finished_at=excluded.finished_at,
                error=excluded.error
            """,
            (case_id, status, started_at, finished_at, error),
        )
    conn.close()


def get_audit_entries(case_id: Optional[str] = None, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve audit log entries."""
    conn = get_connection(db_path)
    if case_id:
        rows = conn.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY id ASC", (case_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_case_onchain_id(case_id: str, onchain_case_id: str, db_path: Optional[Path] = None) -> None:
    """Associate an on-chain 32-byte caseId with the database case."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("UPDATE cases SET onchain_case_id = ? WHERE id = ?", (onchain_case_id, case_id))
    conn.close()


def get_case_by_onchain_id(onchain_case_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Find case by on-chain caseId."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM cases WHERE onchain_case_id = ?", (onchain_case_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def get_case_by_pcap_sha(pcap_sha256: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Find case by PCAP SHA-256."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM cases WHERE pcap_sha256 = ?", (pcap_sha256,)).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def record_chain_tx(
    case_id: str,
    step: str,
    nonce: Optional[int],
    tx_hash: Optional[str],
    status: str,
    retries: int = 0,
    raw_tx: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    """
    Store or update a transaction record in chain_txs.
    Prompt 6.2: Every sent transaction is stored before waiting for receipt.
    COALESCE preserves existing nonce, tx_hash, and raw_tx to prevent erasing intent.
    """
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO chain_txs (case_id, step, nonce, tx_hash, status, retries, raw_tx)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, step) DO UPDATE SET
                nonce=COALESCE(excluded.nonce, chain_txs.nonce),
                tx_hash=COALESCE(excluded.tx_hash, chain_txs.tx_hash),
                raw_tx=COALESCE(excluded.raw_tx, chain_txs.raw_tx),
                status=excluded.status,
                retries=excluded.retries
            """,
            (case_id, step, nonce, tx_hash, status, retries, raw_tx),
        )
    conn.close()


def get_chain_tx(case_id: str, step: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieve transaction record for a specific step."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM chain_txs WHERE case_id = ? AND step = ?", (case_id, step)).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def get_chain_txs(case_id: str, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve all chain transaction records for a case."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM chain_txs WHERE case_id = ? ORDER BY nonce ASC, step ASC", (case_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sync_state(key: str, default: Optional[str] = None, db_path: Optional[Path] = None) -> Optional[str]:
    """Retrieve a persistent sync state value (e.g. last_processed_block)."""
    conn = get_connection(db_path)
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    conn.close()
    if not row:
        return default
    return str(row["value"])


def set_sync_state(key: str, value: str, db_path: Optional[Path] = None) -> None:
    """Store or update a persistent sync state value."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            INSERT INTO sync_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, str(value)),
        )
    conn.close()


def register_validator_key(
    validator_id: str,
    public_key_hex: str,
    db_path: Optional[Path] = None,
) -> None:
    """Register or update validator Curve25519 public key (Prompt T3.1)."""
    conn = get_connection(db_path)
    now = int(time.time())
    with conn:
        conn.execute(
            """
            INSERT INTO validator_keys (validator_id, public_key_hex, registered_at)
            VALUES (?, ?, ?)
            ON CONFLICT(validator_id) DO UPDATE SET
                public_key_hex=excluded.public_key_hex,
                registered_at=excluded.registered_at
            """,
            (validator_id, public_key_hex.strip().lower(), now),
        )
    conn.close()


def get_validator_key(
    validator_id: str,
    db_path: Optional[Path] = None,
) -> Optional[str]:
    """Retrieve registered Curve25519 public key hex for a validator."""
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT public_key_hex FROM validator_keys WHERE validator_id = ?",
        (validator_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return str(row["public_key_hex"])


def list_validator_keys(
    db_path: Optional[Path] = None,
) -> Dict[str, str]:
    """Retrieve all registered validator public keys."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT validator_id, public_key_hex FROM validator_keys").fetchall()
    conn.close()
    return {str(r["validator_id"]): str(r["public_key_hex"]) for r in rows}
