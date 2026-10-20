"""Engine analysis execution runner for SecureMailScope cases (Prompt 6.1)."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Optional

import backend.config as config
from backend.database import (
    add_audit_entry,
    get_case,
    record_analysis_run,
    update_case_status,
)
from backend.storage import get_case_dir

TRUST_STORE_PATH = config.REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"


def is_docker_available() -> bool:
    """Check if Docker CLI and daemon are operational."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def execute_analysis(case_id: str, use_docker: Optional[bool] = None) -> bool:
    """
    Executes engine analysis on case PCAP.
    Runs via isolated Docker container if daemon is running,
    falling back to direct local engine module execution.
    """
    case = get_case(case_id)
    if not case:
        return False

    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    if not pcap_path.exists():
        record_analysis_run(
            case_id=case_id,
            status="failed",
            started_at=int(time.time()),
            finished_at=int(time.time()),
            error="pcap.bin not found in case directory",
        )
        update_case_status(case_id, "failed")
        return False

    started_at = int(time.time())
    record_analysis_run(case_id=case_id, status="running", started_at=started_at)
    add_audit_entry(actor="system", action="analysis_started", case_id=case_id)

    docker_mode = is_docker_available() if use_docker is None else use_docker
    success = False
    err_message: Optional[str] = None
    temp_dir_obj = None

    try:
        pcap_raw = pcap_path.read_bytes()
        if pcap_raw.startswith(b"SMSE"):
            from validator.crypto import decrypt_at_rest
            temp_dir_obj = tempfile.TemporaryDirectory()
            try:
                os.chmod(temp_dir_obj.name, 0o700)
            except Exception:
                pass
            run_pcap_path = Path(temp_dir_obj.name) / "pcap.bin"
            run_pcap_path.write_bytes(decrypt_at_rest(pcap_raw))
        else:
            run_pcap_path = pcap_path

        if docker_mode:
            try:
                insp = subprocess.run(["docker", "image", "inspect", config.ENGINE_DOCKER_IMAGE], capture_output=True, timeout=2)
                if insp.returncode != 0:
                    docker_mode = False
            except Exception:
                docker_mode = False

        if docker_mode:
            # Containerized execution per Prompt 6.1
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{run_pcap_path}:/data/pcap.bin:ro",
                "-v",
                f"{case_dir}:/data/out",
                config.ENGINE_DOCKER_IMAGE,
                "analyze",
                "/data/pcap.bin",
                "--org-secret-hex",
                config.ORG_SECRET_HEX,
                "--out",
                "/data/out",
                "--case-id",
                case_id,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                success = True
            else:
                logger.warning("Container analysis failed with code %s: %s; falling back to direct CLI", res.returncode, res.stderr[:200])
                docker_mode = False

        if not docker_mode:
            # Direct engine CLI invocation
            cmd = [
                sys.executable,
                "-m",
                "smscope",
                "analyze",
                str(run_pcap_path),
                "--org-secret-hex",
                config.ORG_SECRET_HEX,
                "--out",
                str(case_dir),
                "--case-id",
                case_id,
            ]
            if TRUST_STORE_PATH.exists():
                cmd.extend(["--trust-store", str(TRUST_STORE_PATH)])

            env = os.environ.copy()
            real_engine = Path(__file__).resolve().parents[1] / "engine"
            pythonpath = str(real_engine)
            if "PYTHONPATH" in env:
                env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
            else:
                env["PYTHONPATH"] = pythonpath

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
            if res.returncode == 0:
                success = True
            else:
                err_message = f"Engine analysis failed with code {res.returncode}: {res.stderr[:200]}"

    except Exception as exc:
        err_message = f"Analysis exception: {type(exc).__name__}"
    finally:
        if temp_dir_obj is not None:
            try:
                temp_dir_obj.cleanup()
            except Exception:
                pass

    finished_at = int(time.time())

    # Sanitize any accidental secret leakage in error logs
    if err_message and config.ORG_SECRET_HEX in err_message:
        err_message = err_message.replace(config.ORG_SECRET_HEX, "[REDACTED_SECRET]")

    if success:
        update_case_status(case_id, "analyzed")
        record_analysis_run(
            case_id=case_id,
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
        )
        add_audit_entry(actor="system", action="analysis_completed", case_id=case_id)
        return True
    else:
        update_case_status(case_id, "failed")
        record_analysis_run(
            case_id=case_id,
            status="failed",
            started_at=started_at,
            finished_at=finished_at,
            error=err_message,
        )
        add_audit_entry(
            actor="system",
            action="analysis_failed",
            case_id=case_id,
            detail=err_message or "Unknown error",
        )
        return False
