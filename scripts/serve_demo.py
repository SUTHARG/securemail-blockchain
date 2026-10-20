"""Serve isolated demonstration dashboard on dedicated port."""
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

if len(sys.argv) < 2:
    print("Usage: python scripts/serve_demo.py <demo_run_dir> [port]")
    sys.exit(1)

demo_dir = Path(sys.argv[1]).resolve()
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8001

os.environ["DATA_DIR"] = str(demo_dir)
os.environ["DB_PATH"] = str(demo_dir / "smscope.db")

import backend.config as config
config.DATA_DIR = demo_dir
config.CASES_DIR = demo_dir / "cases"
config.DB_PATH = demo_dir / "smscope.db"

from backend.app import app
import uvicorn

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
