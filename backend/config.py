"""Configuration settings for SecureMailScope backend API."""
import os
from pathlib import Path
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")
DATA_DIR = Path(os.environ.get("DATA_DIR", REPO_ROOT / "data"))
CASES_DIR = DATA_DIR / "cases"
DB_PATH = Path(os.environ.get("DB_PATH", DATA_DIR / "smscope.db"))

ANALYST_API_KEY = os.environ.get("ANALYST_API_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
ORG_SECRET_HEX = os.environ.get(
    "ORG_SECRET_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

# 100 MB max upload size
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", 100 * 1024 * 1024))
ENGINE_VERSION = "0.1.0"
ENGINE_DOCKER_IMAGE = os.environ.get("ENGINE_DOCKER_IMAGE", "smscope:latest")

# Blockchain configuration
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
DEPLOYMENT_FILE = Path(
    os.environ.get("DEPLOYMENT_FILE", REPO_ROOT / "contracts" / "deployments" / "local.json")
)
ANALYST_KEY = os.environ.get(
    "ANALYST_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
ADMIN_KEY = os.environ.get(
    "ADMIN_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
