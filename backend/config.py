"""Configuration settings for SecureMailScope backend API."""
import os
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
try:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass
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
RPC_TIMEOUT = int(os.environ.get("RPC_TIMEOUT", 5))
DEPLOYMENT_FILE = Path(
    os.environ.get("DEPLOYMENT_FILE", REPO_ROOT / "contracts" / "deployments" / "local.json")
)
ANALYST_KEY = os.environ.get(
    "ANALYST_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
ADMIN_KEY = os.environ.get(
    "ADMIN_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
VALIDATOR_KEY_1 = os.environ.get("VALIDATOR_KEY_1", os.environ.get("VALIDATOR_1_KEY", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"))
VALIDATOR_KEY_2 = os.environ.get("VALIDATOR_KEY_2", os.environ.get("VALIDATOR_2_KEY", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"))
VALIDATOR_KEY_3 = os.environ.get("VALIDATOR_KEY_3", os.environ.get("VALIDATOR_3_KEY", "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"))
ENGINE_IMAGE_DIGEST = os.environ.get("ENGINE_IMAGE_DIGEST", "")

APP_ENV = os.environ.get("APP_ENV", "development").lower()
ALLOW_DEV_KEYS = os.environ.get("ALLOW_DEV_KEYS", "").lower() in ("true", "1", "yes")
HARDHAT_DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


DEFAULT_ORG_SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def validate_environment() -> None:
    """Enforces configuration constraints at startup."""
    # 1. Require valid, explicitly configured storage-at-rest encryption key
    from validator.crypto import get_storage_at_rest_key
    get_storage_at_rest_key()

    # 2. Reject default development keys in production environments
    is_local_demo = APP_ENV in ("development", "local", "demo", "test") or ALLOW_DEV_KEYS
    if not is_local_demo:
        # Require explicit valid blockchain keys
        for key_name, key_val in [("ANALYST_KEY", ANALYST_KEY), ("ADMIN_KEY", ADMIN_KEY)]:
            if not key_val:
                raise RuntimeError(f"Production configuration requires {key_name} to be set.")
            clean_k = key_val.lower().replace("0x", "").strip()
            if len(clean_k) != 64:
                raise RuntimeError(f"Production configuration {key_name} must be a 64-character hex string.")
            try:
                bytes.fromhex(clean_k)
            except ValueError:
                raise RuntimeError(f"Production configuration {key_name} contains invalid hex.")
            if clean_k == HARDHAT_DEV_KEY.lower().replace("0x", ""):
                raise RuntimeError(f"Production configuration {key_name} must not use Hardhat development keys.")

        # Require explicit, strong, non-default API keys
        if not ANALYST_API_KEY or len(ANALYST_API_KEY.strip()) < 16:
            raise RuntimeError("Production configuration requires ANALYST_API_KEY of at least 16 characters.")
        if not ADMIN_API_KEY or len(ADMIN_API_KEY.strip()) < 16:
            raise RuntimeError("Production configuration requires ADMIN_API_KEY of at least 16 characters.")
        if ANALYST_API_KEY == ADMIN_API_KEY:
            raise RuntimeError("Production configuration requires distinct ANALYST_API_KEY and ADMIN_API_KEY.")
        known_bad = {"0123456789abcdef", "analyst_secret_key", "admin_secret_key", "changeme", "password"}
        if ANALYST_API_KEY.lower() in known_bad:
            raise RuntimeError("Production configuration rejects default ANALYST_API_KEY.")
        if ADMIN_API_KEY.lower() in known_bad:
            raise RuntimeError("Production configuration rejects default ADMIN_API_KEY.")

        # Require explicit, non-default ORG_SECRET_HEX
        if not ORG_SECRET_HEX:
            raise RuntimeError("Production configuration requires ORG_SECRET_HEX to be set.")
        clean_org = ORG_SECRET_HEX.lower().replace("0x", "").strip()
        if clean_org == DEFAULT_ORG_SECRET_HEX.lower():
            raise RuntimeError("Production configuration must not use the hard-coded default ORG_SECRET_HEX.")
        if len(clean_org) != 64:
            raise RuntimeError("Production configuration ORG_SECRET_HEX must be a 64-character hex string.")
        try:
            bytes.fromhex(clean_org)
        except ValueError:
            raise RuntimeError("Production configuration ORG_SECRET_HEX contains invalid hex.")
