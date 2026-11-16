"""Contract deployment configuration loader for client-side and backend inspector."""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import backend.config as config
from backend.chain.gateway import load_contract_artifact

logger = logging.getLogger("securemailscope.chain.deployment")

REQUIRED_CONTRACTS = ["CaseRegistry", "ValidationQuorum", "PostureLedger", "Roles"]


def get_client_deployment_config(deployment_file: Optional[Path] = None) -> Dict[str, Any]:
    """Load deployment addresses, network info, and ABIs for client-side read-only inspection."""
    dep_file = deployment_file or config.DEPLOYMENT_FILE

    if not dep_file.exists():
        logger.warning("Deployment file not found at %s", dep_file)
        return {
            "network": "localhost",
            "chainId": 31337,
            "rpcUrl": config.RPC_URL,
            "deployer": "",
            "deploymentFile": str(dep_file),
            "contracts": {
                name: {"address": "", "abi": [], "abiPath": ""}
                for name in REQUIRED_CONTRACTS
            },
        }

    try:
        with open(dep_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.error("Failed to read deployment file %s: %s", dep_file, exc)
        return {
            "network": "unknown",
            "chainId": 31337,
            "rpcUrl": config.RPC_URL,
            "deployer": "",
            "deploymentFile": str(dep_file),
            "contracts": {},
        }

    raw_contracts = data.get("contracts", {})
    contracts: Dict[str, Dict[str, Any]] = {}

    for name in REQUIRED_CONTRACTS:
        c_info = raw_contracts.get(name, {})
        addr = c_info.get("address", "")
        abi_path = c_info.get("abiPath", "")
        abi: List[Dict[str, Any]] = []

        if abi_path:
            try:
                abi = load_contract_artifact(dep_file, abi_path)
            except Exception as exc:
                logger.warning("Could not load ABI for contract %s (%s): %s", name, abi_path, exc)

        contracts[name] = {
            "address": addr,
            "abiPath": abi_path,
            "abi": abi,
        }

    rel_path = str(dep_file)
    try:
        rel_path = str(dep_file.relative_to(config.REPO_ROOT)).replace("\\", "/")
    except ValueError:
        pass

    return {
        "network": data.get("network", "localhost"),
        "chainId": int(data.get("chainId", 31337)),
        "rpcUrl": config.RPC_URL,
        "deployer": data.get("deployer", ""),
        "deploymentFile": rel_path,
        "contracts": contracts,
    }
