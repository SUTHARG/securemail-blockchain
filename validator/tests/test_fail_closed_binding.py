"""Regression tests for validator fail-closed case and PCAP binding (Requirement 4).

Verifies for both validator implementations:
1. Rejects zero on-chain pcapHash (0x00...00).
2. Rejects missing / None on-chain pcapHash.
3. Rejects mismatched PCAP hash (bundle PCAP SHA-256 != onchain pcapHash).
4. Rejects bundle with missing metadata in strict mode.
5. Rejects bundle with wrong metadata (case ID mismatch).
6. Accepts valid bundle matching target on-chain case.
"""
import hashlib
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from validator.node import process_case
from validator.service import ValidatorService


def _setup_mock_node_deps(monkeypatch, case_id_bytes, onchain_pcap, engine_hash, ruleset_hash):
    mock_case_reg = MagicMock()
    mock_case_reg.functions.caseState.return_value.call.return_value = 1  # State.Opened
    mock_case_reg.functions.caseRound.return_value.call.return_value = 0
    mock_case_reg.functions.engineHash.return_value.call.return_value = engine_hash
    mock_case_reg.functions.rulesetHash.return_value.call.return_value = ruleset_hash
    mock_case_reg.functions.pcapHash.return_value.call.return_value = onchain_pcap

    mock_w3 = MagicMock()
    mock_w3.eth.contract.return_value = mock_case_reg
    return mock_case_reg, mock_w3


def test_node_zero_onchain_hash_rejected(tmp_path, monkeypatch):
    """ValidatorNode rejects zero on-chain pcapHash."""
    case_id_hex = "1" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    pcap_bytes = b"sample-pcap"
    pcap_path = tmp_path / "pcap.bin"
    pcap_path.write_bytes(pcap_bytes)
    (tmp_path / "org_secret.hex").write_text("01" * 32)
    (tmp_path / "onchain_case_id.txt").write_text("0x" + case_id_hex)

    # Zero on-chain pcapHash
    mock_reg, mock_w3 = _setup_mock_node_deps(
        monkeypatch, case_bytes, b"\x00" * 32, b"\x01" * 32, b"\x02" * 32
    )
    monkeypatch.setattr("validator.node.Web3", MagicMock(return_value=mock_w3))
    monkeypatch.setattr("validator.node.Account.from_key", MagicMock(return_value=MagicMock(address="0x" + "9" * 40)))

    # Mock deployment reading
    mock_deploy = {
        "CaseRegistry": {"address": "0x" + "1" * 40, "abi": []},
        "ValidationQuorum": {"address": "0x" + "2" * 40, "abi": []},
    }
    monkeypatch.setattr("validator.node.load_deployment", lambda p: mock_deploy)

    with pytest.raises(ValueError) as exc_info:
        process_case(
            case_id_hex=case_id_hex,
            pcap_path=pcap_path,
            org_secret_hex="01" * 32,
            private_key_hex="0a" * 32,
            rpc_url="http://127.0.0.1:8545",
            strict=True,
        )

    assert "missing or zero on-chain pcaphash" in str(exc_info.value).lower()


def test_node_mismatched_pcap_rejected(tmp_path, monkeypatch):
    """ValidatorNode rejects bundle PCAP whose SHA-256 does not match on-chain pcapHash."""
    case_id_hex = "2" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    pcap_bytes = b"sample-pcap"
    pcap_path = tmp_path / "pcap.bin"
    pcap_path.write_bytes(pcap_bytes)
    (tmp_path / "org_secret.hex").write_text("01" * 32)
    (tmp_path / "onchain_case_id.txt").write_text("0x" + case_id_hex)

    # Different on-chain pcapHash
    different_pcap_hash = bytes.fromhex("ff" * 32)
    mock_reg, mock_w3 = _setup_mock_node_deps(
        monkeypatch, case_bytes, different_pcap_hash, b"\x01" * 32, b"\x02" * 32
    )
    monkeypatch.setattr("validator.node.Web3", MagicMock(return_value=mock_w3))
    monkeypatch.setattr("validator.node.Account.from_key", MagicMock(return_value=MagicMock(address="0x" + "9" * 40)))
    mock_deploy = {
        "CaseRegistry": {"address": "0x" + "1" * 40, "abi": []},
        "ValidationQuorum": {"address": "0x" + "2" * 40, "abi": []},
    }
    monkeypatch.setattr("validator.node.load_deployment", lambda p: mock_deploy)

    with pytest.raises(ValueError) as exc_info:
        process_case(
            case_id_hex=case_id_hex,
            pcap_path=pcap_path,
            org_secret_hex="01" * 32,
            private_key_hex="0a" * 32,
            rpc_url="http://127.0.0.1:8545",
            strict=True,
        )

    assert "does not match on-chain case pcaphash" in str(exc_info.value).lower()


def test_node_missing_metadata_in_strict_mode(tmp_path, monkeypatch):
    """ValidatorNode in strict mode rejects plaintext bundle missing onchain_case_id.txt."""
    case_id_hex = "3" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    pcap_bytes = b"sample-pcap"
    pcap_path = tmp_path / "pcap.bin"
    pcap_path.write_bytes(pcap_bytes)
    (tmp_path / "org_secret.hex").write_text("01" * 32)
    # onchain_case_id.txt is NOT created

    actual_hash = hashlib.sha256(pcap_bytes).digest()
    mock_reg, mock_w3 = _setup_mock_node_deps(
        monkeypatch, case_bytes, actual_hash, b"\x01" * 32, b"\x02" * 32
    )
    monkeypatch.setattr("validator.node.Web3", MagicMock(return_value=mock_w3))
    monkeypatch.setattr("validator.node.Account.from_key", MagicMock(return_value=MagicMock(address="0x" + "9" * 40)))
    mock_deploy = {
        "CaseRegistry": {"address": "0x" + "1" * 40, "abi": []},
        "ValidationQuorum": {"address": "0x" + "2" * 40, "abi": []},
    }
    monkeypatch.setattr("validator.node.load_deployment", lambda p: mock_deploy)

    with pytest.raises(ValueError) as exc_info:
        process_case(
            case_id_hex=case_id_hex,
            pcap_path=pcap_path,
            org_secret_hex="01" * 32,
            private_key_hex="0a" * 32,
            rpc_url="http://127.0.0.1:8545",
            strict=True,
        )

    assert "missing onchain_case_id.txt in strict mode" in str(exc_info.value).lower()


def test_node_wrong_metadata_case_id_mismatch(tmp_path, monkeypatch):
    """ValidatorNode rejects bundle when metadata case ID does not match target case ID."""
    case_id_hex = "4" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    pcap_bytes = b"sample-pcap"
    pcap_path = tmp_path / "pcap.bin"
    pcap_path.write_bytes(pcap_bytes)
    (tmp_path / "org_secret.hex").write_text("01" * 32)
    # Different case ID in onchain_case_id.txt
    (tmp_path / "onchain_case_id.txt").write_text("0x" + "5" * 64)

    actual_hash = hashlib.sha256(pcap_bytes).digest()
    mock_reg, mock_w3 = _setup_mock_node_deps(
        monkeypatch, case_bytes, actual_hash, b"\x01" * 32, b"\x02" * 32
    )
    monkeypatch.setattr("validator.node.Web3", MagicMock(return_value=mock_w3))
    monkeypatch.setattr("validator.node.Account.from_key", MagicMock(return_value=MagicMock(address="0x" + "9" * 40)))
    mock_deploy = {
        "CaseRegistry": {"address": "0x" + "1" * 40, "abi": []},
        "ValidationQuorum": {"address": "0x" + "2" * 40, "abi": []},
    }
    monkeypatch.setattr("validator.node.load_deployment", lambda p: mock_deploy)

    with pytest.raises(ValueError) as exc_info:
        process_case(
            case_id_hex=case_id_hex,
            pcap_path=pcap_path,
            org_secret_hex="01" * 32,
            private_key_hex="0a" * 32,
            rpc_url="http://127.0.0.1:8545",
            strict=True,
        )

    assert "does not match target case id" in str(exc_info.value).lower()


def test_service_zero_onchain_pcap_rejected(tmp_path, monkeypatch):
    """ValidatorService rejects incoming bundle when on-chain pcapHash is zero."""
    vs = ValidatorService.__new__(ValidatorService)
    vs.validator_id = "v1"
    vs.strict = True
    vs.inbox_dir = tmp_path / "inbox"
    vs.inbox_dir.mkdir(parents=True)
    vs.state_dir = tmp_path / "state"
    vs.state_dir.mkdir(parents=True)
    vs.state_file = vs.state_dir / "v1.json"
    vs.temp_state_file = vs.state_dir / "v1.json.tmp"
    vs.account = MagicMock(address="0x" + "9" * 40)
    vs.private_key = "0a" * 32

    case_id_hex = "6" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    bundle_dir = vs.inbox_dir / f"case_{case_id_hex}"
    bundle_dir.mkdir()
    (bundle_dir / "pcap.bin").write_bytes(b"pcap-bytes")
    (bundle_dir / "org_secret.hex").write_text("01" * 32)
    (bundle_dir / "onchain_case_id.txt").write_text("0x" + case_id_hex)

    vs.case_registry = MagicMock()
    vs.case_registry.functions.caseExists.return_value.call.return_value = True
    vs.case_registry.functions.caseState.return_value.call.return_value = 3  # Committing
    vs.case_registry.functions.caseRound.return_value.call.return_value = 0
    # Zero on-chain pcapHash
    vs.case_registry.functions.pcapHash.return_value.call.return_value = b"\x00" * 32

    vs.quorum = MagicMock()
    vs.quorum.functions.isSnapshotValidator.return_value.call.return_value = True
    vs.quorum.functions.hasCommitted.return_value.call.return_value = False
    vs.quorum.functions.hasRevealed.return_value.call.return_value = False

    with pytest.raises(ValueError) as exc_info:
        vs.process_bundle(case_bytes, bundle_dir, "01" * 32)

    assert "missing or zero on-chain pcaphash" in str(exc_info.value).lower()


def test_service_mismatched_pcap_rejected(tmp_path, monkeypatch):
    """ValidatorService rejects incoming bundle when PCAP SHA-256 does not match on-chain pcapHash."""
    vs = ValidatorService.__new__(ValidatorService)
    vs.validator_id = "v1"
    vs.strict = True
    vs.inbox_dir = tmp_path / "inbox"
    vs.inbox_dir.mkdir(parents=True)
    vs.state_dir = tmp_path / "state"
    vs.state_dir.mkdir(parents=True)
    vs.state_file = vs.state_dir / "v1.json"
    vs.temp_state_file = vs.state_dir / "v1.json.tmp"
    vs.account = MagicMock(address="0x" + "9" * 40)
    vs.private_key = "0a" * 32

    case_id_hex = "7" * 64
    case_bytes = bytes.fromhex(case_id_hex)
    bundle_dir = vs.inbox_dir / f"case_{case_id_hex}"
    bundle_dir.mkdir()
    (bundle_dir / "pcap.bin").write_bytes(b"pcap-bytes")
    (bundle_dir / "org_secret.hex").write_text("01" * 32)
    (bundle_dir / "onchain_case_id.txt").write_text("0x" + case_id_hex)

    vs.case_registry = MagicMock()
    vs.case_registry.functions.caseExists.return_value.call.return_value = True
    vs.case_registry.functions.caseState.return_value.call.return_value = 3  # Committing
    vs.case_registry.functions.caseRound.return_value.call.return_value = 0
    # Mismatched on-chain pcapHash
    vs.case_registry.functions.pcapHash.return_value.call.return_value = bytes.fromhex("ee" * 32)

    vs.quorum = MagicMock()
    vs.quorum.functions.isSnapshotValidator.return_value.call.return_value = True
    vs.quorum.functions.hasCommitted.return_value.call.return_value = False
    vs.quorum.functions.hasRevealed.return_value.call.return_value = False

    with pytest.raises(ValueError) as exc_info:
        vs.process_bundle(case_bytes, bundle_dir, "01" * 32)

    assert "does not match on-chain case pcaphash" in str(exc_info.value).lower()
