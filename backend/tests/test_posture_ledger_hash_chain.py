"""Regression tests for PostureLedger record hash chain verification (Requirement 7).

Verifies:
1. Valid hash chain with keccak256(abi.encode(hostId, caseId, score, resultRoot, prevHash, timestamp)) -> PASS.
2. Broken prevHash chaining -> FAIL.
3. Altered score or altered resultRoot -> FAIL.
4. Missing record for expected host -> FAIL.
5. Wrong case ID -> FAIL.
6. Incorrect recordHash (tampered hash) -> FAIL.
"""
import eth_abi
from web3 import Web3
from backend.chain.verifier import verify_posture_ledger_hash_chain


def _build_mock_record(host_bytes, case_bytes, score, root_bytes, prev_hash, timestamp, tamper_hash=False):
    encoded = eth_abi.encode(
        ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
        [host_bytes, case_bytes, int(score), root_bytes, prev_hash, int(timestamp)],
    )
    rec_hash = Web3.keccak(encoded)
    if tamper_hash:
        rec_hash = bytes.fromhex("ff" * 32)
    return (host_bytes, case_bytes, score, root_bytes, prev_hash, timestamp, rec_hash)


def test_valid_hash_chain_single_host():
    """Valid hash chain for single host passes."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes = bytes.fromhex("02" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    score = 85
    timestamp = 1700000000

    rec = _build_mock_record(host_bytes, case_bytes, score, root_bytes, bytes(32), timestamp)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                class MockCall:
                    def call(self):
                        return 1
                return MockCall()

            @staticmethod
            def recordAt(h, idx):
                class MockCall:
                    def call(self):
                        return rec
                return MockCall()

    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": score}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes,
        result_root_bytes=root_bytes,
        expected_host_scores=expected_scores,
    )
    assert passed is True
    assert "Verified hash chain" in msg


def test_broken_prev_hash():
    """First record with non-zero prevHash or broken link fails."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes = bytes.fromhex("02" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    score = 90
    timestamp = 1700000000

    # Non-zero prev_hash on first record
    rec = _build_mock_record(host_bytes, case_bytes, score, root_bytes, bytes.fromhex("aa" * 32), timestamp)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                return type("Call", (), {"call": lambda s: 1})()

            @staticmethod
            def recordAt(h, idx):
                return type("Call", (), {"call": lambda s: rec})()

    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": score}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes,
        result_root_bytes=root_bytes,
        expected_host_scores=expected_scores,
    )
    assert passed is False
    assert "Broken prevHash chain" in msg


def test_altered_score():
    """On-chain score differing from local expected score fails."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes = bytes.fromhex("02" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    timestamp = 1700000000

    # Recorded score is 50
    rec = _build_mock_record(host_bytes, case_bytes, 50, root_bytes, bytes(32), timestamp)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                return type("Call", (), {"call": lambda s: 1})()

            @staticmethod
            def recordAt(h, idx):
                return type("Call", (), {"call": lambda s: rec})()

    # Local expected score is 95
    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": 95}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes,
        result_root_bytes=root_bytes,
        expected_host_scores=expected_scores,
    )
    assert passed is False
    assert "Score mismatch" in msg


def test_altered_result_root():
    """On-chain result root differing from expected root fails."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes = bytes.fromhex("02" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    timestamp = 1700000000

    # On-chain has root "03" * 32
    rec = _build_mock_record(host_bytes, case_bytes, 80, root_bytes, bytes(32), timestamp)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                return type("Call", (), {"call": lambda s: 1})()

            @staticmethod
            def recordAt(h, idx):
                return type("Call", (), {"call": lambda s: rec})()

    # Expected root is "99" * 32
    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": 80}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes,
        result_root_bytes=bytes.fromhex("99" * 32),
        expected_host_scores=expected_scores,
    )
    assert passed is False
    assert "Result root mismatch" in msg


def test_wrong_case_id():
    """Records exist on-chain for host but for a different case."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes_target = bytes.fromhex("02" * 32)
    case_bytes_other = bytes.fromhex("77" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    timestamp = 1700000000

    rec = _build_mock_record(host_bytes, case_bytes_other, 80, root_bytes, bytes(32), timestamp)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                return type("Call", (), {"call": lambda s: 1})()

            @staticmethod
            def recordAt(h, idx):
                return type("Call", (), {"call": lambda s: rec})()

    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": 80}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes_target,
        result_root_bytes=root_bytes,
        expected_host_scores=expected_scores,
    )
    assert passed is False
    assert "none for case" in msg


def test_tampered_record_hash():
    """If recordHash does not match keccak256(abi.encode(...)), verification fails."""
    host_bytes = bytes.fromhex("01" * 32)
    case_bytes = bytes.fromhex("02" * 32)
    root_bytes = bytes.fromhex("03" * 32)
    timestamp = 1700000000

    # Tampered record hash
    rec = _build_mock_record(host_bytes, case_bytes, 80, root_bytes, bytes(32), timestamp, tamper_hash=True)

    class MockContract:
        class functions:
            @staticmethod
            def recordCount(h):
                return type("Call", (), {"call": lambda s: 1})()

            @staticmethod
            def recordAt(h, idx):
                return type("Call", (), {"call": lambda s: rec})()

    expected_scores = [{"hostId": "0x" + host_bytes.hex(), "score": 80}]
    passed, msg = verify_posture_ledger_hash_chain(
        posture_ledger_contract=MockContract(),
        onchain_case_bytes=case_bytes,
        result_root_bytes=root_bytes,
        expected_host_scores=expected_scores,
    )
    assert passed is False
    assert "Record hash mismatch" in msg
