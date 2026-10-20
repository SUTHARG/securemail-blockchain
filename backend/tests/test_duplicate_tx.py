"""Regression tests for preventing duplicate blockchain transactions after broadcast (Requirement 3).

Verifies:
1. Timeout after broadcast raises TransientRPCError and NEVER broadcasts a second transaction.
2. Delayed receipt recovery: recovers existing transaction hash and confirms receipt when available.
3. Reverted transaction raises TransactionRevertedError without broadcasting again.
4. Duplicate invocation recovers stored transaction rather than sending new transaction.
5. Calldata and destination mismatch rejects reuse of stored transaction.
6. Unknown transaction outcome returns TransientRPCError and does not treat missing data as match.
"""
import threading
from unittest.mock import MagicMock
import pytest
from web3.datastructures import AttributeDict
from backend.chain.gateway import (
    ChainGateway,
    TransientRPCError,
    TransactionRevertedError,
    InvalidStateError,
)
from backend.database import init_db, record_chain_tx, get_chain_tx
import backend.config as config


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    test_db = tmp_path / "test_dup_tx.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def _create_mock_gateway():
    gw = ChainGateway.__new__(ChainGateway)
    gw.w3 = MagicMock()
    gw.w3.eth.get_transaction_count.return_value = 0
    gw.w3.eth.chain_id = 31337
    gw.w3.eth.gas_price = 1000000000
    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    gw.w3.eth.wait_for_transaction_receipt.return_value = None
    gw.analyst_account = MagicMock()
    gw.analyst_account.address = "0x" + "1" * 40
    gw._analyst_lock = threading.Lock()
    gw._send_tx_retry_delay = 0.01
    return gw


def _make_mock_contract_fn(target_addr: str, calldata: str = "0xabcdef"):
    mock_fn = MagicMock()
    mock_fn.address = target_addr
    mock_fn.build_transaction.return_value = {"to": target_addr, "data": calldata}
    mock_fn._encode_transaction_data.return_value = calldata
    mock_fn.estimate_gas.return_value = 100000
    return mock_fn


def test_timeout_after_broadcast_never_rebroadcasts():
    """Once send_raw_transaction returns a hash, receipt timeout raises TransientRPCError and never sends a second raw tx."""
    gw = _create_mock_gateway()
    case_id = "case-timeout-1"
    step = "open"

    mock_contract_fn = _make_mock_contract_fn("0x" + "2" * 40, "0xabcdef")
    gw.analyst_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw-tx-bytes")

    tx_hash_hex = "0x" + "9" * 64
    gw.w3.eth.send_raw_transaction.return_value = bytes.fromhex("9" * 64)
    # wait_for_transaction_receipt raises timeout
    gw.w3.eth.wait_for_transaction_receipt.side_effect = TimeoutError("Polling timed out")
    gw.w3.eth.get_transaction_receipt.return_value = None

    with pytest.raises(TransientRPCError) as exc_info:
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
            max_retries=3,
        )

    assert "receipt wait timed out" in str(exc_info.value).lower()
    # CRITICAL: send_raw_transaction MUST have been called EXACTLY ONCE
    assert gw.w3.eth.send_raw_transaction.call_count == 1

    # Database must have recorded the transaction as 'sent'
    recorded = get_chain_tx(case_id, step)
    assert recorded is not None
    assert recorded["tx_hash"] == tx_hash_hex
    assert recorded["status"] == "sent"


def test_delayed_receipt_recovery():
    """When a transaction was previously stored as 'sent', next call recovers it and waits for receipt without broadcasting."""
    gw = _create_mock_gateway()
    case_id = "case-delayed-receipt"
    step = "open"
    tx_hash = "0x" + "8" * 64
    target_addr = "0x" + "2" * 40
    expected_data = "0xabcdef"

    # Pre-record as sent
    record_chain_tx(case_id, step, 5, tx_hash, "sent", 0)

    mock_contract_fn = _make_mock_contract_fn(target_addr, expected_data)

    # Node returns stored tx matching calldata and address
    gw.w3.eth.get_transaction.return_value = {
        "hash": bytes.fromhex("8" * 64),
        "nonce": 5,
        "to": target_addr,
        "input": expected_data,
    }
    # Receipt is now available with status 1
    mock_receipt = AttributeDict({"status": 1, "transactionHash": bytes.fromhex("8" * 64), "blockNumber": 100})
    gw.w3.eth.get_transaction_receipt.return_value = mock_receipt
    gw.w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

    receipt = gw._send_tx(
        contract_fn=mock_contract_fn,
        account=gw.analyst_account,
        lock=gw._analyst_lock,
        case_id=case_id,
        step=step,
    )

    assert receipt.status == 1
    # send_raw_transaction MUST NOT be called at all
    assert gw.w3.eth.send_raw_transaction.call_count == 0

    # Recorded status updated to confirmed
    recorded = get_chain_tx(case_id, step)
    assert recorded["status"] == "confirmed"


def test_reverted_transaction_raises_and_persists():
    """A reverted receipt status raises TransactionRevertedError and records status 'reverted'."""
    gw = _create_mock_gateway()
    case_id = "case-reverted-1"
    step = "open"
    tx_hash = "0x" + "7" * 64
    target_addr = "0x" + "2" * 40
    expected_data = "0xabcdef"

    record_chain_tx(case_id, step, 6, tx_hash, "sent", 0)

    mock_contract_fn = _make_mock_contract_fn(target_addr, expected_data)

    gw.w3.eth.get_transaction.return_value = {
        "hash": bytes.fromhex("7" * 64),
        "nonce": 6,
        "to": target_addr,
        "input": expected_data,
    }
    mock_receipt = AttributeDict({"status": 0, "transactionHash": bytes.fromhex("7" * 64)})
    gw.w3.eth.get_transaction_receipt.return_value = mock_receipt
    gw.w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

    with pytest.raises(TransactionRevertedError):
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
        )

    recorded = get_chain_tx(case_id, step)
    assert recorded["status"] == "reverted"
    assert gw.w3.eth.send_raw_transaction.call_count == 0


def test_calldata_mismatch_rejects_stored_transaction():
    """If stored transaction has different calldata or recipient, reuse is rejected with InvalidStateError."""
    gw = _create_mock_gateway()
    case_id = "case-mismatch-1"
    step = "open"
    tx_hash = "0x" + "6" * 64
    target_addr = "0x" + "2" * 40

    record_chain_tx(case_id, step, 7, tx_hash, "sent", 0)

    mock_contract_fn = _make_mock_contract_fn(target_addr, "0x999999")

    gw.w3.eth.get_transaction.return_value = {
        "hash": bytes.fromhex("6" * 64),
        "nonce": 7,
        "to": target_addr,
        "input": "0x111111",  # Mismatched calldata!
    }

    with pytest.raises(InvalidStateError) as exc_info:
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
        )

    assert "calldata or destination mismatch" in str(exc_info.value).lower()
    assert gw.w3.eth.send_raw_transaction.call_count == 0


def test_unknown_transaction_returns_pending_error():
    """If stored transaction cannot be found on RPC, does not assume match; raises TransientRPCError."""
    gw = _create_mock_gateway()
    case_id = "case-unknown-1"
    step = "open"
    tx_hash = "0x" + "5" * 64
    target_addr = "0x" + "2" * 40

    record_chain_tx(case_id, step, 8, tx_hash, "sent", 0)

    mock_contract_fn = _make_mock_contract_fn(target_addr, "0xabcdef")

    # RPC returns None for get_transaction and timeout for receipts
    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    gw.w3.eth.wait_for_transaction_receipt.side_effect = TimeoutError("Not mined")

    with pytest.raises(TransientRPCError) as exc_info:
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
        )

    assert "pending confirmation" in str(exc_info.value).lower() or "already broadcast" in str(exc_info.value).lower()
    assert gw.w3.eth.send_raw_transaction.call_count == 0


def test_crash_recovery_between_signing_and_broadcast_rebroadcasts_exact_raw_tx():
    """If process crashes after signing (intent with raw_tx), retry rebroadcasts exact raw_tx without creating new tx."""
    gw = _create_mock_gateway()
    case_id = "case-crash-intent-1"
    step = "open"
    tx_hash = "0x" + "4" * 64
    raw_tx_bytes = b"\x02\xf8\x70\x01\x82test-raw-tx"
    raw_tx_hex = raw_tx_bytes.hex()
    target_addr = "0x" + "2" * 40

    # Persist as 'intent' before crash
    record_chain_tx(case_id, step, 10, tx_hash, "intent", 0, raw_tx=raw_tx_hex)

    mock_contract_fn = _make_mock_contract_fn(target_addr, "0xabcdef")

    # On recovery, get_transaction returns None initially
    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    # send_raw_transaction accepts the exact raw_tx
    gw.w3.eth.send_raw_transaction.return_value = bytes.fromhex("4" * 64)
    # wait_for_transaction_receipt times out before broadcast, then returns confirmed receipt after broadcast
    mock_receipt = AttributeDict({"status": 1, "transactionHash": bytes.fromhex("4" * 64)})
    gw.w3.eth.wait_for_transaction_receipt.side_effect = [TimeoutError("Not yet broadcast"), mock_receipt]

    receipt = gw._send_tx(
        contract_fn=mock_contract_fn,
        account=gw.analyst_account,
        lock=gw._analyst_lock,
        case_id=case_id,
        step=step,
    )

    assert receipt.status == 1
    # MUST have broadcast the exact raw_tx bytes that were stored before crash
    gw.w3.eth.send_raw_transaction.assert_called_once_with(raw_tx_bytes)
    # MUST NOT have created a new signed transaction
    assert gw.analyst_account.sign_transaction.call_count == 0

    # Database updated to confirmed
    rec = get_chain_tx(case_id, step)
    assert rec["status"] == "confirmed"
    assert rec["raw_tx"] == raw_tx_hex


def test_latest_nonce_higher_does_not_assume_dropped_preserves_state():
    """Do not treat latest_nonce > saved_nonce as proof of drop; preserve state and stop."""
    gw = _create_mock_gateway()
    case_id = "case-nonce-high-1"
    step = "open"
    tx_hash = "0x" + "3" * 64
    target_addr = "0x" + "2" * 40

    # Stored as sent with nonce 5
    record_chain_tx(case_id, step, 5, tx_hash, "sent", 0)

    mock_contract_fn = _make_mock_contract_fn(target_addr, "0xabcdef")

    # Receipt is not available
    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    gw.w3.eth.wait_for_transaction_receipt.side_effect = TimeoutError("No receipt")
    # Latest confirmed nonce is 6 (> 5)
    gw.w3.eth.get_transaction_count.return_value = 6

    with pytest.raises(TransientRPCError) as exc_info:
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
        )

    # Must STOP and preserve state, never broadcast a new transaction
    assert "outcome is unknown" in str(exc_info.value).lower()
    assert gw.w3.eth.send_raw_transaction.call_count == 0
    # Status in database must remain sent (not marked dropped)
    rec = get_chain_tx(case_id, step)
    assert rec["status"] == "sent"
    assert rec["tx_hash"] == tx_hash


def test_database_update_cannot_erase_recorded_intent():
    """Updates to chain_txs with None tx_hash/nonce must not erase previously stored intent/raw_tx."""
    case_id = "case-persist-intent"
    step = "claim"
    record_chain_tx(case_id, step, 12, "0x" + "a" * 64, "intent", 0, raw_tx="aabbccdd")

    # Attempt update on failure where tx_hash and nonce are None
    record_chain_tx(case_id, step, None, None, "reverted", 1, raw_tx=None)

    rec = get_chain_tx(case_id, step)
    assert rec["status"] == "reverted"
    # Nonce, tx_hash, and raw_tx MUST NOT be erased to None!
    assert rec["nonce"] == 12
    assert rec["tx_hash"] == "0x" + "a" * 64
    assert rec["raw_tx"] == "aabbccdd"


def test_intent_rebroadcast_already_known_reconciles_and_waits_for_receipt():
    """If rebroadcasting intent returns 'already known', gateway transitions to sent and waits for receipt."""
    gw = _create_mock_gateway()
    case_id = "case-already-known-1"
    step = "open"
    tx_hash = "0x" + "7" * 64
    raw_tx_bytes = b"\x02\xf8\x70\x01\x82already-known-bytes"
    raw_tx_hex = raw_tx_bytes.hex()
    target_addr = "0x" + "2" * 40

    record_chain_tx(case_id, step, 15, tx_hash, "intent", 0, raw_tx=raw_tx_hex)
    mock_contract_fn = _make_mock_contract_fn(target_addr, "0xabcdef")

    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    # send_raw_transaction raises 'already known'
    gw.w3.eth.send_raw_transaction.side_effect = Exception("already known: transaction is already in mempool")

    mock_receipt = AttributeDict({"status": 1, "transactionHash": bytes.fromhex("7" * 64)})
    gw.w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

    receipt = gw._send_tx(
        contract_fn=mock_contract_fn,
        account=gw.analyst_account,
        lock=gw._analyst_lock,
        case_id=case_id,
        step=step,
    )

    assert receipt.status == 1
    rec = get_chain_tx(case_id, step)
    assert rec["status"] == "confirmed"


def test_receipt_rpc_failure_preserves_sent_state():
    """If RPC fails during receipt polling, gateway raises TransientRPCError and preserves sent state."""
    gw = _create_mock_gateway()
    case_id = "case-rpc-failure-1"
    step = "open"
    tx_hash = "0x" + "6" * 64
    target_addr = "0x" + "2" * 40

    record_chain_tx(case_id, step, 20, tx_hash, "sent", 0)
    mock_contract_fn = _make_mock_contract_fn(target_addr, "0xabcdef")

    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.side_effect = ConnectionError("RPC node unreachable")
    gw.w3.eth.wait_for_transaction_receipt.side_effect = ConnectionError("RPC node unreachable")

    with pytest.raises(TransientRPCError) as exc_info:
        gw._send_tx(
            contract_fn=mock_contract_fn,
            account=gw.analyst_account,
            lock=gw._analyst_lock,
            case_id=case_id,
            step=step,
        )

    assert "outcome is unknown" in str(exc_info.value).lower() or "already broadcast" in str(exc_info.value).lower()
    assert gw.w3.eth.send_raw_transaction.call_count == 0
    rec = get_chain_tx(case_id, step)
    assert rec["status"] == "sent"
