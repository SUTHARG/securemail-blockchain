"""Clean End-to-End Demonstration for SecureMailScope.

Runs full lifecycle using an isolated demo database and case-storage directory:
1. Fresh, isolated demo database and storage (unique timestamped directory by default).
2. Uses lab/captures/S05.pcap.
3. Uploads, encrypts at rest, and runs deterministic engine analysis.
4. Opens case on-chain on local Hardhat EVM (records tx hash and onchain ID).
5. Submits claimed Merkle root to ValidationQuorum (records tx hash).
6. Runs 3 validator nodes with commit and reveal lifecycle against Hardhat node.
7. Finalizes quorum consensus on-chain (records tx hash).
8. Records per-host posture on PostureLedger with Merkle proofs (records tx hashes).
9. Anchors deterministic report hash in CaseRegistry (records tx hash).
10. Executes 5-step independent verification suite (all 5 steps PASS).
11. Verifies browser overview and chain HTML dashboards render actual on-chain ID,
    actual transaction hashes, and separate local vs on-chain statuses.

Safety Rules:
- Never touches or modifies real data/smscope.db or data/cases.
- Does not silently delete existing demo data; uses unique run directories by default
  or requires explicit --reset-demo if targeting a fixed path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

# Set up paths
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description="Run isolated clean demonstration.")
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Custom demo output directory. If omitted, a unique timestamped directory under data/demo_runs/ is used.",
    )
    parser.add_argument(
        "--reset-demo",
        action="store_true",
        help="Explicitly permit wiping the specified output directory if it already exists.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Determine isolated output directory
    if args.output_dir:
        demo_run_dir = Path(args.output_dir).resolve()
        demo_db = demo_run_dir / "smscope.db"
        demo_cases_dir = demo_run_dir / "cases"

        if demo_run_dir.exists() and any(demo_run_dir.iterdir()):
            if not args.reset_demo:
                print(f"[!] Error: Target demo directory '{demo_run_dir}' already exists and is not empty.", file=sys.stderr)
                print("[!] To prevent accidental deletion, run without --output-dir (unique directory default)", file=sys.stderr)
                print("[!] or explicitly pass --reset-demo to reset this specific demo directory.", file=sys.stderr)
                sys.exit(1)
            print(f"[*] --reset-demo specified: cleaning existing directory {demo_run_dir}...")
            shutil.rmtree(demo_run_dir)
    else:
        # Default: unique timestamped run directory
        run_id = int(time.time())
        demo_run_dir = REPO_ROOT / "data" / "demo_runs" / f"run_{run_id}"
        demo_db = demo_run_dir / "smscope.db"
        demo_cases_dir = demo_run_dir / "cases"

    demo_run_dir.mkdir(parents=True, exist_ok=True)
    demo_cases_dir.mkdir(parents=True, exist_ok=True)

    # Configure backend environment using the project's actual configuration mechanism
    os.environ["DATA_DIR"] = str(demo_run_dir)
    os.environ["DB_PATH"] = str(demo_db)

    import backend.config as config
    config.DATA_DIR = demo_run_dir
    config.CASES_DIR = demo_cases_dir
    config.DB_PATH = demo_db

    print("=" * 80)
    print("      SECUREMAILSCOPE: CLEAN ISOLATED END-TO-END DEMONSTRATION")
    print("=" * 80)
    print(f"[*] Demo Run Directory: {demo_run_dir}")
    print(f"[*] Demo Database:      {demo_db}")
    print(f"[*] Demo Case Storage:  {demo_cases_dir}")
    print(f"[*] Real App DB:        {REPO_ROOT / 'data' / 'smscope.db'} (untouched)")
    print(f"[*] PCAP Capture:       lab/captures/S05.pcap\n")

    # Import backend and chain modules after configuring environment
    from backend.database import init_db, create_case, get_case, get_chain_txs, list_all_cases
    from backend.storage import get_case_dir, write_case_json, read_case_json, read_case_pcap
    from backend.runner import execute_analysis
    from backend.chain.gateway import ChainGateway
    from backend.app import _compute_verifier_steps_and_state, get_gateway, app, distribute_case
    from validator.crypto import encrypt_at_rest
    from fastapi.testclient import TestClient
    from web3 import Web3
    from eth_account import Account
    from eth_abi import encode
    from engine.smscope.results.canonical import canonical_json
    from engine.smscope.results.hashing import finding_leaf, host_score_leaf
    from engine.smscope.results.merkle import MerkleTree

    # Initialize isolated demo database
    init_db()
    print("[+] Isolated demo database initialized.")

    # 1. Ingest S05.pcap via normal application pipeline
    pcap_source = REPO_ROOT / "lab" / "captures" / "S05.pcap"
    if not pcap_source.exists():
        print(f"[!] Prerequisite Missing: PCAP capture '{pcap_source}' not found.", file=sys.stderr)
        sys.exit(1)

    pcap_raw = pcap_source.read_bytes()
    pcap_sha = hashlib.sha256(pcap_raw).hexdigest()

    client = TestClient(app)
    client.headers["X-API-Key"] = config.ANALYST_API_KEY
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    csrf_token = "clean-demo-csrf"
    client.cookies.set("csrf_token", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    print(f"[*] Step 0: Uploading {pcap_source.name} through normal application pipeline (/cases)...")
    upload_resp = client.post(
        "/cases",
        files={"file": (pcap_source.name, pcap_raw, "application/vnd.tcpdump.pcap")},
    )
    assert upload_resp.status_code == 201, f"Upload failed: {upload_resp.text}"
    case_info = upload_resp.json()
    case_id = case_info["caseId"]
    assert case_info["pcapSha256"] == pcap_sha, "Uploaded PCAP SHA-256 mismatch!"
    print(f"[+] Case {case_id} registered via API upload. Status: {case_info['status']}")

    # Confirm stored PCAP can be read and decrypted, and its SHA-256 matches upload
    stored_pcap = read_case_pcap(case_id)
    decrypted_sha = hashlib.sha256(stored_pcap).hexdigest()
    assert decrypted_sha == pcap_sha, f"Decrypted PCAP SHA mismatch: {decrypted_sha} != {pcap_sha}"
    print(f"[+] Stored PCAP successfully read & decrypted from storage. SHA-256: {decrypted_sha}")

    # 2. Run Engine Analysis
    print("[*] Running deterministic forensic engine analysis...")
    analysis_ok = execute_analysis(case_id=case_id, use_docker=False)
    if not analysis_ok:
        print("[!] Engine analysis failed!", file=sys.stderr)
        sys.exit(1)

    from backend.reports.builder import build_case_report
    build_case_report(case_id, save=True)

    # Verify all expected analysis files exist and match
    manifest_data = read_case_json(case_id, "manifest.json")
    assert manifest_data["pcapSha256"] == pcap_sha, "Manifest pcapSha256 mismatch!"
    findings_data = read_case_json(case_id, "findings.json")
    sessions_data = read_case_json(case_id, "sessions.json")
    host_scores = read_case_json(case_id, "host_scores.json")
    host_proofs = read_case_json(case_id, "host_proofs.json")
    result_data = read_case_json(case_id, "result.json")
    report_data = read_case_json(case_id, "report.json")
    assert (get_case_dir(case_id) / "report.html").exists(), "report.html missing!"
    print(f"[+] All expected analysis files verified for case {case_id}:")
    print(f"    - findings.json ({len(findings_data)} findings)")
    print(f"    - host_scores.json ({len(host_scores)} hosts)")
    print(f"    - sessions.json ({len(sessions_data)} sessions)")
    print(f"    - host_proofs.json ({len(host_proofs)} proofs)")
    print(f"    - result.json (resultRoot: {result_data['resultRoot']})")
    print(f"    - manifest.json (rulesetHash: {manifest_data.get('rulesetHash')})")
    print(f"    - report.json & report.html")

    # 3. Recompute and verify result Merkle root
    result_root = result_data["resultRoot"]
    leaves = [finding_leaf(canonical_json(f)) for f in findings_data]
    for s in host_scores:
        leaves.append(host_score_leaf(s["hostId"], s["findingsDigest"], int(s["score"])))
    rebuilt_tree = MerkleTree(leaves)
    rebuilt_root = rebuilt_tree.root_hex.lower()
    expected_root = result_root.lower().replace("0x", "")
    assert rebuilt_root == expected_root, f"Recomputed Merkle root {rebuilt_root} != {expected_root}"
    print(f"[+] Merkle Root Recomputation PASS: {rebuilt_root}")

    # 4. Connect to Hardhat Gateway and check availability & contract code
    gateway = get_gateway()
    w3 = gateway.w3
    if not w3.is_connected():
        print("[!] Prerequisite Missing: Cannot connect to local Hardhat node on port 8545.", file=sys.stderr)
        print("[!] Please start the node with `npx hardhat node` and deploy contracts.", file=sys.stderr)
        sys.exit(1)

    chain_id = w3.eth.chain_id
    assert chain_id == 31337, f"Unexpected chain ID: {chain_id} (expected 31337)"
    print(f"[+] Connected to local Hardhat chain (Chain ID {chain_id}, Block #{w3.eth.block_number})")

    # Verify contract code on chain
    for c_name, c_inst in [
        ("Roles", gateway.roles),
        ("CaseRegistry", gateway.case_registry),
        ("ValidationQuorum", gateway.quorum),
        ("PostureLedger", gateway.posture_ledger),
    ]:
        code = w3.eth.get_code(c_inst.address)
        assert len(code) > 2, f"No bytecode found at {c_name} address {c_inst.address}"
        print(f"    - {c_name} at {c_inst.address} (bytecode size: {len(code)} bytes)")

    # Ensure engine and validators are registered on CaseRegistry if needed
    expected_ruleset = bytes.fromhex(manifest_data["rulesetHash"].replace("0x", ""))
    try:
        active_digest, active_ruleset = gateway.case_registry.functions.activeEngine().call()
        if active_ruleset != expected_ruleset or active_digest == bytes(32):
            print("[*] Registering active engine & ruleset hash on CaseRegistry...")
            engine_digest = active_digest if active_digest != bytes(32) else hashlib.sha256(b"smscope:latest").digest()
            reg_fn = gateway.case_registry.functions.registerEngine(engine_digest, expected_ruleset)
            rcpt = gateway._send_tx(reg_fn, gateway.admin_account, gateway._admin_lock)
            assert rcpt.status == 1, "Failed to register engine on-chain"
            print(f"[+] Engine registered on-chain: tx={rcpt.transactionHash.hex()}")
        else:
            print(f"[+] Active engine & ruleset verified on CaseRegistry:")
            print(f"    - activeImageDigest: 0x{active_digest.hex()}")
            print(f"    - activeRulesetHash: 0x{active_ruleset.hex()}")
    except Exception as exc:
        print(f"[*] Engine check note: {exc}")

    val_keys = [
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    ]
    val_count = gateway.case_registry.functions.validatorCount().call()
    if val_count < 3:
        print(f"[*] Validator count is {val_count}, registering standard validators...")
        for key in val_keys:
            val_addr = Account.from_key(key).address
            if not gateway.case_registry.functions.isValidator(val_addr).call():
                add_fn = gateway.case_registry.functions.addValidator(val_addr)
                rcpt = gateway._send_tx(add_fn, gateway.admin_account, gateway._admin_lock)
                assert rcpt.status == 1, f"Failed to add validator {val_addr}"
                print(f"[+] Added validator {val_addr}: tx={rcpt.transactionHash.hex()}")

    # 5. Open Case On-Chain
    print("\n[*] Step 1: Opening case on-chain via CaseRegistry.openCase()...")
    open_res = gateway.open_case(case_id)
    onchain_case_id = open_res["onchainCaseId"]
    open_tx = open_res["txHash"]
    rcpt_open = w3.eth.wait_for_transaction_receipt(open_tx)
    assert rcpt_open.status == 1, "openCase receipt status failed!"
    print(f"[+] Case opened on-chain! (Receipt: block {rcpt_open.blockNumber}, gas {rcpt_open.gasUsed})")
    print(f"    On-Chain Case ID: {onchain_case_id}")
    print(f"    Transaction Hash: {open_tx}")

    # 5. Submit Claim
    print("[*] Step 2: Submitting forensic result root to ValidationQuorum...")
    claim_res = gateway.submit_claim(case_id)
    claim_tx = claim_res["txHash"]
    rcpt_claim = w3.eth.wait_for_transaction_receipt(claim_tx)
    assert rcpt_claim.status == 1, "submit_claim receipt status failed!"
    print(f"[+] Claim submitted on-chain! (Receipt: block {rcpt_claim.blockNumber}, gas {rcpt_claim.gasUsed})")
    print(f"    Claimed Root:     {claim_res.get('claimedRoot') or claim_res.get('root')}")
    print(f"    Transaction Hash: {claim_tx}")

    # 6. Distribute Bundles to Validator Inboxes
    print("\n[*] Step 3: Distributing sealed bundles to validator inboxes via distribute_case()...")
    import asyncio
    dist_res = asyncio.run(distribute_case(case_id, actor="analyst"))
    assert dist_res["status"] == "distributed"
    print(f"[+] Case bundles distributed to {len(dist_res['inboxes'])} validator inboxes:")
    for ib in dist_res["inboxes"]:
        print(f"    - {ib}")

    # 7. Validator Consensus (Commit & Reveal)
    print("\n[*] Step 4: Running independent validator consensus nodes (commit & reveal)...")
    val_res = gateway.run_validator_round(case_id)
    assert val_res["quorumReached"] == True, f"Quorum was not reached: {val_res}"
    print(f"[+] Validator consensus successfully completed!")
    print(f"    Quorum Round:    Round #{val_res['round']}")
    print(f"    Total Commits:   {val_res['commits']}")
    print(f"    Matching Reveals:{val_res['reveals']}/{val_res['quorum']}")
    print(f"    Quorum Status:   {'REACHED' if val_res['quorumReached'] else 'PENDING'}")

    # 7. Finalize Case On-Chain
    print("[*] Step 4: Finalizing consensus quorum on-chain...")
    fin_res = gateway.finalize(case_id)
    fin_tx = fin_res["txHash"]
    rcpt_fin = w3.eth.wait_for_transaction_receipt(fin_tx)
    assert rcpt_fin.status == 1, "finalize receipt status failed!"
    onchain_bytes = bytes.fromhex(onchain_case_id.replace("0x", ""))
    final_root = "0x" + gateway.case_registry.functions.finalRoot(onchain_bytes).call().hex()
    print(f"[+] Case successfully Finalized on-chain! (Receipt: block {rcpt_fin.blockNumber}, gas {rcpt_fin.gasUsed})")
    print(f"    Finalized Root:   {final_root}")
    print(f"    Transaction Hash: {fin_tx}")

    # 8. Record Host Posture Scores on PostureLedger
    print(f"[*] Step 5: Recording per-host security posture on PostureLedger for {len(host_scores)} hosts...")
    rec_res = gateway.record_posture(case_id)
    recorded_hosts = rec_res["hosts"]
    for h in recorded_hosts:
        h_tx = h.get("txHash")
        if h_tx:
            rcpt_h = w3.eth.wait_for_transaction_receipt(h_tx)
            assert rcpt_h.status == 1, f"record_posture failed for {h['hostId']}"
            print(f"    Host {h['hostId'][:14]}...: status={h['status']}, tx={h_tx[:18]}... (gas: {rcpt_h.gasUsed})")
        else:
            print(f"    Host {h['hostId'][:14]}...: status={h['status']}")

    # 9. Anchor Custody Report Hash
    print("[*] Step 6: Anchoring canonical custody report hash in CaseRegistry...")
    anch_res = gateway.anchor_report(case_id)
    anch_tx = anch_res["txHash"]
    rcpt_anch = w3.eth.wait_for_transaction_receipt(anch_tx)
    assert rcpt_anch.status == 1, "anchor_report receipt status failed!"
    report_hash = anch_res["reportHash"]
    print(f"[+] Report hash anchored on-chain! (Receipt: block {rcpt_anch.blockNumber}, gas {rcpt_anch.gasUsed})")
    print(f"    Report Hash:      {report_hash}")
    print(f"    Transaction Hash: {anch_tx}")

    # 10. Run 5-Step Independent Verification Suite
    print("\n" + "=" * 80)
    print("      SECTION 8: 5-STEP INDEPENDENT VERIFICATION EXECUTION")
    print("=" * 80)
    steps, chain_info, validators, txs, all_passed = _compute_verifier_steps_and_state(case_id)
    for s in steps:
        verdict = s["status"]
        print(f"  Step {s['step']}: {s['name']}")
        print(f"    Verdict: [{verdict}] - {s['details']}")
    print(f"  --> OVERALL VERIFICATION: {'PASS' if all_passed else 'FAIL'}")
    assert all_passed, "Verification suite did not pass all 5 steps!"

    # 11. Verify Server-Rendered HTML Dashboards
    print("\n" + "=" * 80)
    print("      DASHBOARD HTML RENDERING & STATUS SEPARATION AUDIT")
    print("=" * 80)
    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "demo-token")

    # Fetch Case Overview Page
    client.headers["X-API-Key"] = config.ANALYST_API_KEY
    res_overview = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res_overview.status_code == 200, f"Overview returned status {res_overview.status_code}"
    ov_html = res_overview.text
    assert onchain_case_id in ov_html, "On-chain Case ID missing from Overview HTML!"
    assert "report_anchored" in ov_html, "Local status missing!"
    assert "Finalized (Quorum Agreed)" in ov_html, "On-chain consensus status missing from Overview HTML!"
    print("[+] Overview HTML verified: Displays separate Local Processing Status and On-Chain Consensus State.")

    # Fetch Chain Ledger & Verification Page
    res_chain = client.get(f"/cases/{case_id}/chain", headers={"Accept": "text/html"})
    assert res_chain.status_code == 200
    chain_html = res_chain.text
    assert "Section 8: Independent Verification Suite" in chain_html
    assert "Audit Notice:" in chain_html
    print("[+] Chain HTML verified: Displays independent verification suite and audit notice.")

    # Trigger Browser Verification Button (/cases/{case_id}/chain/verify)
    res_verify_btn = client.post(f"/cases/{case_id}/chain/verify", data={"csrf_token": "demo-token"})
    assert res_verify_btn.status_code == 200
    v_html = res_verify_btn.text
    assert "OVERALL: PASS" in v_html
    print("[+] Browser Verify action verified: Form submission executes verification and renders OVERALL: PASS.")

    # 12. Transaction Log Table
    print("\n" + "=" * 80)
    print("              FINAL DEMONSTRATION ON-CHAIN TRANSACTION LOG")
    print("=" * 80)
    case_txs = get_chain_txs(case_id)
    print(f"{'Step':<18} | {'Nonce':<6} | {'Status':<10} | {'Transaction Hash'}")
    print("-" * 80)
    for tx in case_txs:
        print(f"{tx['step']:<18} | {str(tx['nonce']):<6} | {tx['status']:<10} | {tx['tx_hash']}")
    # Verify database isolation
    demo_cases = list_all_cases()
    assert len(demo_cases) == 1, f"Demo database should have exactly 1 case, found {len(demo_cases)}"
    assert demo_cases[0]["id"] == case_id, f"Demo database contains unexpected case {demo_cases[0]['id']}"
    print(f"[+] Isolated database verified: Contains exactly 1 demonstration case ({case_id}).")

    print(f"[DEMO COMPLETE] Case {case_id} successfully verified end-to-end against local Hardhat chain!")
    print(f"[+] Isolated artifacts preserved in: {demo_run_dir}")
    print(f"[+] Normal database untouched:       {REPO_ROOT / 'data' / 'smscope.db'}")


if __name__ == "__main__":
    main()
