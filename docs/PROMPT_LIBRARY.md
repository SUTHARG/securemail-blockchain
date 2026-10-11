# SecureMailScope: Antigravity prompt library

Prompts for building the project solo, in order. Tier 1 is the required path. Tier 2 and Tier 3 are optional additions after Tier 1 passes. Every prompt names the context to attach, the task, and an acceptance check you run yourself.

## How to use this library

1. **One prompt per agent session.** Never combine prompts.
2. **Attach context.** Always attach AGENT\_RULES.md and the sections of docs/ARCHITECTURE.md named in the prompt. Later prompts also name earlier files to attach.
3. **Run the acceptance check yourself.** Do not rely on the agent's statement that tests pass.
4. **Run Template A (audit)** after every phase. In phases 2 and 5, run it after every prompt.
5. **Commit after each passing prompt** with the message `P<n>.<m> done`, so a bad session can be reverted.
6. **Record decisions.** Any choice the agent makes that the architecture doc does not define goes in docs/decisions/ as a numbered file. If the agent skipped this, reject the change.
7. **If a prompt fails twice,** use Template B with the failing output instead of rewriting the prompt.
8. **Never paste secrets** into prompts. Secrets live in .env only.

Values in angle brackets are placeholders you fill in.

## Standing file: AGENT\_RULES.md

Paste this at the repo root before prompt 0.1 and keep it updated.

```
RULES FOR ALL WORK ON SECUREMAILSCOPE
1. docs/ARCHITECTURE.md is the specification. Do not invent behavior it does not define. If something is ambiguous or missing, STOP and list your questions instead of choosing. If I tell you to proceed, record each choice in docs/decisions/NNN-title.md.
2. The engine is deterministic: the same PCAP and the same engine release give byte-identical output. No wall-clock time, random values, floats, dict or set iteration order, locale, or timezone in any hashed or written output. Sort explicitly.
3. Hashed data uses integers and ASCII keys only. Timestamps are integer epoch seconds taken from the PCAP record header, never converted through floats.
4. Never store, log, or print credential values or email content. Evidence is stream and packet references only.
5. The engine is passive: it never makes a network call.
6. Only hashes and results go on-chain. No PCAP content or raw evidence.
7. Every module ships with tests. A task is not done until its tests pass and the acceptance check in the prompt is satisfied.
8. Pin exact dependency versions. Do not add a dependency the prompt does not allow without asking.
9. Do not change files outside the scope of the prompt. List every file you created or changed at the end.
10. Prefer simple code that is easy to review over clever code.
SCOPE (Tier 1): implement SMTP only. IMAP and POP3 raise NotImplementedError and are future work. Implement only rules R01, R02, R03, R06, R08, R09, R11, R12, R13, R15, R16, R19. No ML, no LLM, no Postgres, no job queue. Recommendations come from static templates. Validators are local processes. Tier 2 and Tier 3 prompts lift these limits one at a time.
```

## Template A: spec-compliance audit

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md. Audit the code produced in <phase or paths> against the specification. Do not change code. Write docs/audits/<phase>.md containing: (1) every place where behavior differs from the specification, with file and line; (2) every undefined choice that is missing from docs/decisions/; (3) every violation of AGENT_RULES.md (floats, wall-clock use, unordered iteration in written output, credential or payload logging, network calls in the engine); (4) requirements in specification sections <sections> that have no test. Be specific. Do not write praise.
```

## Template B: fix a failure

```
Read AGENT_RULES.md. This test or check fails: <paste the exact command and the full output>. Find the root cause before changing anything and explain it. Fix the code, not the test, unless the test contradicts docs/ARCHITECTURE.md; if it does, say so and stop. Add a regression test. List every file changed.
```

## Phase 0: foundations

### Prompt 0.1: repository bootstrap

Attach: AGENT\_RULES.md.

```
Read AGENT_RULES.md.
Create the repository skeleton for SecureMailScope:
  docs/ARCHITECTURE.md (placeholder; I will paste the real file), docs/decisions/, docs/audits/
  spec/schemas/, spec/test-vectors/
  engine/smscope/{ingest,protocols,tls,certs,rules,results}/ each with __init__.py, and engine/tests/
  contracts/ (empty Hardhat TypeScript project), validator/, verifier/, backend/, lab/, eval/, dashboard/
1. The engine is Python. Create pyproject.toml pinning exact versions of pytest, dpkt, cryptography, jsonschema and hypothesis. Write the Python version in .python-version.
2. Makefile targets: test-engine, test-contracts, test (both), lint.
3. A GitHub Actions workflow that runs make test on every push.
4. docs/decisions/000-template.md and docs/decisions/000-platform.md recording: EVM, Solidity and Hardhat for contracts; Python for engine and backend.
5. .gitignore must exclude: private keys, .env, node_modules, __pycache__, lab/ca/out/, data/, validator_state/, and lab/captures/*.pcap larger than 50 MB.
6. .env.example listing variable NAMES only, no values: ORG_SECRET_HEX, ADMIN_KEY, ANALYST_KEY, VALIDATOR_KEY_1, VALIDATOR_KEY_2, VALIDATOR_KEY_3, RPC_URL, ANALYST_API_KEY, ADMIN_API_KEY.
Do not write application logic.
Acceptance: make test runs and passes with zero tests, the CI file is valid, no secret value exists anywhere in the repository.
```

## Phase 1: shared specification and results library

### Prompt 1.1: schemas, canonical JSON, hashing, Merkle tree

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 5.1 to 5.4.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 5.1 to 5.4.
Create the shared specification and the Python results library. Use only the standard library plus jsonschema.

PART 1: decisions. Write docs/decisions/001-hashing-and-ids.md BEFORE coding, containing exactly these decisions:
- endpoint string: IPv4 is 'a.b.c.d:port'; IPv6 is '[address]:port' with the address in compressed lowercase form.
- findingId = SHA-256 over the ASCII bytes of '<ruleId>|<serverEndpoint>', as lowercase hex.
- findingsDigest (per host) = SHA-256 over the concatenation of that host's findingIds as 32-byte values sorted ascending as bytes.
- hostId = HMAC-SHA-256 with key = organization secret bytes and message = the ASCII endpoint string; 32 bytes.
- Merkle tree: leaves sorted ascending by hash bytes; duplicate leaves rejected; an empty leaf list rejected; the root of a single leaf is that leaf; an odd node at any level is carried up unchanged.

PART 2: code.
1. spec/schemas/: JSON Schemas for session record, finding, host score and case manifest exactly as in sections 5.1 to 5.4. Integers only.
2. engine/smscope/results/canonical.py: canonical_json(obj) -> bytes. UTF-8, sorted keys, separators (',', ':'), no whitespace. Raise on floats, NaN, and non-ASCII keys.
3. engine/smscope/results/hashing.py:
   finding_leaf(canonical_bytes) = SHA-256(0x00 + bytes)
   host_score_leaf(host_id, findings_digest, score) = SHA-256(0x02 + host_id[32] + findings_digest[32] + score as 2-byte big-endian)
   node(a, b) = SHA-256(0x01 + min(a,b) + max(a,b))
   plus finding_id, findings_digest, host_id.
4. engine/smscope/results/merkle.py: build_tree(leaves), root(), proof(leaf), verify(leaf, proof, root) following the decisions above. Proofs need no left or right flags because node hashing sorts its inputs.
5. spec/test-vectors/: JSON files with vectors for every hash function (inputs and outputs in hex) and for trees of 1, 2, 3, 4 and 5 leaves mixing finding leaves and host-score leaves, with the root and the proof of every leaf.
6. pytest tests that load the vectors, plus seeded property tests proving that every leaf verifies and that a changed leaf fails.
7. At the end print three shell commands (using sha256sum or openssl dgst -sha256, with xxd for hex input) that recompute three different vectors independently.
Acceptance: tests pass, and when I run the three printed commands the outputs match the vectors.
```

## Phase 2: smart contracts

### Prompt 2.1: roles, case registry, engine pinning, validator list

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 6.1, 6.2, 6.3, 6.7, 6.8.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 6.1, 6.2, 6.3, 6.7, 6.8.
In contracts/ (Hardhat, TypeScript, Solidity 0.8.x with a pinned compiler version, OpenZeppelin AccessControl with a pinned version) implement:

contracts/Roles.sol: constants ADMIN_ROLE, ANALYST_ROLE, VALIDATOR_ROLE, QUORUM_ROLE (QUORUM_ROLE is granted only to the ValidationQuorum contract). The deployer receives ADMIN_ROLE. Record this as a demo simplification in docs/decisions/002-admin-simplification.md.

contracts/CaseRegistry.sol:
- enum State { None, Opened, Claimed, Committing, Revealing, Finalized, Disputed, Expired, Rejected }
- struct Case { address analyst; bytes32 pcapHash; State state; bytes32 claimedRoot; bytes32 finalRoot; bool contradicted; bytes32 engineHash; bytes32 rulesetHash; bytes32 reportHash; uint64 openedAt; uint32 round; }
- openCase(bytes32 pcapHash) external, ANALYST_ROLE only, returns caseId = keccak256(abi.encode(pcapHash, msg.sender, caseCounter++)). Registering the same PCAP twice creates two cases. Emits CaseOpened(caseId, analyst, pcapHash, timestamp).
- anchorReport(bytes32 caseId, bytes32 reportHash): only the case's analyst, only in state Finalized, only once. Emits ReportAnchored.
- Functions that change state or store claim and final data are callable only by QUORUM_ROLE. Provide getters for everything.
- registerEngine(bytes32 imageDigest, bytes32 rulesetHash), ADMIN_ROLE only, sets the active pinned pair, emits EngineRegistered. activeEngine() returns it.
- addValidator(address) and removeValidator(address), ADMIN_ROLE only: grant or revoke VALIDATOR_ROLE and maintain a list returned by validators(). Emit ValidatorAdded and ValidatorRemoved.
Tests (Hardhat, TypeScript): role checks for every function, the case counter, duplicate PCAP gives a second case, anchorReport rules, validator list maintenance, events with correct arguments. Print gas per function as a table.
Acceptance: all tests pass and no function is callable without the role stated above.
```

### Prompt 2.2: validator quorum with commit-reveal

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 6.3 and 6.4, contracts/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 6.3 and 6.4.
Implement contracts/ValidationQuorum.sol using CaseRegistry (QUORUM_ROLE granted to it at deploy time).
Admin-settable parameters, measured with block.timestamp, test defaults 60 s each: commitWindow, revealWindow.
Per case and per round store: the validator snapshot (array and mapping), N, k = N / 2 + 1 (integer division), commitDeadline, revealDeadline, commitments[validator], hasRevealed[validator], revealCount[root], totalReveals. Key all of this by (caseId, round).
Functions:
- submitClaim(caseId, resultRoot, engineHash, rulesetHash): only the case's analyst; state must be Opened; engineHash and rulesetHash must equal the active pinned pair, and are then stored in the case; require N >= 3; snapshot the validators; set deadlines; state -> Committing; emit ClaimSubmitted.
- commit(caseId, commitment): only a snapshot validator; state Committing; before commitDeadline; once per validator per round; emit CommitSubmitted.
- advance(caseId): anyone; Committing -> Revealing when block.timestamp >= commitDeadline.
- reveal(caseId, resultRoot, salt, engineHash, rulesetHash): only a snapshot validator that committed; state Revealing; before revealDeadline; keccak256(abi.encode(caseId, msg.sender, resultRoot, salt)) must equal the commitment; engineHash and rulesetHash must equal the pair STORED IN THE CASE AT CLAIM TIME (not the current active pair); record it, increment revealCount[resultRoot] and totalReveals; emit RevealSubmitted.
- finalize(caseId): anyone. If revealCount[claimedRoot] >= k: state Finalized, finalRoot = claimedRoot (allowed as soon as k matching reveals exist). Else if block.timestamp > revealDeadline: if totalReveals < k then Expired, otherwise Disputed. Otherwise revert. Expired takes precedence over Disputed; record this in docs/decisions/003-quorum-precedence.md. Emit CaseFinalized, CaseExpired or CaseDisputed.
- resolve(caseId, action, root): ADMIN_ROLE only. From Disputed: AttestMajority requires revealCount[root] >= k, sets Finalized, finalRoot = root, contradicted = (root != claimedRoot); NewRound; Reject. From Expired: NewRound or Reject. NewRound increments round, re-snapshots validators, sets new deadlines, state -> Committing. Emit CaseResolved.
Tests: happy path with 3 and 5 validators; exactly k matching and k-1 matching; a validator revealing a different root; non-validator reveal reverts; wrong salt reverts; reveal before the commit deadline reverts; commit after the deadline reverts; double commit and double reveal revert; wrong engine hash on claim reverts; changing the active pinned pair after the claim does not break reveals; Expired path; Disputed path; AttestMajority with and without a qualifying root; NewRound followed by finalize in the second round; every illegal state transition reverts. Use Hardhat time helpers.
Acceptance: all tests pass and the state machine equals the table in section 6.3, with any deviation listed in docs/decisions/.
```

### Prompt 2.3: Merkle verifier and posture ledger

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 5.3, 6.5, 6.6, docs/decisions/001-hashing-and-ids.md, spec/test-vectors/, contracts/.

```
Read AGENT_RULES.md, docs/ARCHITECTURE.md sections 5.3, 6.5, 6.6, docs/decisions/001-hashing-and-ids.md and spec/test-vectors/.
Implement contracts/MerkleVerifier.sol (library) and contracts/PostureLedger.sol.
MerkleVerifier:
- hostScoreLeaf(bytes32 hostId, bytes32 findingsDigest, uint16 score) = sha256(abi.encodePacked(bytes1(0x02), hostId, findingsDigest, score)); uint16 packs as 2 bytes big-endian.
- node(a, b) = sha256(abi.encodePacked(bytes1(0x01), min, max)) comparing a and b as uint256.
- verify(bytes32[] proof, bytes32 root, bytes32 leaf).
PostureLedger.recordPosture(bytes32 caseId, bytes32 hostId, bytes32 findingsDigest, uint16 score, bytes32[] proof): ANALYST_ROLE and the case's analyst only; the case must be Finalized; score <= 100; the leaf must verify against the case's finalRoot; at most one record per (caseId, hostId). Store Record { hostId, caseId, score, resultRoot, prevHash, timestamp, recordHash } where prevHash is the previous recordHash for that hostId (zero for the first) and recordHash = keccak256(abi.encode(hostId, caseId, score, resultRoot, prevHash, timestamp)). Getters: latestRecord(hostId), recordAt(hostId, index), recordCount(hostId). Emit PostureRecorded.
Cross-language tests: a Hardhat test reads spec/test-vectors/*.json and asserts that hostScoreLeaf, node and verify agree with the Python vectors, including the proof of every leaf of the 1 to 5 leaf trees. Negative tests: wrong score, wrong hostId, wrong digest, proof of another leaf, duplicate record, case not Finalized.
Acceptance: all tests pass. Also print the exact bytes (hex) Solidity hashes for one host-score leaf so I can compare them with Python by hand.
```

### Prompt 2.4: adversarial contract review

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 6, contracts/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 6.
Act as an attacker reviewing contracts/. Do not change contract code first. For each item, state whether the existing code prevents it, cite the code and the test that proves it, and if it does not, write a failing test first and then fix the contract:
(1) finalize without k matching reveals; (2) reveal on behalf of a validator you do not control; (3) copy another validator's root; (4) change state out of order; (5) record a posture for a case that is not Finalized; (6) record the same host twice for one case; (7) replay a commit from another case or another round; (8) change the pinned engine after a claim to change what is accepted; (9) leave a case permanently stuck; (10) overflow or truncation of score or counters; (11) reentrancy through any external call.
Summarize conclusions in docs/decisions/004-contract-review.md.
Acceptance: every item has a conclusion, all new tests pass, and no existing test was weakened.
```

## Phase 3: engine skeleton and walking skeleton (milestone M1)

### Prompt 3.1: engine skeleton with stub stages

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 3, 4.7, 5, spec/, engine/smscope/results/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 3, 4.7 and 5.
Create the engine CLI: python -m smscope analyze <file.pcap> --org-secret-hex <hex> --out <dir>.
Pipeline stages are separate modules with typed dataclass interfaces: ingest -> protocols -> tls -> certs -> rules -> results. For now every stage except rule evaluation, scoring and results is a STUB that reads engine/tests/fixtures/stub_sessions.json (create it: 3 hosts, about 12 sessions covering plaintext, STARTTLS offered but unused, TLS 1.0, an expired certificate, and one clean host).
Implement for real:
- rule evaluation over the fixture for R01, R02, R03, R06, R08, R09, R11, R12, R13, R15, R16, R19 using ruleset/ruleset.yaml (id, title, severity, enabled); detection logic is Python code;
- deduplication per (ruleId, serverEndpoint) with the affected sessionIds and sessionCount;
- integer scoring exactly as section 4.7: weights Critical 40, High 20, Medium 8, Low 2, Info 0; exposure factor 1 for one session, 2 for two to nine, 3 for ten or more; host score = max(0, 100 minus the sum of weight x exposure); grades A >= 90, B >= 75, C >= 60, D >= 40, F below 40;
- finding leaves, host-score leaves, the Merkle tree and per-host proofs, using engine/smscope/results.
Outputs in <dir>, all canonical JSON with no processing timestamps: sessions.json, findings.json, host_scores.json, result.json (resultRoot hex and the sorted leaf list with type, id, leafHash), host_proofs.json (hostId -> proof as hex list), manifest.json (pcapSha256, engineVersion from the environment variable ENGINE_IMAGE_DIGEST or 'dev', rulesetHash = SHA-256 over the bytes of ruleset.yaml followed by the bytes of the files under engine/smscope/rules/ sorted by path, and counts). The organization secret is never written anywhere.
Reject a capture with no mail sessions with a clear message and exit code 2 (for the stub: an empty fixture).
Tests: determinism (run twice and compare every output byte for byte), one scoring test per severity, per exposure bucket and per grade boundary, schema validation of every output file, and a test proving the organization secret does not appear in any output.
Acceptance: two runs give identical sha256sum for every output file.
```

### Prompt 3.2: validator node and end-to-end demo

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 3.3, 6, 7, contracts/, engine/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 3.3, 6 and 7.
1. contracts/scripts/deploy.ts: deploys Roles, CaseRegistry, ValidationQuorum and PostureLedger to a local Hardhat node, grants QUORUM_ROLE to the quorum contract, and writes contracts/deployments/local.json with addresses and ABI file paths.
2. validator/node.py: python -m validator.node --case-id <hex> --pcap <path> --org-secret-hex <hex> --key-env <ENV_VAR_NAME> [--no-strict]. It runs the engine CLI, takes resultRoot from result.json, commits keccak256(abi.encode(caseId, validator, resultRoot, salt)) with a random 32-byte salt stored in validator_state/<address>.json (write to a temp file, then rename), waits until the commit deadline, calls advance if needed, then reveals using the engineHash and rulesetHash stored in the case. In strict mode (default) it aborts BEFORE committing if the local manifest rulesetHash differs from the case's rulesetHash, and also if ENGINE_IMAGE_DIGEST is set and differs from the case's engineHash. --no-strict disables these checks and exists only to simulate a faulty validator. Use web3.py with a pinned version and ABIs from the deployment file.
3. scripts/demo_e2e.py: starts 'npx hardhat node' as a subprocess, deploys, registers the engine (imageDigest = 32 zero bytes in dev, rulesetHash from the engine manifest), adds three validators, then runs: openCase (SHA-256 of the PCAP), analysis, submitClaim, three validator processes, time travel with evm_increaseTime and evm_mine, finalize, recordPosture for every host using host_proofs.json, and anchorReport (SHA-256 of a placeholder report.json). Print a table of step, transaction hash and case state.
Use the stub engine and any placeholder PCAP file (the stub ignores content).
Acceptance: one command runs the whole flow and ends with state Finalized, one posture record per host, and a report hash anchored.
```

### Prompt 3.3: verifier and failure scenarios

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 6.3 and 8, scripts/demo\_e2e.py.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 6.3 and 8.
1. verifier/verify.py: python -m verifier.verify --case-id <hex> --pcap <path> --findings-dir <dir> --report <path>. It performs the five steps of section 8 and prints PASS or FAIL for each: (1) SHA-256 of the PCAP equals the on-chain pcapHash; (2) leaves and root rebuilt from findings.json and host_scores.json equal result.json; (3) that root equals the on-chain finalRoot; (4) for every host in host_scores.json, the posture chain: recompute every recordHash and check every prevHash link; (5) SHA-256 of the report equals the anchored reportHash. Exit code 0 only if all five pass.
2. scripts/scenarios/: four scripts, each runs the flow and asserts the expected outcome: (a) one validator runs with --no-strict and a modified ruleset file, produces a different root, and is outvoted while the case still finalizes, and the output names that validator as a minority revealer; (b) fewer than k validators reveal and the case ends Expired; (c) a PCAP changed by one byte fails verifier step 1; (d) one changed finding in findings.json fails verifier step 2.
3. A README section 'Walking skeleton' explaining how to run everything.
Acceptance (milestone M1): the happy path passes all five steps; scenarios (a) to (d) end exactly as described; engine output is identical across two runs inside two separate containers (print the commands you used).
```

## Phase 4: lab and ground truth

The lab produces the ground truth every later phase is judged against. Build it before the engine modules.

### Prompt 4.1: lab infrastructure

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 11.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 11.
Create lab/ with:
1. docker-compose.yml: network 'lab' with fixed subnet 172.28.0.0/24; services 'mailserver' (Postfix and Dovecot, fixed IP 172.28.0.10; choose a base image and PIN it by digest, record the choice in docs/decisions/), 'client' (Python 3 image, fixed IP 172.28.0.20) and 'capture' (tcpdump sharing the mailserver network namespace, writing classic PCAP files to lab/captures/<name>.pcap; use 'tcpdump -i any' only if needed and record the link type).
2. lab/ca/make_ca.sh: creates a lab CA and issues server certificates by profile: valid-2048-sha256, expired, rsa1024, sha1, self-signed, and a certificate signed by a second CA that is NOT in the client trust store. Expired certificates must use openssl ca with -startdate and -enddate in the past. Output goes to lab/ca/out/ (private keys git-ignored).
3. lab/scenarios/<ID>.env files, each holding the Postfix and Dovecot settings for one scenario (smtpd_tls_security_level, smtpd_tls_protocols, smtpd_tls_ciphers or the cipher list parameters, smtpd_tls_cert_file, smtpd_sasl_auth_enable, smtpd_tls_auth_only). The server config is generated from a template at container start using SCENARIO=<ID>.
4. lab/client/run_client.py: arguments --scenario, --mode starttls|implicit|plain, --auth yes|no, --max-tls 1.0|1.2|1.3, --server-name <name>. Use smtplib with an explicit ssl.SSLContext so TLS limits are exact. Send two or three short test messages with fixed content and the credentials labuser and LabPass-123! (these planted strings are used later by the leak test).
5. lab/run_scenario.sh <ID>: brings the environment up with the scenario, starts the capture, runs the client, stops the capture and writes lab/captures/<ID>.pcap.
Only produce S01a as a smoke test now. Verify it with tshark and report the TLS version, cipher suite and STARTTLS flow you see.
Acceptance: run_scenario.sh S01a produces a PCAP in which tshark shows an SMTP session with STARTTLS followed by a TLS handshake.
```

### Prompt 4.2: scenario captures and labels

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 11, lab/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 11. Attach lab/.
Create scenario files, captures and labels for the scenarios below. IMPORTANT: every scenario that tests a certificate rule uses a client capped at TLS 1.2, because TLS 1.3 encrypts the certificate.
ID | server configuration | client | expected findings
S01a | TLS 1.2 and 1.3 allowed, ECDHE, valid-2048-sha256 certificate | starttls, no auth, max TLS 1.2 | none
S01b | same server | starttls, no auth, TLS 1.3 allowed | R19
S02 | only TLS 1.0 allowed | starttls, no auth, TLS 1.0 | R06
S03 | cipher ECDHE-RSA-DES-CBC3-SHA only (if unavailable use DES-CBC3-SHA and expect R08 and R09) | starttls, no auth, max TLS 1.2 | R08
S04 | expired certificate | starttls, no auth, max TLS 1.2 | R11
S05 | no STARTTLS offered, SASL AUTH enabled, plaintext auth allowed | plain, auth yes | R02, R01
S06 | STARTTLS offered but optional | plain, no auth | R03
S07 | TLS 1.2 with only the static-RSA suite AES256-GCM-SHA384 | starttls, no auth, max TLS 1.2 | R09
S08 | rsa1024 certificate | starttls, no auth, max TLS 1.2 | R12
S09 | sha1 certificate | starttls, no auth, max TLS 1.2 | R13
S10 | self-signed certificate | starttls, no auth, max TLS 1.2 | R16
S11 | certificate from a CA absent from the trust store | starttls, no auth, max TLS 1.2 | R15
S12 | TLS 1.3 only | starttls, no auth | R19
S13 | implicit TLS on port 465, TLS 1.2, valid certificate | implicit, no auth, max TLS 1.2 | none
Stress captures, all on the S01a configuration, expected findings none: X01 reordering and duplication (tc netem reorder and duplicate), X02 small segments (TCP MSS clamped to 100 with iptables TCPMSS), X03 five percent packet loss (tc netem loss). The container needs NET_ADMIN for these.
For each scenario write lab/labels/<ID>.json: {scenario, serverEndpoint ('172.28.0.10:25' or '172.28.0.10:465'), expectedFindings: [{ruleId}]}. Derive expected findings by applying the rule definitions of section 4.7 to the fields tshark observes in the capture (version, cipher, certificate), NOT to our engine output, and never by assuming the configuration worked. If the observed fields add hits (for example static RSA key exchange), list them and add a comment field.
Modern OpenSSL builds refuse TLS 1.0, 3DES, 1024-bit keys and SHA-1 by default. If a scenario cannot be produced with the pinned base image, try an older pinned image or a lowered OpenSSL security level; if it still fails, STOP and report which scenario and why instead of faking a capture. Add lab/COVERAGE.md mapping every Tier 1 rule to the scenarios that exercise it and listing every gap.
Acceptance: each capture exists; for every capture, tshark shows TLS version, cipher suite and STARTTLS behavior matching the intended configuration; COVERAGE.md has no unexplained gap.
```

### Prompt 4.3: tshark ground-truth extractor

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 4.1 to 4.4, lab/captures/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.1 to 4.4. Attach lab/captures/.
Create eval/tshark_truth.py: given a PCAP, run tshark and write a JSON ground-truth file containing, per TCP connection identified by (client endpoint, server endpoint, first frame number): the reassembled client and server byte streams (tshark -z follow,tcp,raw,<stream>), the SMTP commands and reply codes seen, and for TLS: handshake type list, ClientHello legacy version, supported_versions values, offered cipher suite codes, SNI, ServerHello selected cipher and version, JA3 and JA3S if the installed tshark exposes them, and certificate fingerprints. First run tshark -G fields and use the exact field names of the installed version (they differ between versions); record the tshark version in every output. tshark's stream numbering can differ from ours, so key everything by the 5-tuple and the first frame number.
Write eval/README.md explaining how to regenerate, and commit generated files under eval/truth/ for all captures.
Acceptance: for S01a, S05 and X02 I open the truth file next to Wireshark and the values match.
```

## Phase 5: analysis engine (milestone M2)

Run Template A after each prompt of this phase. Do not start a prompt until the previous acceptance check passes.

### Prompt 5.1: PCAP reader and TCP reassembly

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 4.1, eval/tshark\_truth.py, eval/truth/, lab/captures/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.1.
Implement engine/smscope/ingest/pcap.py and reassembly.py. dpkt is allowed for protocol headers only.
1. PCAP reader (own implementation reading the global and record headers with struct, so timestamps stay integers): classic PCAP with magic 0xa1b2c3d4 (microsecond) and 0xa1b23c4d (nanosecond), both byte orders; reject PCAPNG (magic 0x0a0d0d0a) and anything else with a clear PcapFormatError. Link types: Ethernet (1) and Linux cooked capture (113); anything else is an error. Strip 802.1Q VLAN tags. IPv4 and IPv6 (walk extension headers to TCP). IP fragments and non-TCP packets are counted in a stats dict and skipped. Frame numbers are 1-based. Timestamps are integer epoch seconds (ts_sec). Stream the file; never load it whole.
2. Flow table: key = normalized 5-tuple. Client = the sender of the first SYN without ACK; if no SYN was captured, the sender of the first packet, and the stream is flagged clientInferred. Stream index = ordinal of the flow's first packet in the file. Endpoint strings per docs/decisions/001-hashing-and-ids.md.
3. Reassembly per direction from the initial sequence number, with 32-bit sequence wrap-around handled. Exact retransmissions are dropped; overlaps keep the first-seen bytes; out-of-order segments are buffered up to a configurable cap. At a gap, deliver only the contiguous prefix and mark the stream complete=false. Keep a map from byte offset to frame number and capture second for every delivered segment, exposed as frame_for_offset(direction, offset).
4. Output a Stream dataclass: index, client, server, firstFrame, firstTs, complete, clientInferred, clientBytes, serverBytes plus the offset maps.
Document every behavior choice (first-seen overlap policy, gap policy) in docs/decisions/.
Tests: byte-for-byte comparison of both reassembled directions with eval/truth for every lab capture including X01, X02 and X03; Hypothesis property tests that shuffle, duplicate and split segments of a synthetic stream and assert identical output; sequence wrap-around; truncated file, empty file, PCAPNG file and unsupported link type.
Acceptance: all captures match tshark's streams exactly; the property tests pass with 200 examples.
```

### Prompt 5.2: protocol identification

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 4.2, engine/smscope/ingest/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.2.
Implement engine/smscope/protocols/identify.py: identify(stream) returns protocol in {smtp, imap, pop3, unknown}, source in {content, port}, and a transport hint in {plaintext, implicitTls}. Rules: the server's first line starts with '220 ' or '220-' and the client's first command is EHLO or HELO -> smtp; the server's first line starts with '* OK' -> imap; the server's first line starts with '+OK' -> pop3; client bytes starting with 0x16 0x03 -> implicit TLS, with the protocol inferred from the server port (465 smtp, 993 imap, 995 pop3) and source = port; if content is absent or ambiguous use the port hints 25 and 587 (smtp), 143 (imap), 110 (pop3). Anything else is unknown, excluded from analysis, and counted in the run stats.
Tests: every lab capture identifies correctly; a table-driven test with hand-written first lines including malformed and empty streams.
Acceptance: S01a, S05 and S13 identify as smtp with sources content, content and port.
```

### Prompt 5.3: SMTP session tracker

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 4.3 and 5.1, engine/smscope/protocols/identify.py, engine/smscope/ingest/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.3 and 5.1.
Implement engine/smscope/protocols/smtp.py.
- Parse the server stream into replies (code and text; a multiline reply continues while the line is '250-...' and ends at '250 ...') and the client stream into command lines (split on CRLF). Never store message bodies: after a DATA command ignore bytes until the line containing only '.'. Handle BDAT by skipping its declared octet count.
- The EHLO response gives the capability list; STARTTLS offered = the keyword STARTTLS in it (case-insensitive).
- STARTTLS flow: the client command STARTTLS, then the server's next reply: 220 -> succeeded; 4xx or 5xx -> refused. If the client never sends STARTTLS although it was offered -> ignored; if never offered -> notOffered. After a 220 reply to STARTTLS record tlsStartOffset for the client stream and for the server stream (the byte offsets where TLS records begin).
- Cleartext credentials: in the plaintext portion only, a client command AUTH PLAIN or AUTH LOGIN (case-insensitive) records {mechanism, packetNo = frame_for_offset(client, offset of the command)}. Never store or log the credential bytes.
- Implicit TLS streams (from identify): transportMode = implicitTls, tlsStartOffset = 0, no STARTTLS fields.
- Output one SessionRecord per stream per section 5.1 (tls and certificates are filled later) with transportMode in {plaintext, starttls, implicitTls}, starttls {offered, attempted, outcome}, cleartextAuth, streamComplete.
- The IMAP and POP3 trackers are stubs raising NotImplementedError.
Tests: S01a, S05, S06 and S13 session records equal hand-written expected JSON; a planted-credential test proving the lab credentials from lab/client/run_client.py appear in no output of the module; edge cases: multiline replies, commands split across TCP segments, STARTTLS refused with 454, missing EHLO.
Acceptance: the four session records agree with tshark's SMTP view.
```

### Prompt 5.4: TLS record and handshake parser

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 4.4, engine/smscope/protocols/, eval/tshark\_truth.py.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.4.
Implement engine/smscope/tls/records.py and handshake.py.
- Input: the client-to-server and server-to-client byte streams starting at the TLS start offset (from the SMTP tracker, or 0 for implicit TLS) plus the offset-to-frame maps.
- Record layer: parse 5-byte headers (type, version, length); handle handshake messages that span several records. A record cut off by an incomplete stream yields a parse error 'truncated', not an exception. Stop parsing after ChangeCipherSpec in TLS 1.2 and after the ServerHello in TLS 1.3 (everything later is encrypted), counting the remaining records only. Record a cleartext fatal alert when seen before encryption.
- Messages: ClientHello (legacy version, random, session id, cipher suites, extensions: server_name, supported_groups, ec_point_formats, supported_versions, key_share, psk_key_exchange_modes, signature_algorithms, alpn), ServerHello (version, session id, cipher, extensions: supported_versions, key_share, pre_shared_key), HelloRetryRequest (a ServerHello whose random equals the fixed value defined in RFC 8446), Certificate (TLS 1.2: ordered list of DER blobs), ServerKeyExchange (keep the raw bytes and the parameter type), CertificateStatus.
- Negotiated version: the supported_versions value in the ServerHello when present, otherwise the ServerHello version field.
- Every length field is bounds-checked. Malformed input yields a parse-error entry (kind, offset, frame) on the session and processing of that session stops; it never raises out of the module.
Output a TlsHandshake dataclass. Do not interpret ciphers or certificates here.
Tests: hand-built byte strings for each message type; truncated and oversized length fields; a handshake split across two records; field-by-field comparison with eval/truth on every lab capture.
Acceptance: version, selected cipher code, SNI and the list of offered cipher codes match tshark on all lab captures including X02.
```

### Prompt 5.5: cipher table, key exchange, resumption, JA3

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 4.4 and 4.6, engine/smscope/tls/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.4 and 4.6.
1. scripts/gen_cipher_table.py: fetches the official IANA TLS Cipher Suites registry in CSV form (find the official URL; write it and the retrieval date into the header of the generated file) and generates engine/smscope/tls/ciphers_generated.py containing for every suite code: name and properties parsed from the name: kxType in {RSA, DHE, ECDHE, DH, ECDH, PSK, anon, tls13, other}, authentication, bulk cipher, mac or aead, forwardSecrecy (true for DHE, ECDHE and tls13; false for RSA, DH, ECDH and plain PSK; null if unknown), weakClass in {null, NULL, EXPORT, anon, RC4, DES, 3DES}. The generated file is committed. The engine itself never downloads anything.
2. engine/smscope/tls/negotiation.py: from a TlsHandshake produce tls = {version (IANA hex value and name), cipherSuiteCode, cipherSuiteName, kxType, kxGroupOrDhBits, forwardSecrecy, resumed, ja3, ja3s, sni, certObservable, certObservableReason}. kxGroupOrDhBits: TLS 1.3 -> the selected key_share group; TLS 1.2 ECDHE -> the named curve from ServerKeyExchange; DHE -> the bit length of the prime p; otherwise 0. resumed: TLS 1.2 when the ServerHello echoes the client's non-empty session id and no Certificate message follows; TLS 1.3 when the ServerHello carries pre_shared_key. certObservable is false with reason 'tls13' or 'resumed' in those cases.
3. JA3 and JA3S per the published definitions: JA3 string = version,ciphers,extensions,curves,pointformats with values joined by dashes in decimal, GREASE values removed, MD5 of the string; JA3S = version,cipher,extensions, MD5. MD5 is used only as the fingerprint format, not for security.
Tests: for all lab captures compare version, cipher code, key exchange group or DH bits, SNI, resumption flag and (if available) JA3 with eval/truth; GREASE filtering unit test; hand-constructed JA3 strings; forwardSecrecy assertions (AES256-GCM-SHA384 false, ECDHE-RSA-AES256-GCM-SHA384 true, TLS_AES_128_GCM_SHA256 true).
Acceptance: S01a, S01b, S02, S03, S07 and S12 give the expected version, suite and forward secrecy flag.
```

### Prompt 5.6: certificate analysis

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 4.5, engine/smscope/tls/, lab/ca/out/ (public certificates only).

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.5.
Implement engine/smscope/certs/analyze.py using the pinned cryptography library.
- Load each DER certificate from the Certificate message. Record sha256 fingerprint, subject, issuer, notBefore and notAfter as integer epoch seconds, keyAlgorithm (RSA, EC, Ed25519, Ed448, DSA), keySize in bits (for EC the curve size), curve name, signatureAlgorithm name and hash (none if not applicable), san (dNSName and iPAddress lists), isCa, selfSigned (issuer equals subject and the signature verifies with its own key), keyUsage and extendedKeyUsage.
- Validity is evaluated against the capture timestamp (integer seconds) of the packet carrying the Certificate message, never the machine clock. Verdicts: expired, notYetValid.
- Weak key: RSA below 2048 or EC below 224 bits. Weak signature: MD5 or SHA-1 hash.
- Chain: build from the presented certificates in a deterministic order, verifying each signature with the issuer's public key and the CA basic constraint, anchoring in a configurable trust store directory (config key trustStorePath; read certificates in sorted file name order). Prefer cryptography's x509 verification with the validation time set to the capture time if the pinned version supports it; otherwise implement the simple builder and record its limitations (no name constraints, policies or revocation) in docs/decisions/. Verdicts: valid, unknownIssuer (incomplete chain or anchor not in the store), selfSigned. unknownIssuer must never be reported as invalid.
- Name check against SNI: SAN dNSName match with a single-label leftmost wildcard only; IP SANs for IP literals; no fallback to CN; if there is no SNI the check is 'notEvaluable'.
- Output the certificates list of section 5.1 with verdicts as a sorted list of strings.
Tests: S01a (valid), S04, S08, S09, S10, S11 compared with 'openssl x509 -noout -text' and 'openssl verify' run during test setup; wildcard and IP SAN unit tests; a time-reference test (the same expired certificate is valid in a capture whose timestamp is before notAfter).
Acceptance: every certificate property and verdict matches openssl on all lab captures.
```

### Prompt 5.7: rules, scoring, label comparison

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 4.7 and 5, engine/smscope/rules/, all session-producing modules.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.7 and 5.
Replace the fixture-based rule evaluation with real session records. Implement exactly these Tier 1 rules in engine/smscope/rules/ with metadata in ruleset/ruleset.yaml:
R01 Critical: the session has any cleartextAuth entry.
R02 High: transportMode is plaintext and starttls.offered is false.
R03 High: starttls.offered is true, starttls.attempted is false, and transportMode is plaintext.
R06 High: the negotiated version is TLS 1.0 or TLS 1.1.
R08 High: cipher weakClass is RC4, DES or 3DES.
R09 Medium: forwardSecrecy is false and kxType is RSA, DH or ECDH.
R11 High: any observed certificate has notAfter earlier than the capture time of the Certificate message.
R12 High: any non-anchor observed certificate has an RSA key below 2048 bits or an EC key below 224 bits.
R13 High: any observed certificate that is not self-signed has an MD5 or SHA-1 signature hash.
R15 Low: the chain verdict is unknownIssuer and the leaf is not self-signed.
R16 Medium: the leaf certificate is self-signed.
R19 Info: certObservable is false.
Each finding: findingId, ruleId, severity, serverEndpoint, sorted sessionIds, sessionCount, evidence (at most 5 entries of {sessionId, packetNo, note} in ascending sessionId order), details. One finding per (ruleId, serverEndpoint). Scoring as in section 4.7.
Create eval/compare_labels.py: runs the engine on every capture in lab/captures/, loads lab/labels/<ID>.json, matches findings by (ruleId, serverEndpoint), prints per-scenario precision and recall plus every unexpected or missing finding, and exits 1 if any Tier 1 scenario differs from its label.
Tests: one test per rule from synthetic session records, boundary tests (RSA 2048 versus 1024, TLS 1.1 versus 1.2, 9 versus 10 sessions), and a determinism test across two runs.
Acceptance: compare_labels.py exits 0 on S01a to S13 and X01 to X03.
```

### Prompt 5.8: integration and containerization

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 3 and 4, the whole engine/ and lab/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 3 and 4.
Wire the real stages into the CLI (ingest -> protocols -> tls -> certs -> rules -> results) and delete the stubs and the fixture usage. Add a Dockerfile for the engine: base image pinned by digest, non-root user, pinned dependencies, ENTRYPOINT python -m smscope. Build the image and print its digest.
Create tests/golden/: for every lab capture, committed expected outputs (sessions.json, findings.json, host_scores.json, result.json) generated once by scripts/make_golden.py; a golden test compares fresh outputs byte for byte. Create scripts/determinism_check.sh: runs the engine container twice on every capture with --network none and compares sha256sum of all outputs.
Acceptance (milestone M2): compare_labels.py exits 0; golden tests pass; the determinism script reports zero differences; I run the container myself with docker run --network none and it produces output.
```

After 5.8, run Template A on the whole engine. If M2 is not reached by about half to 55 percent of your time, stop adding features and finish only the Tier 1 path.

## Phase 6: backend services and validators (milestone M3)

### Prompt 6.1: API service

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 3 and 8, engine/ (Dockerfile and CLI), contracts/deployments/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 3 and 8.
Create backend/ (FastAPI; SQLite through the standard sqlite3 module or SQLAlchemy with a pinned version; no Postgres, no queue).
- Storage: data/cases/<caseId>/ holds pcap.bin and the engine outputs. Case directories are created with mode 0700. The engine writes canonical JSON files; every hash and root is computed from these files, never from database rows.
- Tables: cases(id, status, pcap_sha256, created_at, engine_version), analysis_runs(case_id, status, started_at, finished_at, error), chain_txs(case_id, step, nonce, tx_hash, status, retries), audit_log(id, at, actor, action, case_id, detail). Operational timestamps are allowed here because they are never hashed.
- Case status machine: uploaded -> analyzed -> opened_on_chain -> claimed -> distributed -> finalized -> recorded -> report_anchored, plus failed. Persist after every step so a restart resumes at the next incomplete step.
- Auth: static API keys from the environment (ANALYST_API_KEY, ADMIN_API_KEY) checked by a dependency; analyst endpoints reject the admin key and the reverse.
- Endpoints: POST /cases (multipart upload; maximum size from configuration, default 100 MB; check the PCAP magic number; compute SHA-256 while streaming), POST /cases/{id}/analyze (runs 'docker run --rm --network none --read-only' with the case directory mounted and a writable output directory, as a background task), GET /cases/{id}, GET /cases/{id}/sessions, /findings and /hosts (paginated), GET /cases/{id}/chain, POST /cases/{id}/verify (calls the verifier module), GET /hosts/{hostId}/posture-chain. Chain-changing endpoints return 501 until prompt 6.2.
- No payloads, credentials or organization secret in logs: log run ids and counts only. The organization secret comes from the environment ORG_SECRET_HEX and reaches the container as an environment variable.
Tests (FastAPI TestClient): upload; bad magic number; oversize rejection; analyze with the real engine image on S01a; resume after the process is killed mid-analysis; role checks; audit_log rows for every state-changing call; the planted lab credentials appear in no log and no response.
Acceptance: uploading lab/captures/S01a.pcap with curl, analyzing it and fetching findings returns the same findings as the engine CLI.
```

### Prompt 6.2: chain gateway

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 3.3 and 6, backend/, contracts/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 3.3 and 6.
Create backend/chain/gateway.py: the only component that owns signing keys (environment variables ANALYST_KEY and ADMIN_KEY) and nonce sequences (one lock per account). Operations: open_case, submit_claim, advance, finalize, record_posture (per host, with its proof from host_proofs.json), anchor_report, resolve.
- Every operation is idempotent: before sending, read the on-chain state and skip if the effect already exists (case already opened for this pcapHash by this analyst and recorded in chain_txs, claim already submitted, host already recorded). Every sent transaction is stored in chain_txs (step, nonce, tx hash, status, retries) BEFORE waiting for the receipt, and updated afterward.
- Retry a bounded number of times with backoff on transient RPC errors; never retry a reverted transaction; surface the revert reason in the case status.
- An event listener polls contract logs from the last processed block (stored in the database) and updates the case index. The chain is the source of truth; on any disagreement the database is corrected from the chain.
- Wire the endpoints POST /cases/{id}/open, /claim, /finalize, /record, /anchor and /resolve (admin only), and GET /cases/{id}/chain returning the on-chain case state, commits and reveals per validator, and transaction hashes.
Tests on a local Hardhat node: full flow; calling every endpoint twice creates no duplicate transaction; a crash test that raises an exception after the transaction is sent but before the receipt is stored, then restarts and finishes without a second transaction; a revert (wrong role) is reported and not retried.
Acceptance: the flow from upload to anchored report works through the API with the real engine and three validator processes started by hand.
```

### Prompt 6.3: validator service

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md sections 6.4 and 7, validator/node.py, backend/chain/, engine/Dockerfile.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 6.4 and 7.
Create validator/service.py: a long-running process per validator (configuration: validator id, key environment variable name, inbox directory validator_inbox/<id>/). It polls the chain. For each case where it is in the validator snapshot, the case is Committing, and an inbox bundle <caseId>/{pcap.bin, org_secret.hex} exists, it: runs the engine image with 'docker run --rm --network none --read-only' (bundle mounted read-only, output directory writable); saves a random salt atomically (temp file then rename) to validator_state/<id>.json BEFORE sending the commit; commits; waits for the commit deadline; calls advance if needed; reveals.
In Tier 1 delivery is a file copy: add backend POST /cases/{id}/distribute that copies pcap.bin and the organization secret into the three inboxes and records status 'distributed'. State in the README that encrypted delivery is future work (Tier 3).
- Restart safety: on startup it resumes from validator_state (committed but not revealed, or already revealed) without double-submitting.
- Strict mode as in validator/node.py. A --faulty flag exists only for the evaluation scenarios.
Tests: restart between commit and reveal still reveals with the stored salt; an inbox bundle for a case the validator is not in is ignored; a wrong engine digest aborts before commit; a faulty validator is outvoted.
Acceptance (milestone M3): API upload, analyze, open, claim, distribute; three validator services finalize; record and anchor complete; killing one validator service after its commit and restarting it still ends in Finalized.
```

## Phase 7: reports and dashboard (milestone M4)

### Prompt 7.1: report builder

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 8, backend/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 8.
Create backend/reports/: build a report from the engine outputs and the chain state: report.json (canonical JSON, deterministic given the inputs and chain state), report.html (Jinja2, pinned; no external assets or scripts) and the report hash = SHA-256 of report.json. Contents per section 8: case ID, PCAP hash, engine and ruleset hashes, result root, transaction hashes, per-host score and grade, prioritized findings with evidence references (ordered by severity, then exposure, then ruleId), session and TLS summary (counts per version and cipher suite, forward secrecy share per server), certificate table, a 'visibility limits' section (TLS 1.3, resumed, no SNI, incomplete streams, parse errors, with counts), a static recommendation per rule from backend/reports/recommendations.yaml (one entry per Tier 1 rule with a concrete Postfix or Dovecot configuration fix; verify parameter names against the official documentation and list the documentation URLs you used), and the on-chain case state. There are no advisory sections in Tier 1.
Endpoint GET /cases/{id}/report?format=json|html (pdf returns 501 until Tier 2). Anchoring the report hash goes through the gateway; the HTML shows the anchored hash and the five verifier steps.
Tests: report.json is byte-identical on two builds; every Tier 1 rule has a recommendation; the HTML has no external URLs except documentation links; planted credentials appear nowhere.
Acceptance: the report for S05 lists R01 and R02 first, with evidence packet numbers that match Wireshark.
```

### Prompt 7.2: dashboard pages

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 8, backend/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 8.
Add server-rendered pages to the FastAPI app (Jinja2, no frontend framework, no external assets): / (case list and upload form); /cases/<id> overview (status timeline from the case status machine, PCAP hash, result root); /cases/<id>/hosts (score, grade, finding counts); /cases/<id>/findings (severity-ordered table with evidence references and the recommendation); /cases/<id>/sessions (protocol, transport mode, STARTTLS outcome, TLS version, cipher, forward secrecy, certificate verdicts, filterable by host and finding); /cases/<id>/tls (distribution of versions and cipher suites as simple HTML bar charts); /cases/<id>/certificates; /cases/<id>/chain (on-chain state, validator commits and reveals, transaction hashes, and a Verify button that calls POST /cases/{id}/verify and shows PASS or FAIL for each of the five steps).
Show not-observable and not-evaluable states explicitly (TLS 1.3, resumed, no SNI, incomplete stream) with a short explanation instead of blanks. Every page works without JavaScript except an optional table filter.
Tests: each page renders for S01a, S05 and S12 cases; the chain page shows PASS for the happy path and FAIL for step 1 after the stored PCAP is modified by one byte; no external URLs appear in any page.
Acceptance (milestone M4): I run one lab case from upload to verified entirely in the browser.
```

## Phase 8: evaluation (milestone M5)

### Prompt 8.1: evaluation scripts

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md section 11, eval/, engine/, validator/, contracts/.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 11.
Create eval/run_all.py and one script per experiment. Every table and figure is generated by scripts into eval/results/ (CSV and Markdown) and reproducible from a clean checkout with one command.
E1 parsing agreement: streams, protocol, TLS version, cipher, key exchange and certificate fields versus eval/truth for every capture; report the agreement rate and list every mismatch.
E2 detection accuracy: per-rule precision and recall from compare_labels over all scenarios, with the confusion list.
E3 baseline comparison: run Zeek on the same PCAPs with the policy scripts policy/protocols/ssl/weak-keys and policy/protocols/ssl/validate-certs loaded and parse notice.log; state the Zeek version; produce a table of which labeled findings Zeek flags and which only SecureMailScope flags. Claim nothing about Zeek beyond what its output shows.
E4 determinism: engine output hashes across 5 runs in 2 containers for every capture.
E5 chain tests: tamper (PCAP, finding, report), faulty validator, unauthorized calls for every role-restricted function, Disputed and Expired paths, NewRound, using scripts/scenarios and the Hardhat tests; table of expected versus observed.
E6 gas: gas per operation (openCase, submitClaim, commit, reveal, finalize, recordPosture, anchorReport) for N = 3 and N = 5.
E7 leak test: scan every output file, log file and chain transaction input data for the planted lab credentials and the organization secret; expect zero hits.
Add eval/THREATS.md: synthetic traffic, one mail stack, small validator set, permissioned assumption, tshark as ground truth, label derivation method.
Acceptance (milestone M5): 'python eval/run_all.py' regenerates every table, and I can explain each number in E1 to E7.
```

## Phase 9: documentation and demo

### Prompt 9.1: README, demo, compliance, viva

Attach: AGENT\_RULES.md, docs/ARCHITECTURE.md, the whole repository.

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md.
1. README.md that a fresh machine can follow: prerequisites with versions, how to build the engine image, run the lab, start the node and contracts, start the backend and three validator services, run the demo, run the tests, and regenerate the evaluation.
2. 'make demo' running scripts/demo_full.sh: lab capture S05 (or a bundled copy), upload, analyze, open, claim, distribute, three validators, finalize, record, report anchoring, verification PASS; then a second run that modifies one byte of the PCAP and shows verification FAIL; then a third where one validator runs with --faulty and is outvoted. Pause between steps with a message saying what the audience should look at.
3. docs/COMPLIANCE.md: a table of every problem-statement deliverable (the 21 listed items plus mitigation recommendations and the blockchain requirement) with status met, partially met or not met, the evidence (file or experiment) and the reason for any gap. Be strict: IMAP, POP3, AI-based scoring, anomaly detection, PDF export and the full interactive dashboard are not met in Tier 1.
4. docs/VIVA.md: written answers (about 150 words each) to: why a blockchain and not a signed database; why determinism is required; what stops validators copying each other; what a colluding majority can do; how privacy is handled; why TLS 1.3 certificates are not analyzed; why the risk score is rule-based; what the chain does not prove.
Acceptance: I follow the README from a clean clone without help, make demo completes, and COMPLIANCE.md matches reality.
```

Stop all feature work at about 80 percent of your time and move to Phases 8 and 9.

## Tier 2 prompts (only after Tier 1 passes)

Run in this order. Update AGENT\_RULES.md scope before each.

### Prompt T2.1: IMAP tracker

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.3 and 5.1. Attach engine/smscope/protocols/smtp.py.
Lift the SMTP-only limit for IMAP. Implement engine/smscope/protocols/imap.py: greeting '* OK'; the CAPABILITY response (record STARTTLS, LOGINDISABLED and AUTH=PLAIN); tagged commands; the STARTTLS flow (tagged OK -> succeeded, NO or BAD -> refused) with tlsStartOffset after the tagged OK; cleartext credentials: LOGIN and AUTHENTICATE PLAIN in the plaintext portion (mechanism and packet number only; handle synchronizing literals {n} only as far as needed to find the command name; never store credential bytes). Implicit TLS on 993 follows the same rule as SMTP 465. Update AGENT_RULES.md and make R01 to R03 apply to imap sessions.
Lab: add S20 (IMAP STARTTLS, TLS 1.2, valid) expected none, S21 (IMAP cleartext LOGIN, no TLS) expected R02 and R01, S22 (IMAP implicit TLS on 993) expected none, with labels whose serverEndpoint ports are 143 and 993.
Acceptance: compare_labels.py passes for S20 to S22; tests as in prompt 5.3.
```

### Prompt T2.2: POP3 tracker

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.3 and 5.1. Attach engine/smscope/protocols/.
Implement engine/smscope/protocols/pop3.py: greeting '+OK'; CAPA response terminated by a line with a single '.', recording STLS; STLS flow ('+OK' -> succeeded, '-ERR' -> refused) with tlsStartOffset; cleartext credentials USER, PASS and AUTH PLAIN (command name and packet number only); implicit TLS on 995. Make R01 to R03 apply to pop3 sessions.
Lab: S23 (POP3 STLS, TLS 1.2, valid) expected none, S24 (POP3 cleartext USER and PASS) expected R02 and R01, S25 (POP3 implicit TLS on 995) expected none.
Acceptance: compare_labels.py passes for S23 to S25.
```

### Prompt T2.3: remaining rules

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.7. Attach engine/smscope/rules/ and lab/.
Add rules R04, R05, R07, R10, R14, R17, R18.
R04 High: starttls.outcome is refused and the session continued in plaintext.
R05 Critical: negotiated version below TLS 1.0 (SSL 3.0 or earlier).
R07 Critical: cipher weakClass is NULL, EXPORT or anon.
R10 Medium (High if below 1024 bits): DHE with kxGroupOrDhBits below 2048.
R14 Medium: SNI present and no SAN matches it (not evaluable without SNI).
R17 Medium: for one server endpoint, STARTTLS is advertised in at least one session and not advertised in at least one other session of the same capture; list both sets of sessionIds; state in details that this is an indicator, not proof of stripping.
R18 Medium: for one server endpoint, two or more distinct leaf certificate fingerprints appear in the same capture.
Lab scenarios: S30 a small Python SMTP stub that answers STARTTLS with 454 and a client that continues in plaintext -> R04; S31 NULL, EXPORT or anonymous cipher and SSL 3.0 if the pinned image can produce them, otherwise a documented synthetic capture generated by a script -> R07 and R05; S32 DHE with a 1024-bit prime -> R10; S33 the client connects with a server name the certificate does not cover -> R14; S34 a proxy removing STARTTLS from the EHLO response for some sessions, in one capture -> R17 and R02; S35 the server certificate replaced between two sessions in one capture -> R18.
Update ruleset.yaml, COVERAGE.md, labels and recommendations.yaml.
Acceptance: compare_labels.py passes on S30 to S35 or lists a documented gap.
```

### Prompt T2.4: anomaly detection (advisory)

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.8. Attach engine/ and lab/.
Create advisory/anomaly/ (outside the result root; its output is never hashed and never sent to the chain).
1. Feature extraction per session (integers or one-hot, no floats derived from timestamps): TLS version, cipher suite code, JA3 rarity (count of baseline sessions with the same JA3, bucketed), whether the leaf fingerprint differs from the baseline fingerprint of the same server endpoint, handshake byte size bucket, resumed flag, STARTTLS offered and used flags.
2. Baseline: a script lab/make_baseline.sh producing at least 200 clean sessions from several client programs and settings that give different JA3 values; train sklearn IsolationForest with a fixed random_state; save the model and a baseline summary recording the scikit-learn version.
3. Scoring: for each session of a target capture output the anomaly score and a flag by a threshold chosen on a held-out clean set to keep false positives at a stated rate. 'Top deviating features': list the features whose value is rare in the baseline (frequency below a stated threshold). State in code comments and in the report that Isolation Forest does not explain itself and this list is a separate heuristic.
4. Injected anomalies: A1 server certificate changes between sessions, A2 one client suddenly negotiates TLS 1.0 where the baseline used 1.2, A3 a client with an unseen JA3.
5. eval/e8_anomaly.py: detection rate and false positive rate on A1 to A3 and on clean captures; comparison with the rule-only system (R17, R18, R06). Report where ML adds detections and where it only adds noise. State that the data is synthetic and small.
6. Reports and dashboard: an 'Advisory' section, clearly labeled, listing flagged sessions. It is not part of the quorum.
Acceptance: the evaluation prints honest numbers; two runs give identical scores.
```

### Prompt T2.5: PDF export

```
Read AGENT_RULES.md. Attach backend/reports/.
Add PDF export from the existing HTML report using WeasyPrint with a pinned version (document its system dependencies in README.md). GET /cases/{id}/report?format=pdf returns it. The report hash anchored on-chain stays the SHA-256 of report.json, not of the PDF; the PDF header shows that hash.
Tests: generation succeeds for S01a, S05 and S12; the PDF text contains the case ID, the result root and the hash; no network access during generation.
Acceptance: I open the PDF and it matches the HTML.
```

### Prompt T2.6: limits, fuzzing, sandbox check

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 4.1 to 4.5 and 9. Attach engine/.
1. engine/smscope/limits.py: configuration for maximum PCAP size, number of streams, buffered bytes per stream, TLS record length, certificate length, handshake message length and runtime seconds. Exceeding a limit stops the run with exit code 3 and a message naming the limit; never a hang or crash.
2. Audit every length field read in tls/ and certs/ and every buffer in ingest/ for bounds checks; fix gaps.
3. Fuzz test: a script that takes every lab capture, applies seeded random byte mutations, truncations and record length changes, runs the engine in process, and asserts no uncaught exception, no breach of the configured limits, and runtime under the limit, for at least 1000 mutated inputs per capture. Report any crash with the minimal reproducing mutation and add it as a regression test.
4. A sandbox check script that runs inside the engine container and confirms there is no network (a connection attempt fails), the filesystem is read-only except the output directory, and the process is not root.
Acceptance: the fuzz run completes with zero crashes and the sandbox script passes.
```

### Prompt T2.7: dashboard upgrade

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 8. Attach backend/.
Improve the dashboard without adding a framework: sortable and filterable tables, a per-host drill-down page (findings, sessions, certificate chain, forward secrecy share, posture chain), inline SVG charts for version and cipher distribution and for score by host, and a page for the advisory anomaly flags. Keep every page usable without JavaScript. Tests: page rendering for all lab cases, no external URLs.
Acceptance: I can reach every finding's evidence in at most three clicks from the overview.
```

## Tier 3 prompts (optional)

### Prompt T3.1: encrypted validator delivery

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md sections 6.4, 7 and 9. Attach validator/ and backend/.
Replace file-copy delivery with encrypted delivery. Each validator has a key pair generated by validator/keygen.py (the private key stays in the validator's state directory with mode 0600; the public key is registered with the backend by a command, not on-chain). The backend encrypts the bundle (pcap.bin and the organization secret) with a fresh AES-256-GCM key and wraps that key for each validator with a sealed box (PyNaCl SealedBox, pinned version), producing one bundle per validator. The validator service decrypts into a temporary directory with mode 0700 and deletes it after the engine run. Also encrypt data/cases/<id>/pcap.bin at rest with a key from the environment.
Tests: a wrong validator key fails; tampered ciphertext fails; the plaintext PCAP never appears outside the temporary directory; temporary files are removed after success and after failure.
Acceptance: the full demo works with encrypted delivery.
```

### Prompt T3.2: LLM recommendations (advisory)

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 4.8. Attach backend/reports/.
Add an advisory recommendation generator. Input: findings.json only, never PCAP data, sessions or evidence payloads. Output JSON: a list of {findingId, summary, steps}. A validator function rejects any item whose findingId is not in findings.json, any item with a missing field, and any configuration snippet containing a parameter name that is not in an allow-list built from recommendations.yaml; rejected items are replaced by the rule's static template. The LLM provider call sits behind an interface with a fake implementation used by tests. All generated text is marked advisory in the report.
Tests: a hallucinated findingId is rejected; a snippet with an unknown parameter is replaced; the fake provider path works; the result root is unchanged when the generator runs.
Acceptance: the report shows labeled generated recommendations and the verifier still passes.
```

### Prompt T3.3: kill-and-resume chaos test

```
Read AGENT_RULES.md and docs/ARCHITECTURE.md section 9. Attach backend/ and validator/.
Create scripts/chaos_test.py: for each step of the flow (analyze, open, claim, distribute, commit, reveal, finalize, record, anchor) run the flow, SIGKILL the responsible process (API worker, gateway or a validator service) at that step, restart it, and let the flow finish. Assert that the case ends Finalized, that chain_txs holds no duplicate transaction for any step, and that the verifier passes. Print a table of step, killed process and result.
Acceptance: every row passes; fix any failure with Template B.
```

## Checkpoints

| Checkpoint | After | You can show |
| --- | --- | --- |
| M1 | Prompt 3.3 | A full case on a local chain with stub analysis, plus tamper and faulty-validator scenarios |
| Gate 1 | M1 | If not reached by about a quarter of your time, drop all of Tier 2 |
| M2 | Prompt 5.8 | Real analysis reproducing every labeled lab finding, deterministic across containers |
| Gate 2 | M2 | If not reached by about half to 55 percent of your time, finish only the Tier 1 path |
| M3 | Prompt 6.3 | The flow through the API with three validator services and crash recovery |
| M4 | Prompt 7.2 | One case from upload to verified in the browser |
| M5 | Prompt 8.1 | All evaluation tables regenerated by one command |

The percentages and gates are my rules of thumb, not measured values.

## Decisions introduced by this library

These go beyond the architecture document. Copy them into docs/ARCHITECTURE.md (or confirm them in docs/decisions/) so the specification and the code agree.

1. Expired takes precedence over Disputed: if fewer than k validators reveal at all, the case is Expired, otherwise Disputed.
2. Reveals must match the engine and ruleset hashes stored in the case at claim time, not the current pinned pair.
3. caseId = keccak256(abi.encode(pcapHash, analyst, counter)). Registering the same PCAP twice creates two cases.
4. Validators run in strict mode by default and abort before committing if their local ruleset hash differs from the case's. Only the evaluation scenarios disable this.
5. Certificate-rule lab scenarios use a client capped at TLS 1.2. S01 is split into S01a (certificate visible) and S01b (TLS 1.3, certificate not observable, R19).
6. Expected findings in lab labels are derived from tshark-observed fields and the rule definitions, never from the engine's own output.
7. Tier 1 delivers PCAPs to validators by file copy. Encrypted delivery and encryption at rest are Tier 3.
8. Admin is a single account in the demo and must be described as a simplification in the report.
9. PCAPNG and link types other than Ethernet and Linux cooked capture are rejected.
10. Overlapping TCP segments keep first-seen bytes, and a stream with a gap delivers only its contiguous prefix and is marked incomplete.
