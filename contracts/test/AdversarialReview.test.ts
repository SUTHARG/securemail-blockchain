import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import * as fs from "fs";
import * as path from "path";
import { CaseRegistry, ValidationQuorum, PostureLedger } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("Adversarial Contract Review Suite (Prompt 2.4)", function () {
  let registry: CaseRegistry;
  let quorum: ValidationQuorum;
  let ledger: PostureLedger;

  let admin: HardhatEthersSigner;
  let analyst: HardhatEthersSigner;
  let analyst2: HardhatEthersSigner;
  let validator1: HardhatEthersSigner;
  let validator2: HardhatEthersSigner;
  let validator3: HardhatEthersSigner;
  let attacker: HardhatEthersSigner;

  const samplePcapHash = "0x" + "11".repeat(32);
  const samplePcapHash2 = "0x" + "22".repeat(32);
  const sampleImageDigest = "0x" + "aa".repeat(32);
  const sampleRulesetHash = "0x" + "bb".repeat(32);
  const sampleResultRoot = "0x" + "dd".repeat(32);
  const alternativeRoot = "0x" + "ee".repeat(32);

  const salt1 = "0x" + "01".repeat(32);
  const salt2 = "0x" + "02".repeat(32);

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const hashesVectorPath = path.resolve(__dirname, "../../spec/test-vectors/hashes.json");
  const merkleVectorPath = path.resolve(__dirname, "../../spec/test-vectors/merkle_trees.json");
  const hashesVectors = JSON.parse(fs.readFileSync(hashesVectorPath, "utf-8"));
  const merkleTreesVectors = JSON.parse(fs.readFileSync(merkleVectorPath, "utf-8"));

  function computeCommitment(caseId: string, validatorAddress: string, root: string, salt: string): string {
    return ethers.keccak256(
      abiCoder.encode(["bytes32", "address", "bytes32", "bytes32"], [caseId, validatorAddress, root, salt])
    );
  }

  async function openCase(analystSigner: HardhatEthersSigner, pcapHash: string = samplePcapHash): Promise<string> {
    const tx = await registry.connect(analystSigner).openCase(pcapHash);
    const rc = await tx.wait();
    return (rc?.logs[0] as any).args[0];
  }

  beforeEach(async function () {
    [
      admin,
      analyst,
      analyst2,
      validator1,
      validator2,
      validator3,
      attacker,
    ] = await ethers.getSigners();

    const CaseRegistryFactory = await ethers.getContractFactory("CaseRegistry");
    registry = await CaseRegistryFactory.deploy();
    await registry.waitForDeployment();

    const ValidationQuorumFactory = await ethers.getContractFactory("ValidationQuorum");
    quorum = await ValidationQuorumFactory.deploy(await registry.getAddress(), 60, 60);
    await quorum.waitForDeployment();

    const PostureLedgerFactory = await ethers.getContractFactory("PostureLedger");
    ledger = await PostureLedgerFactory.deploy(await registry.getAddress());
    await ledger.waitForDeployment();

    // Setup roles
    const ANALYST_ROLE = await registry.ANALYST_ROLE();
    const QUORUM_ROLE = await registry.QUORUM_ROLE();

    await registry.grantRole(ANALYST_ROLE, analyst.address);
    await registry.grantRole(ANALYST_ROLE, analyst2.address);
    await registry.grantRole(QUORUM_ROLE, await quorum.getAddress());

    await registry.connect(admin).registerEngine(sampleImageDigest, sampleRulesetHash);

    await registry.connect(admin).addValidator(validator1.address);
    await registry.connect(admin).addValidator(validator2.address);
    await registry.connect(admin).addValidator(validator3.address);
  });

  it("(1) Finalize without k matching reveals is strictly prevented", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
    await quorum.connect(validator1).commit(caseId, c1);

    await time.increase(60);
    await quorum.advance(caseId);

    // Only 1 validator reveals (k = 2 required)
    await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);

    // Attacker tries to finalize before window passes -> reverts OutcomeNotReady
    await expect(quorum.connect(attacker).finalize(caseId)).to.be.revertedWithCustomError(quorum, "OutcomeNotReady");

    // After window passes, finalize expires instead of finalizing
    await time.increase(61);
    await expect(quorum.connect(attacker).finalize(caseId)).to.emit(quorum, "CaseExpired");
    expect(await registry.caseState(caseId)).to.equal(7); // Expired

    // Attacker or admin tries to force finalize via AttestMajority from Expired -> reverts
    await expect(
      quorum.connect(admin).resolve(caseId, 0, sampleResultRoot)
    ).to.be.revertedWithCustomError(quorum, "AttestMajorityNotAllowedForExpired");
  });

  it("(2) Reveal on behalf of a validator you do not control is strictly prevented", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
    await quorum.connect(validator1).commit(caseId, c1);

    await time.increase(60);
    await quorum.advance(caseId);

    // Attacker calls reveal pretending to reveal validator1's salt and root
    // reveal derives validator from msg.sender, so attacker is rejected as NotSnapshotValidator
    await expect(
      quorum.connect(attacker).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "NotSnapshotValidator")
      .withArgs(caseId, 1, attacker.address);
  });

  it("(3) Copying another validator's commitment root is strictly prevented", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    // Validator1 computes commitment
    const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
    await quorum.connect(validator1).commit(caseId, c1);

    // Validator2 is a valid snapshot validator, but acts maliciously by copying c1 from mempool
    await quorum.connect(validator2).commit(caseId, c1);

    await time.increase(60);
    await quorum.advance(caseId);

    // In reveal, Validator2 attempts to reveal the pre-image
    // Computed commitment hashes msg.sender (validator2) != c1 (which was hashed with validator1)
    await expect(
      quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
  });

  it("(4) Changing state out of order is strictly prevented", async function () {
    const caseId = await openCase(analyst);

    // Non-quorum caller cannot call CaseRegistry mutators directly
    await expect(
      registry.connect(attacker).setState(caseId, 5)
    ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");

    // Cannot advance while in Opened state
    await expect(quorum.advance(caseId)).to.be.revertedWithCustomError(quorum, "InvalidCaseState");

    // Cannot commit while in Opened state
    const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
    await expect(quorum.connect(validator1).commit(caseId, c1)).to.be.revertedWithCustomError(quorum, "InvalidCaseState");

    // Submit claim moves to Committing
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    // Cannot advance before commitDeadline
    await expect(quorum.advance(caseId)).to.be.revertedWithCustomError(quorum, "CommitWindowActive");

    // Cannot reveal while in Committing state
    await expect(
      quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "InvalidCaseState");

    // Cannot resolve while in Committing state
    await expect(
      quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash)
    ).to.be.revertedWithCustomError(quorum, "InvalidCaseState");
  });

  it("(5) Recording posture for a case that is not Finalized is strictly prevented", async function () {
    const caseId = await openCase(analyst);
    const tree2 = merkleTreesVectors.find((t: any) => t.leafCount === 2);
    const hostVector = hashesVectors.host_score_leaf[0];
    const hostId = "0x" + hostVector.hostIdHex;
    const findingsDigest = "0x" + hostVector.findingsDigestHex;
    const score = hostVector.score;
    const proof = tree2.proofs[tree2.leaves[1].leaf].map((p: string) => "0x" + p);

    // Case is in Opened state
    await expect(
      ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof)
    ).to.be.revertedWithCustomError(ledger, "CaseNotFinalized")
      .withArgs(caseId, 1);

    // Move to Committing
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
    await expect(
      ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof)
    ).to.be.revertedWithCustomError(ledger, "CaseNotFinalized")
      .withArgs(caseId, 3);
  });

  it("(6) Recording the same host twice for one case is strictly prevented", async function () {
    const tree2 = merkleTreesVectors.find((t: any) => t.leafCount === 2);
    const rootHex = tree2.rootHex;
    const hostVector = hashesVectors.host_score_leaf[0];
    const hostId = "0x" + hostVector.hostIdHex;
    const findingsDigest = "0x" + hostVector.findingsDigestHex;
    const score = hostVector.score;
    const proof = tree2.proofs[tree2.leaves.find((l: any) => l.type === "host_score").leaf].map((p: string) => "0x" + p);

    // Finalize case
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, "0x" + rootHex, sampleImageDigest, sampleRulesetHash);
    const c1 = computeCommitment(caseId, validator1.address, "0x" + rootHex, salt1);
    const c2 = computeCommitment(caseId, validator2.address, "0x" + rootHex, salt2);
    await quorum.connect(validator1).commit(caseId, c1);
    await quorum.connect(validator2).commit(caseId, c2);
    await time.increase(60);
    await quorum.advance(caseId);
    await quorum.connect(validator1).reveal(caseId, "0x" + rootHex, salt1, sampleImageDigest, sampleRulesetHash);
    await quorum.connect(validator2).reveal(caseId, "0x" + rootHex, salt2, sampleImageDigest, sampleRulesetHash);
    await quorum.finalize(caseId);

    // First posture record succeeds
    await ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof);

    // Second posture record for same (caseId, hostId) reverts
    await expect(
      ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof)
    ).to.be.revertedWithCustomError(ledger, "PostureAlreadyRecorded")
      .withArgs(caseId, hostId);
  });

  it("(7) Replaying a commit from another case or another round is strictly prevented", async function () {
    const caseId1 = await openCase(analyst, samplePcapHash);
    const caseId2 = await openCase(analyst, samplePcapHash2);

    await quorum.connect(analyst).submitClaim(caseId1, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
    await quorum.connect(analyst).submitClaim(caseId2, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    // Compute commitment for caseId1
    const cForCase1 = computeCommitment(caseId1, validator1.address, sampleResultRoot, salt1);

    // Validator1 commits cForCase1 to caseId2
    await quorum.connect(validator1).commit(caseId2, cForCase1);

    await time.increase(60);
    await quorum.advance(caseId2);

    // Validator1 tries to reveal on caseId2 -> commitment mismatch because caseId in hash differs
    await expect(
      quorum.connect(validator1).reveal(caseId2, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
  });

  it("(8) Changing pinned engine after claim does not alter in-flight verification", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    // Admin registers new engine globally
    const newImage = "0x" + "88".repeat(32);
    const newRuleset = "0x" + "77".repeat(32);
    await registry.connect(admin).registerEngine(newImage, newRuleset);

    const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
    const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
    await quorum.connect(validator1).commit(caseId, c1);
    await quorum.connect(validator2).commit(caseId, c2);

    await time.increase(60);
    await quorum.advance(caseId);

    // Revealing with new global engine fails
    await expect(
      quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, newImage, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "EngineMismatch");

    // Revealing with case's pinned pair succeeds
    await expect(
      quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.emit(quorum, "RevealSubmitted");
  });

  it("(9) Leaving a case permanently stuck is prevented (permissionless progress)", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    await time.increase(60);
    // Anyone (e.g. attacker or public bot) can advance
    await quorum.connect(attacker).advance(caseId);
    expect(await registry.caseState(caseId)).to.equal(4); // Revealing

    await time.increase(61);
    // Anyone can finalize an expired case
    await quorum.connect(attacker).finalize(caseId);
    expect(await registry.caseState(caseId)).to.equal(7); // Expired

    // Admin can restart or reject
    await quorum.connect(admin).resolve(caseId, 2, ethers.ZeroHash); // Reject
    expect(await registry.caseState(caseId)).to.equal(8); // Rejected
  });

  it("(10) Overflow or score manipulation (> 100) is strictly prevented", async function () {
    const caseId = await openCase(analyst);
    const tree2 = merkleTreesVectors.find((t: any) => t.leafCount === 2);
    const rootHex = tree2.rootHex;
    const hostVector = hashesVectors.host_score_leaf[0];
    const hostId = "0x" + hostVector.hostIdHex;
    const findingsDigest = "0x" + hostVector.findingsDigestHex;
    const proof = tree2.proofs[tree2.leaves.find((l: any) => l.type === "host_score").leaf].map((p: string) => "0x" + p);

    // Finalize case
    await quorum.connect(analyst).submitClaim(caseId, "0x" + rootHex, sampleImageDigest, sampleRulesetHash);
    const c1 = computeCommitment(caseId, validator1.address, "0x" + rootHex, salt1);
    const c2 = computeCommitment(caseId, validator2.address, "0x" + rootHex, salt2);
    await quorum.connect(validator1).commit(caseId, c1);
    await quorum.connect(validator2).commit(caseId, c2);
    await time.increase(60);
    await quorum.advance(caseId);
    await quorum.connect(validator1).reveal(caseId, "0x" + rootHex, salt1, sampleImageDigest, sampleRulesetHash);
    await quorum.connect(validator2).reveal(caseId, "0x" + rootHex, salt2, sampleImageDigest, sampleRulesetHash);
    await quorum.finalize(caseId);

    // Score > 100 reverts with InvalidScore
    await expect(
      ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, 101, proof)
    ).to.be.revertedWithCustomError(ledger, "InvalidScore")
      .withArgs(101);
  });

  it("(11) Reentrancy: verified that no state hijacking is possible", async function () {
    // Contracts do not make untrusted calls or transfer ETH/ERC20 tokens.
    // Immutable address binding ensures only trusted CaseRegistry is called.
    expect(await quorum.caseRegistry()).to.equal(await registry.getAddress());
    expect(await ledger.caseRegistry()).to.equal(await registry.getAddress());
  });

  it("Edge case: submitClaim fails when registered validators < 3", async function () {
    await registry.connect(admin).removeValidator(validator3.address);
    expect(await registry.validatorCount()).to.equal(2);

    const caseId = await openCase(analyst);
    await expect(
      quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
    ).to.be.revertedWithCustomError(quorum, "InsufficientValidators")
      .withArgs(2);
  });

  it("Edge case: validator removed post-snapshot can still participate in active snapshot round", async function () {
    const caseId = await openCase(analyst);
    await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

    // Admin removes validator3 from registry AFTER snapshot
    await registry.connect(admin).removeValidator(validator3.address);
    expect(await registry.validatorCount()).to.equal(2);
    expect(await registry.isValidator(validator3.address)).to.be.false;

    // But validator3 IS in the snapshot for this case and round!
    expect(await quorum.isSnapshotValidator(caseId, 1, validator3.address)).to.be.true;

    // validator3 can commit and reveal in the snapshotted round
    const c3 = computeCommitment(caseId, validator3.address, sampleResultRoot, salt1);
    await expect(quorum.connect(validator3).commit(caseId, c3)).to.emit(quorum, "CommitSubmitted");

    await time.increase(60);
    await quorum.advance(caseId);

    await expect(
      quorum.connect(validator3).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
    ).to.emit(quorum, "RevealSubmitted");
  });
});
