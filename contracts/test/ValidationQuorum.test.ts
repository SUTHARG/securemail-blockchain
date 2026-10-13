import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { CaseRegistry, ValidationQuorum } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("ValidationQuorum Suite", function () {
  let registry: CaseRegistry;
  let quorum: ValidationQuorum;

  let admin: HardhatEthersSigner;
  let analyst: HardhatEthersSigner;
  let analyst2: HardhatEthersSigner;
  let validator1: HardhatEthersSigner;
  let validator2: HardhatEthersSigner;
  let validator3: HardhatEthersSigner;
  let validator4: HardhatEthersSigner;
  let validator5: HardhatEthersSigner;
  let unprivileged: HardhatEthersSigner;

  const samplePcapHash = "0x" + "11".repeat(32);
  const samplePcapHash2 = "0x" + "22".repeat(32);
  const sampleImageDigest = "0x" + "aa".repeat(32);
  const sampleRulesetHash = "0x" + "bb".repeat(32);
  const sampleResultRoot = "0x" + "dd".repeat(32);
  const alternativeRoot = "0x" + "ee".repeat(32);
  const thirdRoot = "0x" + "ff".repeat(32);

  const salt1 = "0x" + "01".repeat(32);
  const salt2 = "0x" + "02".repeat(32);
  const salt3 = "0x" + "03".repeat(32);
  const salt4 = "0x" + "04".repeat(32);
  const salt5 = "0x" + "05".repeat(32);

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  function computeCommitment(caseId: string, validatorAddress: string, root: string, salt: string): string {
    return ethers.keccak256(
      abiCoder.encode(["bytes32", "address", "bytes32", "bytes32"], [caseId, validatorAddress, root, salt])
    );
  }

  async function openCase(analystSigner: HardhatEthersSigner, pcapHash: string = samplePcapHash): Promise<string> {
    const tx = await registry.connect(analystSigner).openCase(pcapHash);
    const receipt = await tx.wait();
    return (receipt?.logs[0] as any).args[0];
  }

  beforeEach(async function () {
    [
      admin,
      analyst,
      analyst2,
      validator1,
      validator2,
      validator3,
      validator4,
      validator5,
      unprivileged,
    ] = await ethers.getSigners();

    const CaseRegistryFactory = await ethers.getContractFactory("CaseRegistry");
    registry = await CaseRegistryFactory.deploy();
    await registry.waitForDeployment();

    const ValidationQuorumFactory = await ethers.getContractFactory("ValidationQuorum");
    quorum = await ValidationQuorumFactory.deploy(await registry.getAddress(), 60, 60);
    await quorum.waitForDeployment();

    // Grant roles on registry
    const ANALYST_ROLE = await registry.ANALYST_ROLE();
    const QUORUM_ROLE = await registry.QUORUM_ROLE();

    await registry.grantRole(ANALYST_ROLE, analyst.address);
    await registry.grantRole(ANALYST_ROLE, analyst2.address);
    await registry.grantRole(QUORUM_ROLE, await quorum.getAddress());

    // Register active engine
    await registry.connect(admin).registerEngine(sampleImageDigest, sampleRulesetHash);

    // Register 3 default validators
    await registry.connect(admin).addValidator(validator1.address);
    await registry.connect(admin).addValidator(validator2.address);
    await registry.connect(admin).addValidator(validator3.address);
  });

  describe("A. Basic Validation", function () {
    it("Three-validator happy path: N=3, k=2, transitions to Finalized with matching finalRoot", async function () {
      const caseId = await openCase(analyst);

      // Submit claim
      await expect(
        quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "ClaimSubmitted");

      const params = await quorum.getRoundParams(caseId, 1);
      expect(params.n).to.equal(3);
      expect(params.k).to.equal(2);

      // Verify case state is Committing
      expect(await registry.caseState(caseId)).to.equal(3); // Committing

      // Commit
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      const c3 = computeCommitment(caseId, validator3.address, sampleResultRoot, salt3);

      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);
      await quorum.connect(validator3).commit(caseId, c3);

      // Advance past commit window
      await time.increase(60);
      await quorum.advance(caseId);
      expect(await registry.caseState(caseId)).to.equal(4); // Revealing

      // Reveal 2 matching roots (reaches k=2)
      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash);

      // Finalize immediately succeeds because k matching reveals exist
      const finTx = await quorum.finalize(caseId);
      await expect(finTx)
        .to.emit(quorum, "CaseFinalized")
        .withArgs(caseId, sampleResultRoot, false);

      expect(await registry.caseState(caseId)).to.equal(5); // Finalized
      expect(await registry.finalRoot(caseId)).to.equal(sampleResultRoot);
      expect(await registry.isContradicted(caseId)).to.equal(false);
    });

    it("Five-validator happy path: N=5, k=3", async function () {
      await registry.connect(admin).addValidator(validator4.address);
      await registry.connect(admin).addValidator(validator5.address);

      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const params = await quorum.getRoundParams(caseId, 1);
      expect(params.n).to.equal(5);
      expect(params.k).to.equal(3); // 5 / 2 + 1 = 3

      // All 5 commit
      const vals = [validator1, validator2, validator3, validator4, validator5];
      const salts = [salt1, salt2, salt3, salt4, salt5];
      for (let i = 0; i < 5; i++) {
        const c = computeCommitment(caseId, vals[i].address, sampleResultRoot, salts[i]);
        await quorum.connect(vals[i]).commit(caseId, c);
      }

      await time.increase(60);
      await quorum.advance(caseId);

      // Reveal 3 matching claims (reaches k=3)
      for (let i = 0; i < 3; i++) {
        await quorum.connect(vals[i]).reveal(caseId, sampleResultRoot, salts[i], sampleImageDigest, sampleRulesetHash);
      }

      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(5); // Finalized
      expect(await registry.finalRoot(caseId)).to.equal(sampleResultRoot);
    });

    it("Case remains Committing during commit phase and becomes Revealing after advance", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      expect(await registry.caseState(caseId)).to.equal(3); // Committing
      await time.increase(60);
      await quorum.advance(caseId);
      expect(await registry.caseState(caseId)).to.equal(4); // Revealing
    });
  });

  describe("B. Quorum Thresholds", function () {
    it("Exactly k validators reveal claimed root enables finalization", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      // Exactly k=2 reveal
      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash);

      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(5);
    });

    it("Only k - 1 validators reveal claimed root: cannot finalize early; expires if total < k", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);

      // Only 1 reveals (k=2, so k-1 = 1)
      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);

      // Early finalize fails
      await expect(quorum.finalize(caseId)).to.be.revertedWithCustomError(quorum, "OutcomeNotReady");

      // Advance past reveal window
      await time.increase(61);

      // Evaluates: totalReveals (1) < k (2) -> Expired
      await expect(quorum.finalize(caseId))
        .to.emit(quorum, "CaseExpired")
        .withArgs(caseId, 1);
      expect(await registry.caseState(caseId)).to.equal(7); // Expired
    });

    it("Enough validators reveal in total, but disagree with claim: transitions to Disputed", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // 1 commits to claimed root, 2 commit to alternative root
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);
      const c3 = computeCommitment(caseId, validator3.address, alternativeRoot, salt3);

      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);
      await quorum.connect(validator3).commit(caseId, c3);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator3).reveal(caseId, alternativeRoot, salt3, sampleImageDigest, sampleRulesetHash);

      // claimedRoot has 1 reveal (< k=2), so cannot finalize early
      await expect(quorum.finalize(caseId)).to.be.revertedWithCustomError(quorum, "OutcomeNotReady");

      await time.increase(61);

      // Total reveals = 3 >= k=2, but claimedRoot < k -> Disputed
      await expect(quorum.finalize(caseId))
        .to.emit(quorum, "CaseDisputed")
        .withArgs(caseId, 1);
      expect(await registry.caseState(caseId)).to.equal(6); // Disputed
    });

    it("Counts matching roots rather than merely total reveals", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // 3 validators all reveal different roots: sampleResultRoot, alternativeRoot, thirdRoot
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);
      const c3 = computeCommitment(caseId, validator3.address, thirdRoot, salt3);

      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);
      await quorum.connect(validator3).commit(caseId, c3);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator3).reveal(caseId, thirdRoot, salt3, sampleImageDigest, sampleRulesetHash);

      expect(await quorum.getRevealCount(caseId, 1, sampleResultRoot)).to.equal(1);
      expect(await quorum.getRevealCount(caseId, 1, alternativeRoot)).to.equal(1);
      expect(await quorum.getRevealCount(caseId, 1, thirdRoot)).to.equal(1);

      await time.increase(61);
      // Total reveals is 3, but highest root has only 1 (< k=2) -> Disputed
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(6); // Disputed
    });

    it("A validator submits the same result root as another validator, correctly incrementing reveal count", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId, validator1.address, alternativeRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);

      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, alternativeRoot, salt1, sampleImageDigest, sampleRulesetHash);
      expect(await quorum.getRevealCount(caseId, 1, alternativeRoot)).to.equal(1);

      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);
      expect(await quorum.getRevealCount(caseId, 1, alternativeRoot)).to.equal(2);
    });
  });

  describe("C. Access Control", function () {
    it("Non-analyst cannot submit a claim", async function () {
      const caseId = await openCase(analyst);
      const ANALYST_ROLE = await registry.ANALYST_ROLE();

      await expect(
        quorum.connect(unprivileged).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ANALYST_ROLE);
    });

    it("Different analyst cannot submit a claim for another analyst's case", async function () {
      const caseId = await openCase(analyst);

      await expect(
        quorum.connect(analyst2).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NotCaseAnalyst")
        .withArgs(caseId, analyst2.address);
    });

    it("Non-validator cannot commit or reveal", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c = computeCommitment(caseId, unprivileged.address, sampleResultRoot, salt1);
      await expect(
        quorum.connect(unprivileged).commit(caseId, c)
      ).to.be.revertedWithCustomError(quorum, "NotSnapshotValidator")
        .withArgs(caseId, 1, unprivileged.address);

      await time.increase(60);
      await quorum.advance(caseId);

      await expect(
        quorum.connect(unprivileged).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NotSnapshotValidator")
        .withArgs(caseId, 1, unprivileged.address);
    });

    it("Validator added after claim submission is outside snapshot and cannot commit or reveal", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // Add validator4 after snapshot was taken
      await registry.connect(admin).addValidator(validator4.address);

      const c4 = computeCommitment(caseId, validator4.address, sampleResultRoot, salt4);
      await expect(
        quorum.connect(validator4).commit(caseId, c4)
      ).to.be.revertedWithCustomError(quorum, "NotSnapshotValidator")
        .withArgs(caseId, 1, validator4.address);

      await time.increase(60);
      await quorum.advance(caseId);

      await expect(
        quorum.connect(validator4).reveal(caseId, sampleResultRoot, salt4, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NotSnapshotValidator")
        .withArgs(caseId, 1, validator4.address);
    });

    it("Unauthorized caller cannot resolve a case", async function () {
      const ADMIN_ROLE = await quorum.ADMIN_ROLE();
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      await expect(
        quorum.connect(unprivileged).resolve(caseId, 0, sampleResultRoot)
      ).to.be.revertedWithCustomError(quorum, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ADMIN_ROLE);
    });

    it("Only ADMIN_ROLE can change window configuration", async function () {
      const ADMIN_ROLE = await quorum.ADMIN_ROLE();

      await expect(
        quorum.connect(unprivileged).setWindows(120, 120)
      ).to.be.revertedWithCustomError(quorum, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ADMIN_ROLE);

      await expect(quorum.connect(admin).setWindows(120, 120))
        .to.emit(quorum, "WindowsUpdated")
        .withArgs(120, 120);

      expect(await quorum.commitWindow()).to.equal(120);
      expect(await quorum.revealWindow()).to.equal(120);

      // Zero window rejected
      await expect(
        quorum.connect(admin).setWindows(0, 120)
      ).to.be.revertedWithCustomError(quorum, "InvalidWindow");
      await expect(
        quorum.connect(admin).setWindows(120, 0)
      ).to.be.revertedWithCustomError(quorum, "InvalidWindow");
    });
  });

  describe("D. Commitment Security", function () {
    let caseId: string;

    beforeEach(async function () {
      caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
    });

    it("Wrong salt reverts with CommitmentMismatch", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);

      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
    });

    it("Wrong result root reverts with CommitmentMismatch", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);

      await expect(
        quorum.connect(validator1).reveal(caseId, alternativeRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
    });

    it("Commitment from another validator cannot be reused", async function () {
      // Validator 1 computes commitment for validator 1
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      // Validator 2 attempts to submit validator 1's commitment
      await quorum.connect(validator2).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);

      // When validator 2 reveals with its own sender, it will hash (caseId, validator2, sampleResultRoot, salt1) != c1
      await expect(
        quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
    });

    it("Commitment from another case cannot be reused", async function () {
      const caseId2 = await openCase(analyst, samplePcapHash2);
      await quorum.connect(analyst).submitClaim(caseId2, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // Commitment computed for caseId2
      const cForCase2 = computeCommitment(caseId2, validator1.address, sampleResultRoot, salt1);
      // Validator 1 submits that commitment to caseId
      await quorum.connect(validator1).commit(caseId, cForCase2);

      await time.increase(60);
      await quorum.advance(caseId);

      // Reveals on caseId -> mismatch
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "CommitmentMismatch");
    });

    it("Double commit reverts", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await expect(
        quorum.connect(validator1).commit(caseId, c1)
      ).to.be.revertedWithCustomError(quorum, "AlreadyCommitted")
        .withArgs(caseId, 1, validator1.address);
    });

    it("Double reveal reverts", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);

      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "AlreadyRevealed")
        .withArgs(caseId, 1, validator1.address);
    });

    it("Reveal without prior commitment reverts", async function () {
      await time.increase(60);
      await quorum.advance(caseId);

      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NoPriorCommitment")
        .withArgs(caseId, 1, validator1.address);
    });

    it("A commitment from another round cannot be reused", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.increase(60);
      await quorum.advance(caseId);
      await time.increase(61);
      await quorum.finalize(caseId); // Expired

      // Start round 2
      await quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash); // NewRound
      expect(await registry.caseRound(caseId)).to.equal(2);

      // In round 2, validator 1 has not committed yet
      expect(await quorum.hasCommitted(caseId, 2, validator1.address)).to.be.false;

      await time.increase(60);
      await quorum.advance(caseId);

      // Attempt to reveal in round 2 using round 1's prior commitment reverts
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NoPriorCommitment")
        .withArgs(caseId, 2, validator1.address);
    });
  });

  describe("E. Deadline Security", function () {
    let caseId: string;
    let commitDeadline: bigint;
    let revealDeadline: bigint;

    beforeEach(async function () {
      caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const params = await quorum.getRoundParams(caseId, 1);
      commitDeadline = params.commitDeadline;
      revealDeadline = params.revealDeadline;
    });

    it("Commit before deadline succeeds, at and after deadline fails", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);

      // Before deadline (strictly < commitDeadline)
      await time.setNextBlockTimestamp(commitDeadline - 1n);
      await expect(quorum.connect(validator1).commit(caseId, c1)).to.emit(quorum, "CommitSubmitted");

      // Exactly at deadline (block.timestamp == commitDeadline)
      await time.setNextBlockTimestamp(commitDeadline);
      await expect(
        quorum.connect(validator2).commit(caseId, c2)
      ).to.be.revertedWithCustomError(quorum, "CommitDeadlinePassed")
        .withArgs(commitDeadline, commitDeadline);

      // After deadline (block.timestamp > commitDeadline)
      await time.setNextBlockTimestamp(commitDeadline + 10n);
      await expect(
        quorum.connect(validator2).commit(caseId, c2)
      ).to.be.revertedWithCustomError(quorum, "CommitDeadlinePassed")
        .withArgs(commitDeadline, commitDeadline + 10n);
    });

    it("Advance before deadline fails, at and after deadline succeeds", async function () {
      // Before deadline: fails with CommitWindowActive
      await time.setNextBlockTimestamp(commitDeadline - 1n);
      await expect(quorum.advance(caseId)).to.be.revertedWithCustomError(quorum, "CommitWindowActive");

      // Exactly at deadline: succeeds
      await time.setNextBlockTimestamp(commitDeadline);
      await expect(quorum.advance(caseId)).to.not.be.reverted;
      expect(await registry.caseState(caseId)).to.equal(4); // Revealing
    });

    it("Reveal before revealDeadline succeeds, at and after revealDeadline fails", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.setNextBlockTimestamp(commitDeadline);
      await quorum.advance(caseId);

      // Reveal before deadline (strictly < revealDeadline)
      await time.setNextBlockTimestamp(revealDeadline - 1n);
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "RevealSubmitted");

      // Exactly at revealDeadline (block.timestamp == revealDeadline)
      await time.setNextBlockTimestamp(revealDeadline);
      await expect(
        quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "RevealDeadlinePassed")
        .withArgs(revealDeadline, revealDeadline);

      // After revealDeadline (block.timestamp > revealDeadline)
      await time.setNextBlockTimestamp(revealDeadline + 5n);
      await expect(
        quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "RevealDeadlinePassed")
        .withArgs(revealDeadline, revealDeadline + 5n);
    });

    it("Outcome evaluation boundary: OutcomeNotReady before and exactly at revealDeadline, succeeds strictly after", async function () {
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await quorum.connect(validator1).commit(caseId, c1);

      await time.setNextBlockTimestamp(commitDeadline);
      await quorum.advance(caseId);

      // Only 1 validator revealed (below k=2)
      await time.setNextBlockTimestamp(commitDeadline + 1n);
      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);

      // Immediately before revealDeadline
      await time.setNextBlockTimestamp(revealDeadline - 1n);
      await expect(quorum.finalize(caseId)).to.be.revertedWithCustomError(quorum, "OutcomeNotReady");

      // Exactly at revealDeadline
      await time.setNextBlockTimestamp(revealDeadline);
      await expect(quorum.finalize(caseId)).to.be.revertedWithCustomError(quorum, "OutcomeNotReady");

      // Strictly after revealDeadline
      await time.setNextBlockTimestamp(revealDeadline + 1n);
      await expect(quorum.finalize(caseId)).to.emit(quorum, "CaseExpired");
    });

    it("Finalize before Revealing state reverts with InvalidCaseState", async function () {
      const caseId2 = await openCase(analyst, samplePcapHash2);
      // In Opened state
      await expect(quorum.finalize(caseId2))
        .to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId2, 1);

      await quorum.connect(analyst).submitClaim(caseId2, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
      // In Committing state
      await expect(quorum.finalize(caseId2))
        .to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId2, 3);
    });
  });

  describe("F. Engine and Ruleset Pinning", function () {
    it("Claim with unconfigured or wrong engine/ruleset fails", async function () {
      const caseId = await openCase(analyst);
      const wrongHash = "0x" + "99".repeat(32);

      await expect(
        quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, wrongHash, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "EngineMismatch");

      await expect(
        quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, wrongHash)
      ).to.be.revertedWithCustomError(quorum, "RulesetMismatch");

      await expect(
        quorum.connect(analyst).submitClaim(caseId, ethers.ZeroHash, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "InvalidResultRoot");
    });

    it("Valid claim pins hashes and updating active engine globally does not alter case's verification pair", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      expect(await registry.engineHash(caseId)).to.equal(sampleImageDigest);
      expect(await registry.rulesetHash(caseId)).to.equal(sampleRulesetHash);

      // Admin updates global engine
      const newImage = "0x" + "88".repeat(32);
      const newRuleset = "0x" + "77".repeat(32);
      await registry.connect(admin).registerEngine(newImage, newRuleset);

      // Existing case retains pinned pair
      expect(await registry.engineHash(caseId)).to.equal(sampleImageDigest);

      // Validators commit
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      // Reveal with new active engine fails
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, newImage, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "EngineMismatch");

      // Reveal with new active ruleset fails
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, newRuleset)
      ).to.be.revertedWithCustomError(quorum, "RulesetMismatch");

      // Reveal with pinned pair succeeds
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "RevealSubmitted");
      await expect(
        quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "RevealSubmitted");

      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(5); // Finalized
    });
  });

  describe("G. Expiration and Disputes Resolution", function () {
    it("Disputed case resolved via AttestMajority if root >= k, marks contradicted if root != claimedRoot", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // 2 validators agree on alternativeRoot, 1 on sampleResultRoot
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);
      const c3 = computeCommitment(caseId, validator3.address, alternativeRoot, salt3);

      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);
      await quorum.connect(validator3).commit(caseId, c3);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator3).reveal(caseId, alternativeRoot, salt3, sampleImageDigest, sampleRulesetHash);

      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(6); // Disputed

      // Admin attempts AttestMajority for a root with < k reveals fails
      await expect(
        quorum.connect(admin).resolve(caseId, 0, sampleResultRoot) // AttestMajority
      ).to.be.revertedWithCustomError(quorum, "QuorumNotReached")
        .withArgs(2, 1);

      // Admin resolves with alternativeRoot (has 2 reveals >= k=2)
      const resTx = await quorum.connect(admin).resolve(caseId, 0, alternativeRoot);
      await expect(resTx)
        .to.emit(quorum, "CaseResolved")
        .withArgs(caseId, 0, alternativeRoot);
      await expect(resTx)
        .to.emit(quorum, "CaseFinalized")
        .withArgs(caseId, alternativeRoot, true);

      expect(await registry.caseState(caseId)).to.equal(5); // Finalized
      expect(await registry.finalRoot(caseId)).to.equal(alternativeRoot);
      expect(await registry.isContradicted(caseId)).to.equal(true);
    });

    it("NewRound works from Disputed", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);

      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(6); // Disputed

      // Admin resolves with NewRound
      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash) // NewRound
      ).to.emit(quorum, "CaseResolved")
        .withArgs(caseId, 1, ethers.ZeroHash);

      expect(await registry.caseState(caseId)).to.equal(3); // Committing
      expect(await registry.caseRound(caseId)).to.equal(2);
    });

    it("NewRound works from Expired", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      await time.increase(60);
      await quorum.advance(caseId);

      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(7); // Expired

      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash) // NewRound
      ).to.emit(quorum, "CaseResolved")
        .withArgs(caseId, 1, ethers.ZeroHash);

      expect(await registry.caseState(caseId)).to.equal(3); // Committing
      expect(await registry.caseRound(caseId)).to.equal(2);
    });

    it("Reject works from Disputed and Expired", async function () {
      // Disputed case rejection
      const caseId1 = await openCase(analyst, samplePcapHash);
      await quorum.connect(analyst).submitClaim(caseId1, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId1, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId1, validator2.address, alternativeRoot, salt2);
      await quorum.connect(validator1).commit(caseId1, c1);
      await quorum.connect(validator2).commit(caseId1, c2);

      await time.increase(60);
      await quorum.advance(caseId1);
      await quorum.connect(validator1).reveal(caseId1, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId1, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);
      await time.increase(61);
      await quorum.finalize(caseId1);
      expect(await registry.caseState(caseId1)).to.equal(6); // Disputed

      await expect(
        quorum.connect(admin).resolve(caseId1, 2, ethers.ZeroHash) // Reject
      ).to.emit(quorum, "CaseResolved")
        .withArgs(caseId1, 2, ethers.ZeroHash);
      expect(await registry.caseState(caseId1)).to.equal(8); // Rejected

      // Expired case rejection
      const caseId2 = await openCase(analyst, samplePcapHash2);
      await quorum.connect(analyst).submitClaim(caseId2, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
      await time.increase(60);
      await quorum.advance(caseId2);
      await time.increase(61);
      await quorum.finalize(caseId2);
      expect(await registry.caseState(caseId2)).to.equal(7); // Expired

      await expect(
        quorum.connect(admin).resolve(caseId2, 2, ethers.ZeroHash) // Reject
      ).to.emit(quorum, "CaseResolved")
        .withArgs(caseId2, 2, ethers.ZeroHash);
      expect(await registry.caseState(caseId2)).to.equal(8); // Rejected
    });

    it("AttestMajority from Expired reverts", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      await time.increase(60);
      await quorum.advance(caseId);
      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(7); // Expired

      await expect(
        quorum.connect(admin).resolve(caseId, 0, sampleResultRoot) // AttestMajority
      ).to.be.revertedWithCustomError(quorum, "AttestMajorityNotAllowedForExpired");
    });

    it("Resolve on non-disputed and non-expired states reverts", async function () {
      const caseId = await openCase(analyst);

      // Opened state
      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId, 1);

      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // Committing state
      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId, 3);
    });

    it("Resolving an already Finalized or Rejected case reverts", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash);

      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(5); // Finalized

      // Attempt to resolve already finalized case
      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId, 5);

      // Create an expired case and reject it
      const caseId2 = await openCase(analyst, samplePcapHash2);
      await quorum.connect(analyst).submitClaim(caseId2, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
      await time.increase(60);
      await quorum.advance(caseId2);
      await time.increase(61);
      await quorum.finalize(caseId2); // Expired
      await quorum.connect(admin).resolve(caseId2, 2, ethers.ZeroHash); // Reject
      expect(await registry.caseState(caseId2)).to.equal(8); // Rejected

      // Attempt to resolve already rejected case
      await expect(
        quorum.connect(admin).resolve(caseId2, 1, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(quorum, "InvalidCaseState")
        .withArgs(caseId2, 8);
    });
  });

  describe("H. Second-Round Isolation", function () {
    it("Round 2 has fresh validator snapshot, isolated commitments, isolated reveals, and preserved pinned hashes", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // Round 1 commits
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2 = computeCommitment(caseId, validator2.address, alternativeRoot, salt2);
      await quorum.connect(validator1).commit(caseId, c1);
      await quorum.connect(validator2).commit(caseId, c2);

      await time.increase(60);
      await quorum.advance(caseId);

      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, alternativeRoot, salt2, sampleImageDigest, sampleRulesetHash);

      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(6); // Disputed

      // Admin adds validator4 before starting NewRound
      await registry.connect(admin).addValidator(validator4.address);

      // Start NewRound (Round 2)
      await quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash);
      expect(await registry.caseRound(caseId)).to.equal(2);
      expect(await registry.caseState(caseId)).to.equal(3); // Committing

      // Round 2 snapshot includes validator4!
      expect(await quorum.isSnapshotValidator(caseId, 2, validator4.address)).to.be.true;
      const paramsR2 = await quorum.getRoundParams(caseId, 2);
      expect(paramsR2.n).to.equal(4);
      expect(paramsR2.k).to.equal(3); // 4 / 2 + 1 = 3

      // Verify Round 1 commitments are not considered committed in Round 2
      expect(await quorum.hasCommitted(caseId, 2, validator1.address)).to.be.false;
      expect(await quorum.hasRevealed(caseId, 2, validator1.address)).to.be.false;
      expect(await quorum.getRevealCount(caseId, 2, sampleResultRoot)).to.equal(0);

      // Pinned hashes are still intact from Round 1
      expect(await registry.engineHash(caseId)).to.equal(sampleImageDigest);
      expect(await registry.rulesetHash(caseId)).to.equal(sampleRulesetHash);
      expect(await registry.claimedRoot(caseId)).to.equal(sampleResultRoot);

      // In Round 2, validators commit fresh commitments
      const c1_r2 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      const c2_r2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      const c4_r2 = computeCommitment(caseId, validator4.address, sampleResultRoot, salt4);

      await quorum.connect(validator1).commit(caseId, c1_r2);
      await quorum.connect(validator2).commit(caseId, c2_r2);
      await quorum.connect(validator4).commit(caseId, c4_r2);

      await time.increase(60);
      await quorum.advance(caseId);

      // Reveal in Round 2
      await quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash);
      await quorum.connect(validator4).reveal(caseId, sampleResultRoot, salt4, sampleImageDigest, sampleRulesetHash);

      // Reaches k=3 matching reveals in Round 2
      expect(await quorum.getRevealCount(caseId, 2, sampleResultRoot)).to.equal(3);

      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(5); // Finalized
      expect(await registry.finalRoot(caseId)).to.equal(sampleResultRoot);
      expect(await registry.isContradicted(caseId)).to.equal(false);
    });

    it("NewRound fails if fewer than 3 validators are registered", async function () {
      const caseId = await openCase(analyst);
      await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      await time.increase(60);
      await quorum.advance(caseId);
      await time.increase(61);
      await quorum.finalize(caseId);
      expect(await registry.caseState(caseId)).to.equal(7); // Expired

      // Remove 1 validator so count becomes 2
      await registry.connect(admin).removeValidator(validator3.address);
      expect(await registry.validatorCount()).to.equal(2);

      await expect(
        quorum.connect(admin).resolve(caseId, 1, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(quorum, "InsufficientValidators")
        .withArgs(2);
    });
  });

  describe("I. Custody Events", function () {
    it("Verifies full event sequence and parameters across the lifecycle", async function () {
      const caseId = await openCase(analyst);

      // ClaimSubmitted
      await expect(
        quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "ClaimSubmitted")
        .withArgs(caseId, analyst.address, sampleResultRoot, sampleImageDigest, sampleRulesetHash);

      // CommitSubmitted
      const c1 = computeCommitment(caseId, validator1.address, sampleResultRoot, salt1);
      await expect(
        quorum.connect(validator1).commit(caseId, c1)
      ).to.emit(quorum, "CommitSubmitted")
        .withArgs(caseId, validator1.address, c1, 1);

      await time.increase(60);
      await quorum.advance(caseId);

      // RevealSubmitted
      await expect(
        quorum.connect(validator1).reveal(caseId, sampleResultRoot, salt1, sampleImageDigest, sampleRulesetHash)
      ).to.emit(quorum, "RevealSubmitted")
        .withArgs(caseId, validator1.address, sampleResultRoot, 1);

      // Reveal a second validator to reach quorum
      const c2 = computeCommitment(caseId, validator2.address, sampleResultRoot, salt2);
      // Wait, validator2 didn't commit before advance in this test, so let's verify NoPriorCommitment reverts
      await expect(
        quorum.connect(validator2).reveal(caseId, sampleResultRoot, salt2, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(quorum, "NoPriorCommitment");
    });
  });
});
