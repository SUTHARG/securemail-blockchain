import { expect } from "chai";
import { ethers } from "hardhat";
import { CaseRegistry } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("CaseRegistry & Roles Suite", function () {
  let registry: CaseRegistry;
  let admin: HardhatEthersSigner;
  let analyst: HardhatEthersSigner;
  let analyst2: HardhatEthersSigner;
  let validator1: HardhatEthersSigner;
  let validator2: HardhatEthersSigner;
  let validator3: HardhatEthersSigner;
  let quorumContract: HardhatEthersSigner;
  let unprivileged: HardhatEthersSigner;

  const samplePcapHash = "0x" + "11".repeat(32);
  const samplePcapHash2 = "0x" + "22".repeat(32);
  const sampleImageDigest = "0x" + "aa".repeat(32);
  const sampleRulesetHash = "0x" + "bb".repeat(32);
  const sampleReportHash = "0x" + "cc".repeat(32);
  const sampleResultRoot = "0x" + "dd".repeat(32);

  // Gas measurement storage
  const gasMeasurements: Record<string, bigint> = {};

  beforeEach(async function () {
    [
      admin,
      analyst,
      analyst2,
      validator1,
      validator2,
      validator3,
      quorumContract,
      unprivileged,
    ] = await ethers.getSigners();

    const CaseRegistryFactory = await ethers.getContractFactory("CaseRegistry");
    registry = await CaseRegistryFactory.deploy();
    await registry.waitForDeployment();

    // Grant roles for testing
    const ANALYST_ROLE = await registry.ANALYST_ROLE();
    const QUORUM_ROLE = await registry.QUORUM_ROLE();

    await registry.grantRole(ANALYST_ROLE, analyst.address);
    await registry.grantRole(ANALYST_ROLE, analyst2.address);
    await registry.grantRole(QUORUM_ROLE, quorumContract.address);
  });

  describe("A. Roles Tests", function () {
    it("Deployer receives ADMIN_ROLE and DEFAULT_ADMIN_ROLE", async function () {
      const ADMIN_ROLE = await registry.ADMIN_ROLE();
      const DEFAULT_ADMIN_ROLE = await registry.DEFAULT_ADMIN_ROLE();

      expect(await registry.hasRole(ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(ADMIN_ROLE, unprivileged.address)).to.be.false;
    });

    it("Non-admin cannot register an engine", async function () {
      const ADMIN_ROLE = await registry.ADMIN_ROLE();
      await expect(
        registry.connect(unprivileged).registerEngine(sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ADMIN_ROLE);
    });

    it("Non-admin cannot add or remove validators", async function () {
      const ADMIN_ROLE = await registry.ADMIN_ROLE();
      await expect(
        registry.connect(unprivileged).addValidator(validator1.address)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ADMIN_ROLE);

      await registry.addValidator(validator1.address);
      await expect(
        registry.connect(unprivileged).removeValidator(validator1.address)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ADMIN_ROLE);
    });

    it("User without ANALYST_ROLE cannot open a case", async function () {
      const ANALYST_ROLE = await registry.ANALYST_ROLE();
      await expect(
        registry.connect(unprivileged).openCase(samplePcapHash)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ANALYST_ROLE);
    });

    it("Only QUORUM_ROLE can invoke quorum-restricted operations", async function () {
      const QUORUM_ROLE = await registry.QUORUM_ROLE();
      const tx = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt = await tx.wait();
      const caseId = (receipt?.logs[0] as any).args[0];

      // Non-quorum caller cannot setClaim
      await expect(
        registry.connect(analyst).setClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(analyst.address, QUORUM_ROLE);

      // Non-quorum caller cannot setState
      await expect(
        registry.connect(analyst).setState(caseId, 5) // Finalized
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(analyst.address, QUORUM_ROLE);

      // Non-quorum caller cannot finalizeCase
      await expect(
        registry.connect(analyst).finalizeCase(caseId, sampleResultRoot, false)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(analyst.address, QUORUM_ROLE);

      // Non-quorum caller cannot incrementRound
      await expect(
        registry.connect(analyst).incrementRound(caseId)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(analyst.address, QUORUM_ROLE);
    });
  });

  describe("B. Case Management Tests", function () {
    it("Authorized analyst can open a case with exact ID formula and events", async function () {
      const currentCounter = await registry.caseCounter();
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const expectedCaseId = ethers.keccak256(
        abiCoder.encode(["bytes32", "address", "uint256"], [samplePcapHash, analyst.address, currentCounter])
      );

      const tx = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt = await tx.wait();
      gasMeasurements["openCase"] = receipt?.gasUsed ?? 0n;

      await expect(tx)
        .to.emit(registry, "CaseOpened")
        .withArgs(expectedCaseId, analyst.address, samplePcapHash, (val: any) => val > 0);

      const c = await registry.getCase(expectedCaseId);
      expect(c.analyst).to.equal(analyst.address);
      expect(c.pcapHash).to.equal(samplePcapHash);
      expect(c.state).to.equal(1); // State.Opened
      expect(c.round).to.equal(1);
      expect(c.openedAt).to.be.greaterThan(0);

      // Counter advanced
      expect(await registry.caseCounter()).to.equal(currentCounter + 1n);
    });

    it("Registering the same PCAP twice produces distinct case IDs", async function () {
      const tx1 = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt1 = await tx1.wait();
      const caseId1 = (receipt1?.logs[0] as any).args[0];

      const tx2 = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt2 = await tx2.wait();
      const caseId2 = (receipt2?.logs[0] as any).args[0];

      expect(caseId1).to.not.equal(caseId2);
      expect(await registry.caseExists(caseId1)).to.be.true;
      expect(await registry.caseExists(caseId2)).to.be.true;
    });

    it("Reject opening a case with zero PCAP hash", async function () {
      await expect(
        registry.connect(analyst).openCase(ethers.ZeroHash)
      ).to.be.revertedWithCustomError(registry, "InvalidPcapHash");
    });

    it("Querying nonexistent case reverts with CaseNotFound", async function () {
      const dummyId = "0x" + "ee".repeat(32);
      await expect(registry.getCase(dummyId)).to.be.revertedWithCustomError(
        registry,
        "CaseNotFound"
      ).withArgs(dummyId);
    });
  });

  describe("C. Report Anchoring Tests", function () {
    let caseId: string;

    beforeEach(async function () {
      const tx = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt = await tx.wait();
      caseId = (receipt?.logs[0] as any).args[0];
    });

    it("Anchoring before finalization fails with CaseNotFinalized", async function () {
      await expect(
        registry.connect(analyst).anchorReport(caseId, sampleReportHash)
      ).to.be.revertedWithCustomError(registry, "CaseNotFinalized")
        .withArgs(caseId, 1); // State.Opened
    });

    it("Anchoring by a non-owner analyst fails with NotCaseAnalyst", async function () {
      // Transition to finalized via quorum
      await registry.connect(quorumContract).finalizeCase(caseId, sampleResultRoot, false);

      await expect(
        registry.connect(analyst2).anchorReport(caseId, sampleReportHash)
      ).to.be.revertedWithCustomError(registry, "NotCaseAnalyst")
        .withArgs(caseId, analyst2.address);
    });

    it("Anchoring a finalized case succeeds, records reportHash, and emits event", async function () {
      await registry.connect(quorumContract).finalizeCase(caseId, sampleResultRoot, false);

      const tx = await registry.connect(analyst).anchorReport(caseId, sampleReportHash);
      const receipt = await tx.wait();
      gasMeasurements["anchorReport"] = receipt?.gasUsed ?? 0n;

      await expect(tx)
        .to.emit(registry, "ReportAnchored")
        .withArgs(caseId, sampleReportHash, analyst.address, (val: any) => val > 0);

      expect(await registry.reportHash(caseId)).to.equal(sampleReportHash);
    });

    it("Anchoring the same report twice fails with ReportAlreadyAnchored", async function () {
      await registry.connect(quorumContract).finalizeCase(caseId, sampleResultRoot, false);
      await registry.connect(analyst).anchorReport(caseId, sampleReportHash);

      await expect(
        registry.connect(analyst).anchorReport(caseId, sampleReportHash)
      ).to.be.revertedWithCustomError(registry, "ReportAlreadyAnchored")
        .withArgs(caseId);
    });

    it("Anchoring with zero report hash reverts with InvalidReportHash", async function () {
      await registry.connect(quorumContract).finalizeCase(caseId, sampleResultRoot, false);

      await expect(
        registry.connect(analyst).anchorReport(caseId, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(registry, "InvalidReportHash");
    });
  });

  describe("D. Engine Pinning Tests", function () {
    it("Admin can register an engine and activeEngine() returns the pinned pair", async function () {
      const tx = await registry.connect(admin).registerEngine(sampleImageDigest, sampleRulesetHash);
      const receipt = await tx.wait();
      gasMeasurements["registerEngine"] = receipt?.gasUsed ?? 0n;

      await expect(tx)
        .to.emit(registry, "EngineRegistered")
        .withArgs(sampleImageDigest, sampleRulesetHash, (val: any) => val > 0);

      const [digest, ruleset] = await registry.activeEngine();
      expect(digest).to.equal(sampleImageDigest);
      expect(ruleset).to.equal(sampleRulesetHash);
    });

    it("Rejects registration with zero hash", async function () {
      await expect(
        registry.connect(admin).registerEngine(ethers.ZeroHash, sampleRulesetHash)
      ).to.be.revertedWithCustomError(registry, "InvalidEngineHash");

      await expect(
        registry.connect(admin).registerEngine(sampleImageDigest, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(registry, "InvalidEngineHash");
    });
  });

  describe("E. Validator Management Tests", function () {
    it("Admin can add validator, grants VALIDATOR_ROLE, and updates array", async function () {
      const VALIDATOR_ROLE = await registry.VALIDATOR_ROLE();

      const tx = await registry.connect(admin).addValidator(validator1.address);
      const receipt = await tx.wait();
      gasMeasurements["addValidator"] = receipt?.gasUsed ?? 0n;

      await expect(tx)
        .to.emit(registry, "ValidatorAdded")
        .withArgs(validator1.address, (val: any) => val > 0);

      expect(await registry.hasRole(VALIDATOR_ROLE, validator1.address)).to.be.true;
      expect(await registry.isValidator(validator1.address)).to.be.true;
      expect(await registry.validatorCount()).to.equal(1);
      expect(await registry.validators()).to.deep.equal([validator1.address]);
    });

    it("Rejects zero address or duplicate validator addition", async function () {
      await expect(
        registry.connect(admin).addValidator(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");

      await registry.connect(admin).addValidator(validator1.address);
      await expect(
        registry.connect(admin).addValidator(validator1.address)
      ).to.be.revertedWithCustomError(registry, "ValidatorAlreadyRegistered")
        .withArgs(validator1.address);
    });

    it("Removing a validator updates the list correctly and revokes VALIDATOR_ROLE", async function () {
      const VALIDATOR_ROLE = await registry.VALIDATOR_ROLE();

      await registry.connect(admin).addValidator(validator1.address);
      await registry.connect(admin).addValidator(validator2.address);
      await registry.connect(admin).addValidator(validator3.address);

      // Remove middle validator (validator2)
      const tx = await registry.connect(admin).removeValidator(validator2.address);
      const receipt = await tx.wait();
      gasMeasurements["removeValidator"] = receipt?.gasUsed ?? 0n;

      await expect(tx)
        .to.emit(registry, "ValidatorRemoved")
        .withArgs(validator2.address, (val: any) => val > 0);

      expect(await registry.hasRole(VALIDATOR_ROLE, validator2.address)).to.be.false;
      expect(await registry.isValidator(validator2.address)).to.be.false;
      expect(await registry.validatorCount()).to.equal(2);

      const list = Array.from(await registry.validators());
      expect(list).to.have.members([validator1.address, validator3.address]);
      expect(list).to.not.include(validator2.address);

      // Removing already removed validator reverts
      await expect(
        registry.connect(admin).removeValidator(validator2.address)
      ).to.be.revertedWithCustomError(registry, "ValidatorNotRegistered")
        .withArgs(validator2.address);
    });
  });

  describe("F. Quorum-Driven State Transitions", function () {
    let caseId: string;

    beforeEach(async function () {
      const tx = await registry.connect(analyst).openCase(samplePcapHash);
      const receipt = await tx.wait();
      caseId = (receipt?.logs[0] as any).args[0];
    });

    it("Quorum role can set claim and transition to Committing", async function () {
      await registry.connect(quorumContract).setClaim(
        caseId,
        sampleResultRoot,
        sampleImageDigest,
        sampleRulesetHash
      );

      const c = await registry.getCase(caseId);
      expect(c.state).to.equal(3); // State.Committing
      expect(c.claimedRoot).to.equal(sampleResultRoot);
      expect(c.engineHash).to.equal(sampleImageDigest);
      expect(c.rulesetHash).to.equal(sampleRulesetHash);
    });

    it("Quorum role can increment round", async function () {
      await registry.connect(quorumContract).incrementRound(caseId);
      const c = await registry.getCase(caseId);
      expect(c.round).to.equal(2);
      expect(c.state).to.equal(3); // State.Committing
    });

    it("Quorum role can finalize with contradiction flag", async function () {
      const finalAltRoot = "0x" + "99".repeat(32);
      await registry.connect(quorumContract).finalizeCase(caseId, finalAltRoot, true);

      const c = await registry.getCase(caseId);
      expect(c.state).to.equal(5); // State.Finalized
      expect(c.finalRoot).to.equal(finalAltRoot);
      expect(c.contradicted).to.be.true;
    });
  });

  after(function () {
    console.log("\n=================== GAS MEASUREMENTS REPORT ===================");
    console.log("| Function           | Gas Used (Units)                        |");
    console.log("|--------------------|-----------------------------------------|");
    for (const [fnName, gasUsed] of Object.entries(gasMeasurements)) {
      console.log(`| ${fnName.padEnd(18)} | ${gasUsed.toString().padEnd(39)} |`);
    }
    console.log("===============================================================\n");
  });
});
