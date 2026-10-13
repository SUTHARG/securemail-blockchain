import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import * as fs from "fs";
import * as path from "path";
import { CaseRegistry, ValidationQuorum, PostureLedger } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("PostureLedger & MerkleVerifier Suite", function () {
  let registry: CaseRegistry;
  let quorum: ValidationQuorum;
  let ledger: PostureLedger;

  let admin: HardhatEthersSigner;
  let analyst: HardhatEthersSigner;
  let analyst2: HardhatEthersSigner;
  let validator1: HardhatEthersSigner;
  let validator2: HardhatEthersSigner;
  let validator3: HardhatEthersSigner;
  let unprivileged: HardhatEthersSigner;

  const samplePcapHash = "0x" + "11".repeat(32);
  const samplePcapHash2 = "0x" + "22".repeat(32);
  const sampleImageDigest = "0x" + "aa".repeat(32);
  const sampleRulesetHash = "0x" + "bb".repeat(32);

  const salt1 = "0x" + "01".repeat(32);
  const salt2 = "0x" + "02".repeat(32);

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  // Load test vectors
  const hashesVectorPath = path.resolve(__dirname, "../../spec/test-vectors/hashes.json");
  const merkleVectorPath = path.resolve(__dirname, "../../spec/test-vectors/merkle_trees.json");
  const hashesVectors = JSON.parse(fs.readFileSync(hashesVectorPath, "utf-8"));
  const merkleTreesVectors = JSON.parse(fs.readFileSync(merkleVectorPath, "utf-8"));

  function computeCommitment(caseId: string, validatorAddress: string, root: string, salt: string): string {
    return ethers.keccak256(
      abiCoder.encode(["bytes32", "address", "bytes32", "bytes32"], [caseId, validatorAddress, root, salt])
    );
  }

  async function openAndFinalizeCase(analystSigner: HardhatEthersSigner, finalRootHex: string, pcapHash: string = samplePcapHash): Promise<string> {
    const tx = await registry.connect(analystSigner).openCase(pcapHash);
    const rc = await tx.wait();
    const caseId = (rc?.logs[0] as any).args[0];

    const root32 = "0x" + finalRootHex.replace(/^0x/, "");
    await quorum.connect(analystSigner).submitClaim(caseId, root32, sampleImageDigest, sampleRulesetHash);

    const c1 = computeCommitment(caseId, validator1.address, root32, salt1);
    const c2 = computeCommitment(caseId, validator2.address, root32, salt2);
    await quorum.connect(validator1).commit(caseId, c1);
    await quorum.connect(validator2).commit(caseId, c2);

    await time.increase(60);
    await quorum.advance(caseId);

    await quorum.connect(validator1).reveal(caseId, root32, salt1, sampleImageDigest, sampleRulesetHash);
    await quorum.connect(validator2).reveal(caseId, root32, salt2, sampleImageDigest, sampleRulesetHash);

    await quorum.finalize(caseId);
    expect(await registry.caseState(caseId)).to.equal(5); // Finalized
    return caseId;
  }

  beforeEach(async function () {
    [
      admin,
      analyst,
      analyst2,
      validator1,
      validator2,
      validator3,
      unprivileged,
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

  describe("A. Cross-Language Test Vectors Verification", function () {
    it("hostScoreLeaf agrees exactly with spec/test-vectors/hashes.json", async function () {
      for (const vector of hashesVectors.host_score_leaf) {
        const hostId = "0x" + vector.hostIdHex;
        const findingsDigest = "0x" + vector.findingsDigestHex;
        const score = vector.score;
        const expected = "0x" + vector.expectedLeafHex;

        const actual = await ledger.hostScoreLeaf(hostId, findingsDigest, score);
        expect(actual.toLowerCase()).to.equal(expected.toLowerCase());
      }
    });

    it("Print exact hex Solidity hash for one host-score leaf for manual inspection", async function () {
      const vector = hashesVectors.host_score_leaf[0];
      const hostId = "0x" + vector.hostIdHex;
      const findingsDigest = "0x" + vector.findingsDigestHex;
      const score = vector.score;

      const actual = await ledger.hostScoreLeaf(hostId, findingsDigest, score);

      console.log("================ HOST-SCORE LEAF SOLIDITY HASH ================");
      console.log("Input hostId:        ", hostId);
      console.log("Input findingsDigest:", findingsDigest);
      console.log("Input score:         ", score);
      console.log("Computed leaf (hex): ", actual);
      console.log("Expected Python hex: ", "0x" + vector.expectedLeafHex);
      console.log("===============================================================");

      expect(actual.toLowerCase()).to.equal(("0x" + vector.expectedLeafHex).toLowerCase());
    });

    it("node interior hashing agrees exactly with spec/test-vectors/hashes.json", async function () {
      for (const vector of hashesVectors.node) {
        const a = "0x" + vector.aHex;
        const b = "0x" + vector.bHex;
        const expected = "0x" + vector.expectedNodeHex;

        const actual1 = await ledger.node(a, b);
        const actual2 = await ledger.node(b, a); // Commutative via sorting
        expect(actual1.toLowerCase()).to.equal(expected.toLowerCase());
        expect(actual2.toLowerCase()).to.equal(expected.toLowerCase());
      }
    });

    it("verify agrees with every leaf proof in 1 to 5 leaf trees from merkle_trees.json", async function () {
      for (const tree of merkleTreesVectors) {
        const root = "0x" + tree.rootHex;

        for (const leafObj of tree.leaves) {
          const leafHex = "0x" + leafObj.leaf;
          const rawProof = tree.proofs[leafObj.leaf] || [];
          const proof = rawProof.map((p: string) => "0x" + p);

          const isValid = await ledger.verify(proof, root, leafHex);
          expect(isValid).to.be.true;

          // Altering leaf invalidates proof
          const fakeLeaf = "0x" + "ee".repeat(32);
          const isFakeValid = await ledger.verify(proof, root, fakeLeaf);
          expect(isFakeValid).to.be.false;

          // Altering root invalidates proof
          const fakeRoot = "0x" + "ff".repeat(32);
          const isFakeRootValid = await ledger.verify(proof, fakeRoot, leafHex);
          expect(isFakeRootValid).to.be.false;
        }
      }
    });
  });

  describe("B. Positive Posture Ledger Recording", function () {
    it("Analyst records posture for finalized case with valid proof; verifies hash-linked chain", async function () {
      // Use Tree with 2 leaves from test vectors (leafCount 2, contains host_score)
      const tree2 = merkleTreesVectors.find((t: any) => t.leafCount === 2);
      const rootHex = tree2.rootHex;
      const hostLeafObj = tree2.leaves.find((l: any) => l.type === "host_score");
      const hostVector = hashesVectors.host_score_leaf[0];

      const hostId = "0x" + hostVector.hostIdHex;
      const findingsDigest = "0x" + hostVector.findingsDigestHex;
      const score = hostVector.score;
      const proof = tree2.proofs[hostLeafObj.leaf].map((p: string) => "0x" + p);

      const caseId = await openAndFinalizeCase(analyst, rootHex);

      const tx = await ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof);
      const rc = await tx.wait();

      expect(await ledger.recordCount(hostId)).to.equal(1);
      expect(await ledger.hasRecorded(caseId, hostId)).to.equal(true);

      const rec = await ledger.latestRecord(hostId);
      expect(rec.hostId).to.equal(hostId);
      expect(rec.caseId).to.equal(caseId);
      expect(rec.score).to.equal(score);
      expect(rec.resultRoot).to.equal("0x" + rootHex);
      expect(rec.prevHash).to.equal(ethers.ZeroHash);

      // Verify exact recordHash formula
      const expectedRecordHash = ethers.keccak256(
        abiCoder.encode(
          ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
          [hostId, caseId, score, "0x" + rootHex, ethers.ZeroHash, rec.timestamp]
        )
      );
      expect(rec.recordHash).to.equal(expectedRecordHash);

      // Verify event
      await expect(tx)
        .to.emit(ledger, "PostureRecorded")
        .withArgs(hostId, caseId, expectedRecordHash, score, ethers.ZeroHash, rec.timestamp);

      // Record second assessment in a new case to verify hash-chain link
      const caseId2 = await openAndFinalizeCase(analyst, rootHex, samplePcapHash2);
      const tx2 = await ledger.connect(analyst).recordPosture(caseId2, hostId, findingsDigest, score, proof);
      await tx2.wait();

      expect(await ledger.recordCount(hostId)).to.equal(2);
      const rec2 = await ledger.latestRecord(hostId);
      expect(rec2.prevHash).to.equal(rec.recordHash); // Linked to record 1

      const expectedRecordHash2 = ethers.keccak256(
        abiCoder.encode(
          ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
          [hostId, caseId2, score, "0x" + rootHex, rec.recordHash, rec2.timestamp]
        )
      );
      expect(rec2.recordHash).to.equal(expectedRecordHash2);

      // Check recordAt index
      const recAt0 = await ledger.recordAt(hostId, 0);
      expect(recAt0.recordHash).to.equal(rec.recordHash);
      const recAt1 = await ledger.recordAt(hostId, 1);
      expect(recAt1.recordHash).to.equal(rec2.recordHash);
    });
  });

  describe("C. Negative Tests & Security Restrictions", function () {
    let caseId: string;
    let rootHex: string;
    let hostId: string;
    let findingsDigest: string;
    let score: number;
    let proof: string[];

    beforeEach(async function () {
      const tree2 = merkleTreesVectors.find((t: any) => t.leafCount === 2);
      rootHex = tree2.rootHex;
      const hostLeafObj = tree2.leaves.find((l: any) => l.type === "host_score");
      const hostVector = hashesVectors.host_score_leaf[0];

      hostId = "0x" + hostVector.hostIdHex;
      findingsDigest = "0x" + hostVector.findingsDigestHex;
      score = hostVector.score;
      proof = tree2.proofs[hostLeafObj.leaf].map((p: string) => "0x" + p);

      caseId = await openAndFinalizeCase(analyst, rootHex);
    });

    it("Wrong score (> 100) reverts with InvalidScore", async function () {
      await expect(
        ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, 101, proof)
      ).to.be.revertedWithCustomError(ledger, "InvalidScore")
        .withArgs(101);
    });

    it("Incorrect score value fails Merkle proof verification", async function () {
      // score is 60, passing 59 produces different leaf
      await expect(
        ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, 59, proof)
      ).to.be.revertedWithCustomError(ledger, "InvalidInclusionProof");
    });

    it("Zero hostId reverts with InvalidHostId", async function () {
      await expect(
        ledger.connect(analyst).recordPosture(caseId, ethers.ZeroHash, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "InvalidHostId");
    });

    it("Wrong hostId fails Merkle proof verification", async function () {
      const wrongHost = "0x" + "55".repeat(32);
      await expect(
        ledger.connect(analyst).recordPosture(caseId, wrongHost, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "InvalidInclusionProof");
    });

    it("Wrong findingsDigest fails Merkle proof verification", async function () {
      const wrongDigest = "0x" + "77".repeat(32);
      await expect(
        ledger.connect(analyst).recordPosture(caseId, hostId, wrongDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "InvalidInclusionProof");
    });

    it("Proof of another leaf reverts with InvalidInclusionProof", async function () {
      // Tree with 3 leaves has different proof
      const tree3 = merkleTreesVectors.find((t: any) => t.leafCount === 3);
      const proofOtherLeaf = tree3.proofs[tree3.leaves[0].leaf].map((p: string) => "0x" + p);

      await expect(
        ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proofOtherLeaf)
      ).to.be.revertedWithCustomError(ledger, "InvalidInclusionProof");
    });

    it("Duplicate record for the same (caseId, hostId) reverts with PostureAlreadyRecorded", async function () {
      await ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof);

      await expect(
        ledger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "PostureAlreadyRecorded")
        .withArgs(caseId, hostId);
    });

    it("Case not finalized reverts with CaseNotFinalized", async function () {
      const openTx = await registry.connect(analyst).openCase(samplePcapHash2);
      const rc = await openTx.wait();
      const openCaseId = (rc?.logs[0] as any).args[0];

      // In Opened state
      await expect(
        ledger.connect(analyst).recordPosture(openCaseId, hostId, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "CaseNotFinalized")
        .withArgs(openCaseId, 1);
    });

    it("Non-analyst caller reverts with AccessControlUnauthorizedAccount", async function () {
      const ANALYST_ROLE = await registry.ANALYST_ROLE();
      await expect(
        ledger.connect(unprivileged).recordPosture(caseId, hostId, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "AccessControlUnauthorizedAccount")
        .withArgs(unprivileged.address, ANALYST_ROLE);
    });

    it("Different analyst caller reverts with NotCaseAnalyst", async function () {
      await expect(
        ledger.connect(analyst2).recordPosture(caseId, hostId, findingsDigest, score, proof)
      ).to.be.revertedWithCustomError(ledger, "NotCaseAnalyst")
        .withArgs(caseId, analyst2.address);
    });

    it("Getters revert cleanly on empty host or out of bounds index", async function () {
      const unusedHost = "0x" + "99".repeat(32);
      await expect(
        ledger.latestRecord(unusedHost)
      ).to.be.revertedWithCustomError(ledger, "NoRecordsForHost")
        .withArgs(unusedHost);

      await expect(
        ledger.recordAt(unusedHost, 0)
      ).to.be.revertedWithCustomError(ledger, "IndexOutOfBounds")
        .withArgs(unusedHost, 0);
    });
  });
});
