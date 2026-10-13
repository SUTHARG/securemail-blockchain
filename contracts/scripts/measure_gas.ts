import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import * as fs from "fs";
import * as path from "path";

async function measureQuorum(nValidators: number, kThreshold: number) {
  const signers = await ethers.getSigners();
  const admin = signers[0];
  const analyst = signers[1];
  const validators = signers.slice(2, 2 + nValidators);

  // Deploy Roles & CaseRegistry
  const CaseRegistryFactory = await ethers.getContractFactory("CaseRegistry");
  const caseRegistry = await CaseRegistryFactory.deploy();
  await caseRegistry.waitForDeployment();
  const caseRegistryAddress = await caseRegistry.getAddress();

  // Deploy ValidationQuorum (60s commit, 60s reveal)
  const ValidationQuorumFactory = await ethers.getContractFactory("ValidationQuorum");
  const quorum = await ValidationQuorumFactory.deploy(caseRegistryAddress, 60, 60);
  await quorum.waitForDeployment();
  const quorumAddress = await quorum.getAddress();

  // Deploy PostureLedger
  const PostureLedgerFactory = await ethers.getContractFactory("PostureLedger");
  const postureLedger = await PostureLedgerFactory.deploy(caseRegistryAddress);
  await postureLedger.waitForDeployment();
  const postureLedgerAddress = await postureLedger.getAddress();

  // Grant roles
  const quorumRole = await caseRegistry.QUORUM_ROLE();
  await (await caseRegistry.grantRole(quorumRole, quorumAddress)).wait();

  const analystRole = await caseRegistry.ANALYST_ROLE();
  await (await caseRegistry.grantRole(analystRole, analyst.address)).wait();

  // Register engine
  const sampleImageDigest = "0x" + "aa".repeat(32);
  const sampleRulesetHash = "0x" + "bb".repeat(32);
  await (await caseRegistry.registerEngine(sampleImageDigest, sampleRulesetHash)).wait();

  // Add validators
  for (const v of validators) {
    await (await caseRegistry.addValidator(v.address)).wait();
  }

  const measurements: Record<string, number> = {};

  // 1. openCase
  const samplePcapHash = "0x" + "11".repeat(32);
  const openTx = await caseRegistry.connect(analyst).openCase(samplePcapHash);
  const openRc = await openTx.wait();
  measurements["openCase"] = Number(openRc?.gasUsed ?? 0n);
  const caseId = (openRc?.logs[0] as any).args[0];

  // Vector for 2 leaves (finding + host_score)
  const sampleResultRoot = "0x471dfe9a8859f026b21cad332c274569c729c7aea38170741ae67373e9b04f3b";
  const hostId = "0xedefad951ebaacc3c2431e157810aca48e7427e2a57e326dd9a2ad7672f00520";
  const findingsDigest = "0x31876ca07bfb3f586318f609a5e848cb266aaf1e66b4aef81cd44d2bc5b3d46d";
  const score = 60;
  const proof = ["0xf5e83e6f85e88bf6b691e42538f7f025e168b95ee8a84326c30e06cefeb6c01a"];

  // 2. submitClaim
  const claimTx = await quorum.connect(analyst).submitClaim(caseId, sampleResultRoot, sampleImageDigest, sampleRulesetHash);
  const claimRc = await claimTx.wait();
  measurements["submitClaim"] = Number(claimRc?.gasUsed ?? 0n);

  // Compute commitments
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const salts: string[] = [];
  const commitments: string[] = [];
  for (let i = 0; i < nValidators; i++) {
    const salt = "0x" + (i + 1).toString(16).padStart(2, "0").repeat(32);
    salts.push(salt);
    const c = ethers.keccak256(
      abiCoder.encode(["bytes32", "address", "bytes32", "bytes32"], [caseId, validators[i].address, sampleResultRoot, salt])
    );
    commitments.push(c);
  }

  // 3. commit (measure validator 0)
  const commit0Tx = await quorum.connect(validators[0]).commit(caseId, commitments[0]);
  const commit0Rc = await commit0Tx.wait();
  measurements["commit"] = Number(commit0Rc?.gasUsed ?? 0n);

  // Commit remaining validators up to kThreshold
  for (let i = 1; i < kThreshold; i++) {
    await (await quorum.connect(validators[i]).commit(caseId, commitments[i])).wait();
  }

  // Advance time to reveal window
  await time.increase(61);
  await (await quorum.advance(caseId)).wait();

  // 4. reveal (measure validator 0)
  const reveal0Tx = await quorum.connect(validators[0]).reveal(caseId, sampleResultRoot, salts[0], sampleImageDigest, sampleRulesetHash);
  const reveal0Rc = await reveal0Tx.wait();
  measurements["reveal"] = Number(reveal0Rc?.gasUsed ?? 0n);

  // Reveal remaining validators up to kThreshold
  for (let i = 1; i < kThreshold; i++) {
    await (await quorum.connect(validators[i]).reveal(caseId, sampleResultRoot, salts[i], sampleImageDigest, sampleRulesetHash)).wait();
  }

  // Advance past reveal deadline
  await time.increase(61);

  // 5. finalize
  const finalizeTx = await quorum.finalize(caseId);
  const finalizeRc = await finalizeTx.wait();
  measurements["finalize"] = Number(finalizeRc?.gasUsed ?? 0n);

  // 6. recordPosture
  const postureTx = await postureLedger.connect(analyst).recordPosture(caseId, hostId, findingsDigest, score, proof);
  const postureRc = await postureTx.wait();
  measurements["recordPosture"] = Number(postureRc?.gasUsed ?? 0n);

  // 7. anchorReport
  const sampleReportHash = "0x" + "33".repeat(32);
  const anchorTx = await caseRegistry.connect(analyst).anchorReport(caseId, sampleReportHash);
  const anchorRc = await anchorTx.wait();
  measurements["anchorReport"] = Number(anchorRc?.gasUsed ?? 0n);

  return measurements;
}

async function main() {
  console.log("Measuring gas for N=3 (k=2)...");
  const gasN3 = await measureQuorum(3, 2);

  console.log("Measuring gas for N=5 (k=3)...");
  const gasN5 = await measureQuorum(5, 3);

  const results = {
    N3: gasN3,
    N5: gasN5,
  };

  const outPath = path.resolve(__dirname, "../../eval/results/gas_measurements_raw.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2), "utf-8");
  console.log("Wrote gas measurements to:", outPath);
  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
