import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);

  // 1. Deploy Roles
  const RolesFactory = await ethers.getContractFactory("Roles");
  const roles = await RolesFactory.deploy();
  await roles.waitForDeployment();
  const rolesAddress = await roles.getAddress();
  console.log("Roles deployed to:", rolesAddress);

  // 2. Deploy CaseRegistry
  const CaseRegistryFactory = await ethers.getContractFactory("CaseRegistry");
  const caseRegistry = await CaseRegistryFactory.deploy();
  await caseRegistry.waitForDeployment();
  const caseRegistryAddress = await caseRegistry.getAddress();
  console.log("CaseRegistry deployed to:", caseRegistryAddress);

  // 3. Deploy ValidationQuorum (default 60s commit window, 60s reveal window)
  const ValidationQuorumFactory = await ethers.getContractFactory("ValidationQuorum");
  const quorum = await ValidationQuorumFactory.deploy(caseRegistryAddress, 60, 60);
  await quorum.waitForDeployment();
  const quorumAddress = await quorum.getAddress();
  console.log("ValidationQuorum deployed to:", quorumAddress);

  // 4. Deploy PostureLedger
  const PostureLedgerFactory = await ethers.getContractFactory("PostureLedger");
  const postureLedger = await PostureLedgerFactory.deploy(caseRegistryAddress);
  await postureLedger.waitForDeployment();
  const postureLedgerAddress = await postureLedger.getAddress();
  console.log("PostureLedger deployed to:", postureLedgerAddress);

  // 5. Grant QUORUM_ROLE to the quorum contract on CaseRegistry and standalone Roles
  const quorumRole = await caseRegistry.QUORUM_ROLE();
  const grantTx = await caseRegistry.grantRole(quorumRole, quorumAddress);
  await grantTx.wait();
  await (await roles.grantRole(await roles.QUORUM_ROLE(), quorumAddress)).wait();
  console.log("Granted QUORUM_ROLE to ValidationQuorum on CaseRegistry and Roles");

  // Grant ANALYST_ROLE to deployer so analyst operations work out of the box
  const analystRole = await caseRegistry.ANALYST_ROLE();
  const grantAnalystTx = await caseRegistry.grantRole(analystRole, deployer.address);
  await grantAnalystTx.wait();
  await (await roles.grantRole(await roles.ANALYST_ROLE(), deployer.address)).wait();
  console.log("Granted ANALYST_ROLE to deployer on CaseRegistry and Roles");

  // 6. Write deployment file
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentData = {
    network: "localhost",
    chainId: 31337,
    deployer: deployer.address,
    contracts: {
      Roles: {
        address: rolesAddress,
        abiPath: "artifacts/contracts/Roles.sol/Roles.json",
      },
      CaseRegistry: {
        address: caseRegistryAddress,
        abiPath: "artifacts/contracts/CaseRegistry.sol/CaseRegistry.json",
      },
      ValidationQuorum: {
        address: quorumAddress,
        abiPath: "artifacts/contracts/ValidationQuorum.sol/ValidationQuorum.json",
      },
      PostureLedger: {
        address: postureLedgerAddress,
        abiPath: "artifacts/contracts/PostureLedger.sol/PostureLedger.json",
      },
    },
  };

  const deploymentFile = path.join(deploymentsDir, "local.json");
  fs.writeFileSync(deploymentFile, JSON.stringify(deploymentData, null, 2));
  console.log("Wrote deployment file to:", deploymentFile);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
