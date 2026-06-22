import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';

// ERC-4337 EntryPoint v0.7 — preinstalled on Base
const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

// Redeploys ONLY the CofferdamPaymaster (the v0.7 postOp signature fix).
// Factory + authority modules are unchanged and stay at their existing addresses.
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying CofferdamPaymaster from:', deployer.address);

  const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
  const paymaster = await Paymaster.deploy(ENTRYPOINT_V07);
  await paymaster.waitForDeployment();
  const addr = await paymaster.getAddress();
  console.log('CofferdamPaymaster:', addr);

  // Merge the new paymaster address into deployments/<network>.json, leaving
  // every other entry untouched.
  const registryPath = writeDeployments(network.name, { CofferdamPaymaster: addr });
  console.log('Wrote', registryPath);
  console.log('\nVITE_NATIVE_TESTNET_PAYMASTER_ADDRESS=' + addr);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
