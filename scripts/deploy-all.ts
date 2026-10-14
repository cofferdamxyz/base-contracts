import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';
import { COFFERDAM_SELF_DEST_CHAIN_ID } from './lib/selfUserContext';
import { deployAccountLayer } from './lib/accountLayer';

async function main() {
  console.log('=== Cofferdam Base Contracts — Full Deployment ===\n');

  // 1. Self.xyz contracts (the account factory pins the nullifier registry)
  console.log('--- Self.xyz contracts ---');
  const [deployer] = await ethers.getSigners();
  const SelfAttesterRegistry = await ethers.getContractFactory('SelfAttesterRegistry');
  const attesterReg = await SelfAttesterRegistry.deploy(deployer.address, []);
  await attesterReg.waitForDeployment();
  console.log('SelfAttesterRegistry:', await attesterReg.getAddress());

  // For local/dev: deploy a mock verifier that always returns true.
  // In production, set SELF_VERIFIER_ADDRESS to the real Groth16 verifier.
  let verifierAddress = process.env.SELF_VERIFIER_ADDRESS;
  if (!verifierAddress || verifierAddress === ethers.ZeroAddress) {
    const MockVerifier = await ethers.getContractFactory('MockGroth16Verifier');
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();
    verifierAddress = await mockVerifier.getAddress();
    console.log('MockGroth16Verifier (dev):', verifierAddress);
  }
  const scope = process.env.SELF_SCOPE || '0';
  const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
  const nullifierReg = await NullifierRegistry.deploy(
    verifierAddress,
    await attesterReg.getAddress(),
    BigInt(scope),
    COFFERDAM_SELF_DEST_CHAIN_ID,
    0n // rebindDelay: immediate on local chains (decision 0022)
  );
  await nullifierReg.waitForDeployment();
  console.log('NullifierRegistry:', await nullifierReg.getAddress());

  // 2. Account layer
  console.log('\n--- Account layer ---');
  const accountLayer = await deployAccountLayer(await nullifierReg.getAddress());

  // 3. Summary
  console.log('\n=== Deployment Summary ===');
  for (const [name, address] of Object.entries(accountLayer)) console.log(`${name}:`, address);
  console.log('SelfAttesterRegistry:', await attesterReg.getAddress());
  if (!process.env.SELF_VERIFIER_ADDRESS) {
    console.log('MockGroth16Verifier (dev):', verifierAddress);
  }
  console.log('NullifierRegistry:', await nullifierReg.getAddress());

  // 4. Persist addresses to deployments/<network>.json so the SDK + demo can
  //    read them (deploy-escrow.ts merges into the same file).
  const registryPath = writeDeployments(network.name, {
    ...accountLayer,
    SelfAttesterRegistry: await attesterReg.getAddress(),
    ...(process.env.SELF_VERIFIER_ADDRESS ? {} : { MockGroth16Verifier: verifierAddress }),
    NullifierRegistry: await nullifierReg.getAddress(),
  });
  console.log('\nWrote', registryPath);
  console.log('VITE_TESTNET_RECEIVER_ADDRESS =', await nullifierReg.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
