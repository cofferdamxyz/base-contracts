import { ethers } from 'hardhat';

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying Self.xyz contracts from:', deployer.address);

  // 1. Deploy SelfAttesterRegistry (no initial attesters — add via owner later)
  const SelfAttesterRegistry = await ethers.getContractFactory('SelfAttesterRegistry');
  const attesterRegistry = await SelfAttesterRegistry.deploy(deployer.address, []);
  await attesterRegistry.waitForDeployment();
  console.log('SelfAttesterRegistry:', await attesterRegistry.getAddress());

  // 2. Deploy NullifierRegistry
  //    The verifier address and scope must be set per-environment.
  //    On Base Sepolia, the Self.xyz Groth16 verifier needs to be deployed
  //    (it compiles on standard EVM — it was originally an EVM contract).
  //    For now we use a zero address placeholder; replace before staging.
  const verifierAddress = process.env.SELF_VERIFIER_ADDRESS || ethers.ZeroAddress;
  const scope = process.env.SELF_SCOPE || '0';

  if (verifierAddress === ethers.ZeroAddress) {
    console.warn('WARNING: SELF_VERIFIER_ADDRESS not set — NullifierRegistry will not verify proofs.');
    console.warn('Deploy the Verifier_vc_and_disclose contract first, then re-deploy NullifierRegistry.');
  }

  const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
  const nullifierRegistry = await NullifierRegistry.deploy(
    verifierAddress,
    await attesterRegistry.getAddress(),
    BigInt(scope)
  );
  await nullifierRegistry.waitForDeployment();
  console.log('NullifierRegistry:', await nullifierRegistry.getAddress());

  console.log('\n--- Self contracts deployed ---');
  console.log('Next: add trusted attester addresses via SelfAttesterRegistry.addAttester()');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
