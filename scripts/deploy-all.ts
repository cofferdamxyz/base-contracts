import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';

const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

async function main() {
  console.log('=== Cofferdam Base Contracts — Full Deployment ===\n');

  // 1. Auth framework
  console.log('--- Auth framework ---');
  const [deployer] = await ethers.getSigners();

  const PasskeyAuthority = await ethers.getContractFactory('PasskeyAuthority');
  const passkeyAuth = await PasskeyAuthority.deploy();
  await passkeyAuth.waitForDeployment();
  console.log('PasskeyAuthority:', await passkeyAuth.getAddress());

  const WebAuthnPasskeyAuthority = await ethers.getContractFactory('WebAuthnPasskeyAuthority');
  const webAuthnAuth = await WebAuthnPasskeyAuthority.deploy();
  await webAuthnAuth.waitForDeployment();
  console.log('WebAuthnPasskeyAuthority:', await webAuthnAuth.getAddress());

  const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
  const sessionUntrusted = await SessionKeyAuthority.deploy(1);
  await sessionUntrusted.waitForDeployment();
  const sessionManaged = await SessionKeyAuthority.deploy(2);
  await sessionManaged.waitForDeployment();
  console.log('SessionKeyAuthority (LowUntrusted):', await sessionUntrusted.getAddress());
  console.log('SessionKeyAuthority (LowManaged):', await sessionManaged.getAddress());

  const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
  const factory = await Factory.deploy(ENTRYPOINT_V07);
  await factory.waitForDeployment();
  console.log('CofferdamAccountFactory4337:', await factory.getAddress());

  const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
  const paymaster = await Paymaster.deploy(ENTRYPOINT_V07);
  await paymaster.waitForDeployment();
  console.log('CofferdamPaymaster (stub):', await paymaster.getAddress());

  // 2. Self.xyz contracts
  console.log('\n--- Self.xyz contracts ---');
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
    BigInt(scope)
  );
  await nullifierReg.waitForDeployment();
  console.log('NullifierRegistry:', await nullifierReg.getAddress());

  // 3. Summary
  console.log('\n=== Deployment Summary ===');
  console.log('EntryPoint v0.7:', ENTRYPOINT_V07);
  console.log('PasskeyAuthority:', await passkeyAuth.getAddress());
  console.log('WebAuthnPasskeyAuthority:', await webAuthnAuth.getAddress());
  console.log('SessionKeyAuthority (untrusted):', await sessionUntrusted.getAddress());
  console.log('SessionKeyAuthority (managed):', await sessionManaged.getAddress());
  console.log('AccountFactory:', await factory.getAddress());
  console.log('Paymaster (stub):', await paymaster.getAddress());
  console.log('SelfAttesterRegistry:', await attesterReg.getAddress());
  if (!process.env.SELF_VERIFIER_ADDRESS) {
    console.log('MockGroth16Verifier (dev):', verifierAddress);
  }
  console.log('NullifierRegistry:', await nullifierReg.getAddress());

  // 4. Persist addresses to deployments/<network>.json so the SDK + demo can
  //    read them (deploy-escrow.ts merges into the same file).
  const registryPath = writeDeployments(network.name, {
    EntryPoint: ENTRYPOINT_V07,
    PasskeyAuthority: await passkeyAuth.getAddress(),
    WebAuthnPasskeyAuthority: await webAuthnAuth.getAddress(),
    SessionKeyAuthorityLowUntrusted: await sessionUntrusted.getAddress(),
    SessionKeyAuthorityLowManaged: await sessionManaged.getAddress(),
    CofferdamAccountFactory4337: await factory.getAddress(),
    CofferdamPaymaster: await paymaster.getAddress(),
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
