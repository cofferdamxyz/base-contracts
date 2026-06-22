import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';

// ERC-4337 EntryPoint v0.7 — preinstalled on Base
const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying auth framework from:', deployer.address);

  // 1. Deploy authority modules
  const PasskeyAuthority = await ethers.getContractFactory('PasskeyAuthority');
  const passkeyAuthority = await PasskeyAuthority.deploy();
  await passkeyAuthority.waitForDeployment();
  console.log('PasskeyAuthority:', await passkeyAuthority.getAddress());

  const WebAuthnPasskeyAuthority = await ethers.getContractFactory('WebAuthnPasskeyAuthority');
  const webAuthnPasskeyAuthority = await WebAuthnPasskeyAuthority.deploy();
  await webAuthnPasskeyAuthority.waitForDeployment();
  console.log('WebAuthnPasskeyAuthority:', await webAuthnPasskeyAuthority.getAddress());

  // Deploy SessionKeyAuthority at both tiers
  const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
  const sessionUntrusted = await SessionKeyAuthority.deploy(1); // Tier.LowUntrusted
  await sessionUntrusted.waitForDeployment();
  console.log('SessionKeyAuthority (LowUntrusted):', await sessionUntrusted.getAddress());

  const sessionManaged = await SessionKeyAuthority.deploy(2); // Tier.LowManaged
  await sessionManaged.waitForDeployment();
  console.log('SessionKeyAuthority (LowManaged):', await sessionManaged.getAddress());

  // 2. Deploy account factory
  const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
  const factory = await Factory.deploy(ENTRYPOINT_V07);
  await factory.waitForDeployment();
  console.log('CofferdamAccountFactory4337:', await factory.getAddress());

  // 3. Deploy stub paymaster
  const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
  const paymaster = await Paymaster.deploy(ENTRYPOINT_V07);
  await paymaster.waitForDeployment();
  console.log('CofferdamPaymaster (stub):', await paymaster.getAddress());

  // Persist to deployments/<network>.json (merge with existing entries).
  const registryPath = writeDeployments(network.name, {
    EntryPoint: ENTRYPOINT_V07,
    PasskeyAuthority: await passkeyAuthority.getAddress(),
    WebAuthnPasskeyAuthority: await webAuthnPasskeyAuthority.getAddress(),
    SessionKeyAuthorityLowUntrusted: await sessionUntrusted.getAddress(),
    SessionKeyAuthorityLowManaged: await sessionManaged.getAddress(),
    CofferdamAccountFactory4337: await factory.getAddress(),
    CofferdamPaymaster: await paymaster.getAddress(),
  });

  console.log('\n--- Deployment complete ---');
  console.log('EntryPoint:', ENTRYPOINT_V07);
  console.log('Wrote', registryPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
