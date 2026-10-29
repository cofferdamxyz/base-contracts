import * as fs from 'fs';
import * as path from 'path';
import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';
import { accountCodeFingerprint, paymasterRelayer, refuseMainnetPaymaster } from './lib/paymaster';

// ERC-4337 EntryPoint v0.7 — preinstalled on Base
const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

// Redeploys ONLY the CofferdamPaymaster for the recorded factory. The factory
// and the authority modules stay at their addresses. Testnet only.
//
//   RELAYER_ADDRESS  the plane's relayer EOA (required off the local networks)
//
// Then move the deposit from the old paymaster (`yarn paymaster:move:sepolia`
// with OLD_PAYMASTER) and update the pins (API relay policy, app env).
async function main() {
  refuseMainnetPaymaster();
  const [deployer] = await ethers.getSigners();
  console.log('Deploying CofferdamPaymaster from:', deployer.address);

  const file = path.join(__dirname, '..', 'deployments', `${network.name}.json`);
  const recorded = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const factory = process.env.FACTORY?.trim() || recorded.CofferdamAccountFactory4337?.address;
  const highModule = process.env.HIGH_MODULE?.trim() || recorded.WebAuthnPasskeyAuthority?.address;
  if (!factory || !highModule) throw new Error('No factory or WebAuthn module recorded: set FACTORY and HIGH_MODULE');

  const relayer = paymasterRelayer(deployer.address);
  const fp = await accountCodeFingerprint(factory, highModule);
  console.log('factory:', factory);
  console.log('relayer:', relayer);
  console.log('account code hash:', fp.codeHash, `(${fp.codeSize} bytes, masked words at ${fp.maskOffsets.join(', ')})`);

  const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
  const paymaster = await Paymaster.deploy(ENTRYPOINT_V07, relayer, fp.codeHash, fp.codeSize, fp.maskOffsets);
  await paymaster.waitForDeployment();
  const addr = await paymaster.getAddress();
  console.log('CofferdamPaymaster:', addr);

  // Merge the new paymaster address into deployments/<network>.json, leaving
  // every other entry untouched.
  const registryPath = writeDeployments(network.name, { CofferdamPaymaster: addr });
  console.log('Wrote', registryPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
