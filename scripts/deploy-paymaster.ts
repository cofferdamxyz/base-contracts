import { ethers, network } from 'hardhat';
import { ENTRYPOINT_V07 } from './lib/accountLayer';
import { readDeployments, writeDeployments } from './lib/deployments';
import { chainId } from './lib/chain';
import { accountCodeFingerprint, paymasterRelayer, refuseMainnetPaymaster } from './lib/paymaster';

// Redeploys ONLY the CofferdamPaymaster for the recorded factory. The factory
// and the authority modules stay at their addresses. Testnet only.
//
//   RELAYER_ADDRESS  the plane's relayer EOA (required off the local networks)
//
// Then move the deposit from the old paymaster (`yarn paymaster:move:sepolia`
// with OLD_PAYMASTER) and update the pins (API relay policy, app env).
async function main() {
  await refuseMainnetPaymaster();
  const [deployer] = await ethers.getSigners();
  console.log('Deploying CofferdamPaymaster from:', deployer.address);

  const recorded = readDeployments(network.name, await chainId());
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
  const registryPath = writeDeployments(network.name, await chainId(), { CofferdamPaymaster: addr });
  console.log('Wrote', registryPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
