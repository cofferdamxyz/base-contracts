import * as fs from 'fs';
import * as path from 'path';
import { ethers, network } from 'hardhat';

/**
 * Rotate the Self attester key on an already-deployed SelfAttesterRegistry.
 *
 * Key rotation touches three places that must agree, or the attester Worker
 * signs proofs nothing on-chain will accept:
 *
 *   1. `cofferdam-attester/.dev.vars`  — local `wrangler dev`
 *   2. `wrangler secret put ATTESTER_PRIVATE_KEY` — the deployed Worker
 *   3. `SelfAttesterRegistry.isTrustedAttester` — this script
 *
 * Doing (3) by hand is what makes rotations expensive, hence this script. It
 * is idempotent: re-running with the same address is a no-op that still prints
 * the resulting trusted set.
 *
 * Usage:
 *   ATTESTER_ADDRESS=0x<new> \
 *   RETIRE_ATTESTER_ADDRESS=0x<old> \
 *   npx hardhat run scripts/rotate-self-attester.ts --network baseSepolia
 *
 * `RETIRE_ATTESTER_ADDRESS` is optional but strongly recommended — leaving a
 * retired key trusted keeps a compromised signer live.
 */

function requireAddress(label: string, raw: string | undefined): string {
  if (!raw || raw.trim() === '') {
    throw new Error(`${label} is required. Pass it as an environment variable.`);
  }
  const value = raw.trim();
  if (!ethers.isAddress(value)) {
    throw new Error(`${label} is not a valid address: ${value}`);
  }
  if (value === ethers.ZeroAddress) {
    throw new Error(`${label} must not be the zero address.`);
  }
  return ethers.getAddress(value);
}

/**
 * Public RPC endpoints are load-balanced, so a read issued immediately after a
 * receipt can land on a node that has not applied that block yet. The first
 * version of this script did exactly that and reported a freshly revoked
 * attester as still trusted. Poll until the value matches expectation.
 */
async function confirmTrusted(
  read: (address: string) => Promise<boolean>,
  address: string,
  expected: boolean,
  attempts = 10,
  delayMs = 1500,
): Promise<{ value: boolean; converged: boolean }> {
  let value = await read(address);
  for (let i = 1; i < attempts && value !== expected; i++) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    value = await read(address);
  }
  return { value, converged: value === expected };
}

function readRegistryAddress(networkName: string): string {
  const registryPath = path.join(__dirname, '..', 'deployments', `${networkName}.json`);
  if (!fs.existsSync(registryPath)) {
    throw new Error(`No deployments manifest at ${registryPath}. Deploy the Self contracts first.`);
  }
  const manifest = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  const address = manifest?.SelfAttesterRegistry?.address;
  if (!address) {
    throw new Error(
      `SelfAttesterRegistry missing from ${registryPath}. Run scripts/deploy-self.ts first.`,
    );
  }
  return ethers.getAddress(address);
}

async function main() {
  const next = requireAddress('ATTESTER_ADDRESS', process.env.ATTESTER_ADDRESS);
  const retireRaw = process.env.RETIRE_ATTESTER_ADDRESS;
  const retire =
    retireRaw && retireRaw.trim() !== ''
      ? requireAddress('RETIRE_ATTESTER_ADDRESS', retireRaw)
      : undefined;

  if (retire && retire === next) {
    throw new Error(
      'RETIRE_ATTESTER_ADDRESS equals ATTESTER_ADDRESS — that would revoke the key you just added.',
    );
  }

  const registryAddress = readRegistryAddress(network.name);
  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt('SelfAttesterRegistry', registryAddress);

  console.log('Network         :', network.name);
  console.log('Registry        :', registryAddress);
  console.log('Signer          :', signer.address);
  console.log('New attester    :', next);
  console.log('Retire attester :', retire ?? '(none)');

  const owner: string = await registry.owner();
  if (owner !== signer.address) {
    throw new Error(
      `Signer is not the registry owner. owner=${owner} signer=${signer.address}. ` +
        'Set DEPLOYER_PRIVATE_KEY to the owner key.',
    );
  }

  if (await registry.isTrustedAttester(next)) {
    console.log(`\n${next} is already trusted — skipping addAttester.`);
  } else {
    console.log(`\naddAttester(${next})...`);
    const tx = await registry.addAttester(next);
    const receipt = await tx.wait();
    console.log('  mined in block', receipt?.blockNumber, 'tx', tx.hash);
  }

  if (retire) {
    if (await registry.isTrustedAttester(retire)) {
      console.log(`\nremoveAttester(${retire})...`);
      const tx = await registry.removeAttester(retire);
      const receipt = await tx.wait();
      console.log('  mined in block', receipt?.blockNumber, 'tx', tx.hash);
    } else {
      console.log(`\n${retire} is not trusted — skipping removeAttester.`);
    }
  }

  console.log('\n--- Final state ---');
  const isTrusted = (address: string): Promise<boolean> => registry.isTrustedAttester(address);
  const nextState = await confirmTrusted(isTrusted, next, true);
  console.log(
    `  ${next} trusted:`,
    nextState.value,
    nextState.converged ? '' : '<- expected true; RPC may be lagging, re-read before trusting this',
  );
  let retireState: { value: boolean; converged: boolean } | undefined;
  if (retire) {
    retireState = await confirmTrusted(isTrusted, retire, false);
    console.log(
      `  ${retire} trusted:`,
      retireState.value,
      retireState.converged ? '' : '<- expected false; RPC may be lagging, re-read before trusting this',
    );
  }

  if (!nextState.converged || (retireState && !retireState.converged)) {
    process.exitCode = 1;
    console.error('\nRegistry reads did not converge. Re-run this script to confirm.');
  }

  console.log(
    '\nNext: confirm the Worker signs with this address.\n' +
      "  curl -sX POST http://127.0.0.1:8787/v1/attester/test-sign \\\n" +
      "    -H 'content-type: application/json' \\\n" +
      '    -d \'{"account":"0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695"}\' \\\n' +
      "    | jq '{onchainValid, signer: .signed.attesterAddress}'",
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
