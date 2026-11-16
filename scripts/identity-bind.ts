import * as fs from 'fs';
import { ethers, network } from 'hardhat';
import { chainId as nodeChainId, isLocalFork } from './lib/chain';
import { readDeployments } from './lib/deployments';
import { IDENTITY_ACTIONS, ZkpSolidityParams, zkpCustomData, zkpEvidenceFromParams } from './lib/identity';
import type { CofferdamIdentityRegistry } from '../typechain-types';

// Decision 0080: a real bound proof against a generation's registry on a local
// fork of Base mainnet. Fork only; it refuses any other node, so nothing it
// does reaches the chain.
//
//   yarn identity:bind:fork:zkp-test-1
//       the live zkp-test-1 contracts (DEPLOYMENTS_NETWORK=baseDevTest
//       GENERATION=zkp-test-1); prints the digest, the custom_data and the
//       cofferdam-app command that requests the proof from the phone
//   ZKP_PARAMS_FILE=<pipe> yarn identity:bind:fork:zkp-test-1
//       the proof: read-only cross-checks, then check() by eth_call, then
//       bind() as ACCOUNT (impersonated on the fork); prints the gas, never
//       the identifier
//   GENERATION=… yarn identity:bind:fork
//       a generation deployed on the fork itself (deployments/baseFork.*)
//
// ACCOUNT defaults to anvil's account #1. On the fork an EOA stands in for the
// account contract: the registry only checks msg.sender against the proof's
// user_address (test/identity-registry.test.ts covers a real account). A
// registry that takes test accounts only gets ACCOUNT added by its owner,
// impersonated, on the fork alone.
//
// The cross-checks, before check(): the adapter accepts the proof; ZKPassport's
// own example consumer (contracts/test/ZKPassportExampleConsumer.sol, from
// their dashboard) accepts it with the adapter's domain, scope, validity and
// minimum age and returns the same identifier; and the scope is enforced:
// RootVerifier.verify and the helper's verifyScopes refuse it under the
// dashboard policy's name `zkp-test-1` and under another domain, which the
// adapter relies on (it passes its scope to RootVerifier.verify and does not
// call verifyScopes itself).
//
// ZKP_PARAMS_FILE is the proof's Solidity parameters
// (`zkpassport-test.mjs --solidity-params`), kept outside this repository.

/** The dashboard policy's name, which a request made through the policy would use as its scope. */
const POLICY_SCOPE = 'zkp-test-1';

function reasonOf(e: unknown): string {
  // The reason only: the revert data of a custom error carries no proof field.
  const err = e as { shortMessage?: string; message: string };
  return err.shortMessage ?? err.message.split('\n')[0];
}

async function main() {
  if ((await nodeChainId()) !== 8453n || !(await isLocalFork())) {
    throw new Error('identity-bind.ts runs only on a local fork of Base mainnet (yarn node:start:base, --network baseFork)');
  }
  const fileNetwork = process.env.DEPLOYMENTS_NETWORK?.trim() || network.name;
  const recorded = readDeployments(fileNetwork, 8453n);
  const registryAddr = recorded.CofferdamIdentityRegistry?.address;
  const adapterAddr = recorded.ZKPassportEvidenceAdapter?.address;
  if (!registryAddr || !adapterAddr) throw new Error(`No identity registry recorded for ${fileNetwork}.${process.env.GENERATION}: deploy one, or name a generation`);
  const registry = (await ethers.getContractAt('CofferdamIdentityRegistry', registryAddr)) as unknown as CofferdamIdentityRegistry;
  const adapter = await ethers.getContractAt('ZKPassportEvidenceAdapter', adapterAddr);
  if ((await ethers.provider.getCode(registryAddr)) === '0x') throw new Error(`No contract at ${registryAddr} on this fork`);
  const account = ethers.getAddress(process.env.ACCOUNT?.trim() || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');

  async function as<T>(address: string, run: (signer: Awaited<ReturnType<typeof ethers.getSigner>>) => Promise<T>): Promise<T> {
    await ethers.provider.send('anvil_impersonateAccount', [address]);
    if ((await ethers.provider.getBalance(address)) < ethers.parseEther('0.1')) {
      await ethers.provider.send('hardhat_setBalance', [address, ethers.toBeHex(ethers.parseEther('1'))]);
    }
    try {
      return await run(await ethers.getSigner(address));
    } finally {
      await ethers.provider.send('anvil_stopImpersonatingAccount', [address]);
    }
  }

  // Test accounts only: the owner (the Safe, for zkp-test-1) adds ACCOUNT, on this fork alone.
  if ((await registry.allowlistOnly()) && !(await registry.isTestAccount(account))) {
    const owner = await registry.owner();
    await as(owner, async (s) => (await registry.connect(s).setTestAccount(account, true)).wait());
    console.log(`Fork only: ${owner} (the owner) added ${account} as a test account`);
  }

  const digest = await registry.digest(IDENTITY_ACTIONS.bind, account);
  const scope = await adapter.scope();
  const domain = await adapter.DOMAIN();
  const margin = await adapter.EXPIRY_MARGIN();
  const minAge = await adapter.MIN_AGE();
  const validity = await adapter.VALIDITY();
  // ZKPassport compares dates by day: ask for a whole day past the margin.
  const expiryAfter = new Date((Number((await ethers.provider.getBlock('latest'))!.timestamp) + Number(margin) + 86_400) * 1000)
    .toISOString()
    .slice(0, 10);
  console.log({ registry: registryAddr, adapter: adapterAddr, account, domain, scope, minAge: Number(minAge), validitySeconds: Number(validity), expiryMarginDays: Number(margin) / 86_400 });
  console.log(`digest (custom_data): ${zkpCustomData(digest)}`);

  const file = process.env.ZKP_PARAMS_FILE?.trim();
  if (!file) {
    console.log(`\nRequest the proof (cofferdam-app worktree on branch zkpassport-test); it stays valid for ${Number(validity) / 60} minutes:`);
    console.log(
      `  node scripts/zkpassport-test.mjs --probe --evm --scope ${scope} --address ${account} --custom-data ${zkpCustomData(digest)} --expiry-after ${expiryAfter}`,
    );
    console.log('Then stream its Solidity parameters through a named pipe, so no second copy lands on disk, into this script again:');
    console.log('  mkfifo -m 600 /tmp/zkp.fifo');
    console.log('  (cd <cofferdam-app worktree> && node scripts/zkpassport-test.mjs --solidity-params .zkpassport-results/run-<stamp>.json > /tmp/zkp.fifo &)');
    console.log(`  ZKP_PARAMS_FILE=/tmp/zkp.fifo yarn ${process.env.npm_lifecycle_event ?? 'identity:bind:fork'} && rm /tmp/zkp.fifo`);
    return;
  }

  const params = JSON.parse(fs.readFileSync(file, 'utf8')) as ZkpSolidityParams;
  // anvil mines only on transactions, so its latest block can predate the
  // proof, which the verifier refuses as outside its validity: mine one now.
  await ethers.provider.send('evm_mine', []);
  const evidence = zkpEvidenceFromParams(params);

  // Cross-checks, all read-only.
  const failures: string[] = [];
  const report = (what: string, ok: boolean, detail = '') => {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${detail ? `: ${detail}` : ''}`);
    if (!ok) failures.push(what);
  };
  // The adapter's own configuration, as it passes it to RootVerifier.verify.
  const pinned = {
    version: await adapter.VERSION(),
    proofVerificationData: params.proofVerificationData,
    committedInputs: params.committedInputs,
    serviceConfig: { validityPeriodInSeconds: validity, domain, scope, devMode: false },
  };
  const root = await ethers.getContractAt('IZKPassportRootVerifier', await adapter.ROOT_VERIFIER());
  const helper = new ethers.Contract(
    await adapter.HELPER(),
    ['function verifyScopes(bytes32[] publicInputs, string domain, string scope) view returns (bool)'],
    ethers.provider,
  );
  const verifies = async (serviceConfig: typeof pinned.serviceConfig) => {
    try {
      const [valid] = await root.verify({ ...pinned, serviceConfig });
      return valid as boolean;
    } catch {
      return false;
    }
  };
  const scopes = async (d: string, s: string) => {
    try {
      return (await helper.verifyScopes(params.proofVerificationData.publicInputs, d, s)) as boolean;
    } catch {
      return false;
    }
  };

  let adapterId: string | null = null;
  try {
    adapterId = await adapter.verify(account, digest, evidence);
    report('the adapter accepts it', true);
  } catch (e) {
    report('the adapter accepts it', false, reasonOf(e));
  }
  const Example = await ethers.getContractFactory('ZKPassportExampleConsumer');
  const example = await (await Example.deploy(await adapter.ROOT_VERIFIER(), domain, scope, validity, minAge)).waitForDeployment();
  try {
    const exampleId: string = await example.verify(pinned, { from: account });
    report("ZKPassport's example consumer accepts it", true);
    if (adapterId) report('with the same identifier as the adapter', exampleId === adapterId);
  } catch (e) {
    report("ZKPassport's example consumer accepts it", false, reasonOf(e));
  }
  report(`RootVerifier.verify takes it under ${domain} × ${scope}`, await verifies(pinned.serviceConfig));
  report(`RootVerifier.verify refuses it under the policy's name ${POLICY_SCOPE}`, !(await verifies({ ...pinned.serviceConfig, scope: POLICY_SCOPE })));
  report('RootVerifier.verify refuses it under another domain', !(await verifies({ ...pinned.serviceConfig, domain: 'example.com' })));
  report(`the helper's verifyScopes agrees under ${scope}`, await scopes(domain, scope));
  report(`the helper's verifyScopes refuses ${POLICY_SCOPE}`, !(await scopes(domain, POLICY_SCOPE)));
  if (failures.length > 0) {
    console.log(`\nNot binding: ${failures.length} cross-check(s) failed`);
    process.exitCode = 1;
    return;
  }

  try {
    await registry.check(IDENTITY_ACTIONS.bind, account, adapterAddr, evidence);
    console.log('check(): passes');
  } catch (e) {
    console.log(`check(): reverts: ${reasonOf(e)}`);
    process.exitCode = 1;
    return;
  }
  const receipt = await as(account, async (s) => (await registry.connect(s).bind(adapterAddr, evidence)).wait());
  console.log(`bind(): mined on the fork, gas used ${receipt!.gasUsed}; isAccountBound = ${await registry.isAccountBound(account)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
