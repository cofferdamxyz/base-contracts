import * as fs from 'fs';
import { ethers, network } from 'hardhat';
import { chainId as nodeChainId, isLocalFork } from './lib/chain';
import { readDeployments } from './lib/deployments';
import { IDENTITY_ACTIONS, ZkpSolidityParams, zkpCustomData, zkpEvidenceFromParams } from './lib/identity';
import type { CofferdamIdentityRegistry } from '../typechain-types';

// Decision 0080, M1 step 2: a real bound proof against the registry on a
// local fork of Base mainnet. Fork only; it refuses any other node.
//
//   GENERATION=zkp-dryrun-1 ACCOUNT=0x… yarn identity:bind:fork
//       prints the digest, the custom_data and the cofferdam-app command that
//       requests the proof from the phone
//   GENERATION=zkp-dryrun-1 ACCOUNT=0x… ZKP_PARAMS_FILE=<pipe> yarn identity:bind:fork
//       runs check() by eth_call, then bind() as ACCOUNT (impersonated on the
//       fork), and prints the gas; never the identifier
//
// ACCOUNT defaults to anvil's account #1. On the fork an EOA stands in for the
// account contract: the registry only checks msg.sender against the proof's
// user_address (test/identity-registry.test.ts covers a real account).
// ZKP_PARAMS_FILE is the proof's Solidity parameters
// (`zkpassport-test.mjs --solidity-params`), kept outside this repository.
async function main() {
  if ((await nodeChainId()) !== 8453n || !(await isLocalFork())) {
    throw new Error('identity-bind.ts runs only on a local fork of Base mainnet (yarn node:start:base, --network baseFork)');
  }
  const recorded = readDeployments(network.name, 8453n);
  const registryAddr = recorded.CofferdamIdentityRegistry?.address;
  const adapterAddr = recorded.ZKPassportEvidenceAdapter?.address;
  if (!registryAddr || !adapterAddr) throw new Error('No identity registry in this generation: run yarn deploy:identity:fork first');
  const registry = (await ethers.getContractAt('CofferdamIdentityRegistry', registryAddr)) as unknown as CofferdamIdentityRegistry;
  const adapter = await ethers.getContractAt('ZKPassportEvidenceAdapter', adapterAddr);
  const account = ethers.getAddress(process.env.ACCOUNT?.trim() || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');

  const digest = await registry.digest(IDENTITY_ACTIONS.bind, account);
  const scope = await adapter.scope();
  const margin = await adapter.EXPIRY_MARGIN();
  const minAge = await adapter.MIN_AGE();
  // ZKPassport compares dates by day: ask for a whole day past the margin.
  const expiryAfter = new Date((Number((await ethers.provider.getBlock('latest'))!.timestamp) + Number(margin) + 86_400) * 1000)
    .toISOString()
    .slice(0, 10);
  console.log({ registry: registryAddr, adapter: adapterAddr, account, scope, minAge: Number(minAge), expiryMarginDays: Number(margin) / 86_400 });
  console.log(`digest (custom_data): ${zkpCustomData(digest)}`);

  const file = process.env.ZKP_PARAMS_FILE?.trim();
  if (!file) {
    if (scope !== 'cofferdam-zkp-test') {
      console.log(`Note: zkpassport-test.mjs requests scope cofferdam-zkp-test; this adapter pins ${scope}, so the proof would fail.`);
    }
    console.log('\nRequest the proof (cofferdam-app worktree on branch zkpassport-test); it stays valid for an hour:');
    console.log(
      `  node scripts/zkpassport-test.mjs --probe --evm --address ${account} --custom-data ${zkpCustomData(digest)} --expiry-after ${expiryAfter}`,
    );
    return;
  }

  const params = JSON.parse(fs.readFileSync(file, 'utf8')) as ZkpSolidityParams;
  // anvil mines only on transactions, so its latest block can predate the
  // proof, which the verifier refuses as outside its validity: mine one now.
  await ethers.provider.send('evm_mine', []);
  const evidence = zkpEvidenceFromParams(params);
  try {
    await registry.check(IDENTITY_ACTIONS.bind, account, adapterAddr, evidence);
    console.log('check(): passes');
  } catch (e) {
    // The reason only: the revert data of a custom error carries no proof field.
    const err = e as { shortMessage?: string; message: string };
    console.log(`check(): reverts: ${err.shortMessage ?? err.message.split('\n')[0]}`);
    process.exitCode = 1;
    return;
  }
  await ethers.provider.send('anvil_impersonateAccount', [account]);
  await ethers.provider.send('hardhat_setBalance', [account, ethers.toBeHex(ethers.parseEther('1'))]);
  const signer = await ethers.getSigner(account);
  const receipt = await (await registry.connect(signer).bind(adapterAddr, evidence)).wait();
  await ethers.provider.send('anvil_stopImpersonatingAccount', [account]);
  console.log(`bind(): mined, gas used ${receipt!.gasUsed}; isAccountBound = ${await registry.isAccountBound(account)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
