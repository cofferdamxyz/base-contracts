import * as fs from 'fs';
import * as path from 'path';
import { ethers, network } from 'hardhat';
import { chainId as nodeChainId, isLocalFork, readSafe } from './lib/chain';
import { readDeployments } from './lib/deployments';
import { devKeyExceptionRequested } from './lib/devKeyException';
import { productionOwnerRefusal } from './lib/productionSafe';
import {
  SafeProposal,
  actionTarget,
  buildSafeCall,
  parseProposeAction,
  proposalNonce,
  safeCallTx,
  safeProposeRefusal,
  safeTxHash,
  safeTxHashParts,
  txBuilderFile,
} from './lib/safeProposal';

// Owner actions through a Safe whose threshold is 2 or more: the company Safe
// (2-of-3: the Ledger, the founder's phone, a second hardware wallet; the
// founder's ruling of 2026-11-26), or the throwaway 2-of-3 Safe of the Base
// Sepolia rehearsal. It sends nothing and signs nothing: it builds the Safe's
// one call for SAFE_ACTION, pre-flights it from the Safe's address, writes
//
//   safe-proposals/<network>[.<GENERATION>].<nonce>.<action>.txbuilder.json
//       the Safe Transaction Builder file: Safe{Wallet} > Apps > Transaction
//       Builder > drag it in > Create batch > Send batch
//   safe-proposals/<network>[.<GENERATION>].<nonce>.<action>.proposal.json
//       the record safe-readback.ts checks the execution against
//
// and prints the Safe transaction hash for the nonce. Before signing, every
// signer checks that the app shows the same safeTxHash (a Ledger signing blind
// shows the domain and message hashes printed here). The signers sign in the
// app; the last one, or anyone, executes. Then:
//
//   SAFE_PROPOSAL=<the .proposal.json> EXEC_TX=<the execution's tx hash> yarn safe:readback:<network>
//
//   SAFE_ACTION   the identity registry's: pause, unpause, set-test-account (ACCOUNT, ALLOWED),
//                 adapter-propose / adapter-activate / adapter-cancel (ZKP_CIRCUITS_VERSION, and
//                 ZKP_ADAPTER_KIND=pepper for the pepper's copies; the copy must be recorded);
//                 the handle anchor's anchor-* (as safe-exec.ts, same variables);
//                 CofferdamRelayPaymaster's: paymaster-set-relayer (RELAYER_ADDRESS),
//                 paymaster-pause, paymaster-unpause, paymaster-set-max-cost (PAYMASTER_MAX_COST_WEI),
//                 paymaster-withdraw (AMOUNT_WEI, WITHDRAW_TO default the Safe),
//                 paymaster-deposit (AMOUNT_WEI, from the Safe's balance),
//                 paymaster-transfer-ownership (NEW_SAFE), paymaster-cancel-ownership-transfer,
//                 paymaster-accept-ownership (SAFE_ADDRESS the new Safe)
//   SAFE_ADDRESS  default the generation's recorded Safe (CofferdamHandleAnchorSafe, else
//                 CofferdamSafe, for anchor-*); an acceptance names the new Safe
//   SAFE_NONCE    default the Safe's current nonce; a later one when proposals are queued
//   IDENTITY_REGISTRY, HANDLE_ANCHOR, RELAY_PAYMASTER  default the generation's recorded contract
//
// safe-exec.ts's drills are two transactions each: propose pause then unpause,
// or adapter-propose then adapter-cancel. On chain 8453 outside the M2
// dev-key exception the Safe must pass the company Safe's check (Safe v1.4.1,
// at least 3 owners, threshold 2 or more, no module).

const DIR = path.join(__dirname, '..', 'safe-proposals');

function pick(name: string, fromEnv: string | undefined, recorded: string | undefined): string {
  const env = fromEnv?.trim();
  if (env && recorded && env.toLowerCase() !== recorded.toLowerCase()) throw new Error(`${name} ${env} differs from the generation's recorded ${recorded}`);
  const address = env || recorded;
  if (!address || !ethers.isAddress(address)) throw new Error(`No ${name}: set it, or run with the generation's GENERATION`);
  return ethers.getAddress(address);
}

async function main() {
  const action = parseProposeAction(process.env.SAFE_ACTION);
  const chainId = await nodeChainId();
  console.log(`Safe proposal ${action} on ${network.name} (chain ${chainId})`);
  const recorded = readDeployments(network.name, chainId);
  const target = actionTarget(action);
  const targetAddress = pick(target.env, process.env[target.env], recorded[target.key]?.address);

  const accepting = action.endsWith('accept-ownership');
  const recordedSafe = target.safeKeys.map((k) => recorded[k]?.address).find(Boolean);
  const safe = accepting ? pick('SAFE_ADDRESS', process.env.SAFE_ADDRESS, undefined) : pick('SAFE_ADDRESS', process.env.SAFE_ADDRESS, recordedSafe);
  const facts = await readSafe(safe);
  const refusal = safeProposeRefusal(safe, facts, accepting ? undefined : recordedSafe);
  if (refusal) throw new Error(refusal);
  if (chainId === 8453n && !devKeyExceptionRequested()) {
    const production = productionOwnerRefusal(safe, facts);
    if (production) throw new Error(production);
  }

  const built = await buildSafeCall({ action, env: process.env, provider: ethers.provider, chainId, safe, safeFacts: facts!, target: targetAddress, recorded });

  // Pre-flight as the Safe, so a refusal comes back with the contract's own error.
  // base-anvil charges an eth_call's gas to its sender: on a fork only, give the Safe test ETH.
  if ((await isLocalFork()) && (await ethers.provider.getBalance(safe)) < ethers.parseEther('0.01') + built.value) {
    await ethers.provider.send('hardhat_setBalance', [safe, ethers.toBeHex(ethers.parseEther('0.01') + built.value)]);
  }
  try {
    await ethers.provider.call({ from: safe, to: built.to, data: built.data, value: built.value });
  } catch (e) {
    throw new Error(`${built.describe}: the call from the Safe reverts now: ${(e as Error).message}`);
  }

  const safeContract = new ethers.Contract(safe, ['function nonce() view returns (uint256)', 'function getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256) view returns (bytes32)'], ethers.provider);
  const current: bigint = await safeContract.nonce();
  const nonce = proposalNonce(process.env.SAFE_NONCE, current);
  const tx = safeCallTx(built.to, built.value, built.data, nonce);
  const hash = safeTxHash(chainId, safe, tx);
  // The Safe's own hash for the same fields: the two must agree.
  const onChain: string = await safeContract.getTransactionHash(tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce);
  if (onChain.toLowerCase() !== hash.toLowerCase()) throw new Error(`The Safe computes ${onChain} for this transaction, not ${hash}`);
  const parts = safeTxHashParts(chainId, safe, tx);

  const generation = chainId === 8453n ? `.${process.env.GENERATION?.trim()}` : '';
  const label = `${network.name}${generation}.${nonce}.${action}`;
  const proposal: SafeProposal = {
    kind: 'cofferdam-safe-proposal-v1',
    action,
    describe: built.describe,
    chainId: chainId.toString(),
    safe,
    nonce: nonce.toString(),
    safeTxHash: hash,
    domainHash: parts.domainHash,
    messageHash: parts.messageHash,
    tx: { to: tx.to, value: tx.value.toString(), data: tx.data, operation: 0 },
    checks: built.checks,
  };
  const batch = txBuilderFile({
    chainId,
    safe,
    createdAt: Date.now(),
    name: `Cofferdam ${action} (nonce ${nonce})`,
    description: `${built.describe}. safeTxHash ${hash} at nonce ${nonce}.`,
    tx: { to: tx.to, value: tx.value.toString(), data: tx.data },
  });
  fs.mkdirSync(DIR, { recursive: true });
  const batchPath = path.join(DIR, `${label}.txbuilder.json`);
  const proposalPath = path.join(DIR, `${label}.proposal.json`);
  for (const p of [batchPath, proposalPath]) if (fs.existsSync(p)) throw new Error(`${path.relative(process.cwd(), p)} exists: a proposal for this nonce and action was written already (remove it, or set SAFE_NONCE)`);
  fs.writeFileSync(batchPath, JSON.stringify(batch, null, 2) + '\n');
  fs.writeFileSync(proposalPath, JSON.stringify(proposal, null, 2) + '\n');

  console.log(`\n  ${built.describe}`);
  console.log(`  to ${tx.to}, value ${tx.value}, data ${tx.data}`);
  console.log(`  Safe ${safe}, ${facts!.threshold}-of-${facts!.owners.length} (${facts!.owners.join(', ')})`);
  console.log(`  nonce ${nonce}${nonce > current ? ` (the Safe's is ${current}: earlier nonces execute first)` : ''}`);
  console.log(`\n  safeTxHash   ${hash}`);
  console.log(`  domain hash  ${parts.domainHash}`);
  console.log(`  message hash ${parts.messageHash}\n`);
  for (const n of built.notes) console.log(`  NOTE: ${n}`);
  console.log(`  Import into Safe{Wallet} (Transaction Builder): ${path.relative(process.cwd(), batchPath)}`);
  console.log(`  Each signer checks the app shows safeTxHash ${hash} at nonce ${nonce} before signing.`);
  console.log(`  After execution: SAFE_PROPOSAL=${path.relative(process.cwd(), proposalPath)} EXEC_TX=0x… yarn safe:readback:<network>`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
