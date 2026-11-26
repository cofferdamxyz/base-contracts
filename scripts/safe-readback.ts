import * as fs from 'fs';
import { ethers, network } from 'hardhat';
import { chainId as nodeChainId } from './lib/chain';
import { SafeProposal, runReadback } from './lib/safeProposal';

// After the Safe's owners executed a proposal of safe-propose.ts: ties the
// execution to the proposal (the Safe's ExecutionSuccess for its safeTxHash in
// EXEC_TX's receipt; an ExecutionFailure is reported as such) and reads the
// effect back at that block. Reads only; signs nothing.
//
//   SAFE_PROPOSAL  the .proposal.json safe-propose.ts wrote
//   EXEC_TX        the transaction that executed it (the Safe app shows it)
async function main() {
  const file = process.env.SAFE_PROPOSAL?.trim();
  if (!file || !fs.existsSync(file)) throw new Error('SAFE_PROPOSAL is required: the .proposal.json safe-propose.ts wrote');
  const proposal = JSON.parse(fs.readFileSync(file, 'utf8')) as SafeProposal;
  if (proposal.kind !== 'cofferdam-safe-proposal-v1') throw new Error(`${file} is not a safe-propose.ts proposal`);
  const chainId = await nodeChainId();
  if (BigInt(proposal.chainId) !== chainId) throw new Error(`The proposal is for chain ${proposal.chainId}; ${network.name} is chain ${chainId}`);
  const execTx = process.env.EXEC_TX?.trim();
  if (!execTx || !/^0x[0-9a-fA-F]{64}$/.test(execTx)) throw new Error('EXEC_TX is required: the hash of the transaction that executed the proposal');
  console.log(`Read back ${proposal.action} (${proposal.describe}) on ${network.name}`);
  await runReadback(ethers.provider, proposal, execTx, (line) => console.log(line));
  console.log('Read back: every check passed.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
