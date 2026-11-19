import { artifacts, ethers, network, run } from 'hardhat';
import { Etherscan } from '@nomicfoundation/hardhat-verify/etherscan';
import type { TransactionResponse } from 'ethers';
import { BASE_MAINNET_CHAIN_ID, chainId as nodeChainId, isLocalFork } from './lib/chain';
import { readDeployments } from './lib/deployments';
import { BytecodeMismatchError, constructorArgsHex, createNonce, selectRecorded, verifyPlan } from './lib/verify';

// Basescan verification of a generation's contracts, from the chain itself:
// for each contract the deployments file records, find its creation
// transaction (the deployer's nonce whose CREATE made it), check that the
// transaction starts with the bytecode compiled here, decode the constructor
// arguments from the rest, and submit the source to Etherscan's v2 API with
// them. Nothing is signed: it runs on the `base` network, which holds no key.
// On Base Sepolia (`yarn verify:sepolia`, which loads the deployer's key but
// sends nothing) it verifies the entries VERIFY_KEYS names, and an entry that
// records its `txHash` (the handle anchor's) is found by that hash.
//
//   GENERATION            the generation (one deployments file each on Base mainnet)
//   DEPLOYMENTS_NETWORK   the file's network name, default this network's
//                         (`baseDevTest` for zkp-test-1, the M2 dev-key exception)
//   DEPLOYER              default the file's devKeyException deployer, else the
//                         `deployer` the selected entries record
//   VERIFY_KEYS           comma-separated entries to verify, default all;
//                         required in practice on Base Sepolia
//   ETHERSCAN_API_KEY     in .env; without it, or with CHECK_ONLY=1, the checks
//                         run and nothing is submitted
//   CHECK_ONLY=1          the checks only
//
// A contract deployed before a later change to its source no longer matches
// the bytecode compiled here. With an API key, one Basescan already shows the
// source of is reported as verified from an earlier commit, not as a failure;
// without a key it cannot be told apart from a wrong build, and fails.

const BASE_CHAIN_CONFIG = {
  network: 'base',
  chainId: 8453,
  urls: { apiURL: 'https://api.basescan.org/api', browserURL: 'https://basescan.org/' },
};
const BASE_SEPOLIA_CHAIN_ID = 84532n;
const BASE_SEPOLIA_CHAIN_CONFIG = {
  network: 'baseSepolia',
  chainId: 84532,
  urls: { apiURL: 'https://api-sepolia.basescan.org/api', browserURL: 'https://sepolia.basescan.org/' },
};

async function main() {
  const chainId = await nodeChainId();
  const known = chainId === BASE_MAINNET_CHAIN_ID || chainId === BASE_SEPOLIA_CHAIN_ID;
  if (!known || (await isLocalFork())) throw new Error(`Basescan verifies Base mainnet and Base Sepolia only; ${network.name} is chain ${chainId}${known ? ', a local fork' : ''}`);
  const fileNetwork = process.env.DEPLOYMENTS_NETWORK?.trim() || network.name;
  const recorded = selectRecorded(
    readDeployments(fileNetwork, chainId) as Record<string, { address?: string; deployer?: string; txHash?: string }>,
    process.env.VERIFY_KEYS,
  );
  if (Object.keys(recorded).length === 0) throw new Error(`No deployments recorded for ${fileNetwork} and GENERATION ${process.env.GENERATION}`);
  const entryDeployers = [...new Set(Object.values(recorded).map((e) => e?.deployer?.toLowerCase()).filter(Boolean))];
  const deployerRaw = process.env.DEPLOYER?.trim() || recorded.devKeyException?.deployer || (entryDeployers.length === 1 ? entryDeployers[0] : undefined);
  if (!deployerRaw || !ethers.isAddress(deployerRaw)) throw new Error('No deployer: set DEPLOYER (the Ledger address for a Ledger generation)');
  const deployer = ethers.getAddress(deployerRaw);
  const apiKey = process.env.ETHERSCAN_API_KEY?.trim() || process.env.BASESCAN_API_KEY?.trim() || '';
  const submit = process.env.CHECK_ONLY !== '1' && apiKey !== '';
  const plan = verifyPlan(recorded);
  console.log(`Verifying ${plan.ours.length} contracts of ${fileNetwork}${process.env.GENERATION ? `.${process.env.GENERATION}` : ''} deployed by ${deployer}${submit ? '' : ' (checks only: CHECK_ONLY=1 or no ETHERSCAN_API_KEY)'}`);

  // The block in which the deployer's transaction with `nonce` was mined: the
  // first block after which its account nonce exceeds it. Galloping back from
  // the head, then bisecting; the public RPC answers historical nonces.
  const head = await ethers.provider.getBlockNumber();
  const nonceAt = new Map<number, number>();
  const nonceAtBlock = async (block: number) => {
    if (!nonceAt.has(block)) nonceAt.set(block, await ethers.provider.getTransactionCount(deployer, block));
    return nonceAt.get(block)!;
  };
  async function blockOfNonce(nonce: number): Promise<number> {
    let hi = head;
    let step = 1024;
    let lo = Math.max(0, hi - step);
    while ((await nonceAtBlock(lo)) > nonce) {
      if (lo === 0) throw new Error(`The deployer's nonce ${nonce} predates block 0`);
      hi = lo;
      step *= 2;
      lo = Math.max(0, hi - step);
    }
    // nonceAt(lo) <= nonce < nonceAt(hi)
    while (hi - lo > 1) {
      const mid = Math.floor((lo + hi) / 2);
      if ((await nonceAtBlock(mid)) > nonce) hi = mid;
      else lo = mid;
    }
    return hi;
  }

  const nonceNow = await ethers.provider.getTransactionCount(deployer, 'latest');
  const etherscan = apiKey ? Etherscan.fromChainConfig(apiKey, chainId === BASE_SEPOLIA_CHAIN_ID ? BASE_SEPOLIA_CHAIN_CONFIG : BASE_CHAIN_CONFIG) : undefined;
  const failed: string[] = [];
  const earlier: string[] = [];
  for (const { key, contract, address, txHash } of plan.ours) {
    try {
      let tx: TransactionResponse | null | undefined;
      let blockNumber: number;
      let nonce: number;
      if (txHash) {
        // The entry records its creation transaction: no nonce search.
        tx = await ethers.provider.getTransaction(txHash);
        if (!tx || tx.blockNumber == null) throw new Error(`its recorded creation transaction ${txHash} is not mined on this chain`);
        if (tx.from.toLowerCase() !== deployer.toLowerCase() || tx.to !== null) throw new Error(`${txHash} is not a contract creation by ${deployer}`);
        blockNumber = tx.blockNumber;
        nonce = tx.nonce;
      } else {
        const found = createNonce(deployer, address, nonceNow);
        if (found === null) throw new Error(`no nonce of ${deployer} below ${nonceNow} created it`);
        nonce = found;
        blockNumber = await blockOfNonce(nonce);
        const block = await ethers.provider.getBlock(blockNumber, true);
        tx = block?.prefetchedTransactions.find((t) => t.from.toLowerCase() === deployer.toLowerCase() && t.nonce === nonce);
      }
      if (!tx || tx.to !== null) throw new Error(`no contract creation by ${deployer} with nonce ${nonce} in block ${blockNumber}`);
      const receipt = await ethers.provider.getTransactionReceipt(tx.hash);
      if (receipt?.status !== 1 || receipt.contractAddress?.toLowerCase() !== address.toLowerCase()) throw new Error(`${tx.hash} did not create ${address}`);

      const artifact = await artifacts.readArtifact(contract);
      const argsHex = constructorArgsHex(tx.data, artifact.bytecode);
      const iface = new ethers.Interface(artifact.abi);
      const args = iface.deploy.inputs.length === 0 ? [] : ethers.AbiCoder.defaultAbiCoder().decode(iface.deploy.inputs, argsHex).toArray(true);
      if (iface.encodeDeploy(args) !== argsHex) throw new Error('the constructor arguments do not re-encode to the transaction’s');
      console.log(`\n${key} ${address}: ${artifact.sourceName}:${contract}, created by ${tx.hash} (block ${blockNumber}, nonce ${nonce})`);
      iface.deploy.inputs.forEach((input, i) => console.log(`  ${input.name}: ${JSON.stringify(args[i], (_k, v) => (typeof v === 'bigint' ? v.toString() : v))}`));
      if (!submit) continue;
      await run('verify:verify', { address, constructorArguments: args, contract: `${artifact.sourceName}:${contract}` });
    } catch (e) {
      if (e instanceof BytecodeMismatchError && etherscan && (await etherscan.isVerified(address))) {
        console.log(`\n${key} ${address}: built from an earlier commit's sources (this checkout compiles other bytecode); Basescan already shows its source (${etherscan.getContractUrl(address)})`);
        earlier.push(key);
        continue;
      }
      console.error(`\n${key} ${address}: ${(e as Error).message}`);
      failed.push(key);
    }
  }

  if (etherscan) {
    for (const { key, address } of plan.notOurs) {
      const verified = await etherscan.isVerified(address);
      console.log(`\n${key} ${address}: not ours to verify; Basescan ${verified ? 'shows its source' : 'shows no source yet'} (${etherscan.getContractUrl(address)})`);
    }
  } else {
    for (const { key, address } of plan.notOurs) console.log(`\n${key} ${address}: not ours to verify (check Basescan)`);
  }

  if (failed.length > 0) throw new Error(`Not verified: ${failed.join(', ')}`);
  if (earlier.length > 0) console.log(`\nVerified on Basescan from an earlier commit: ${earlier.join(', ')}`);
  console.log(submit ? '\nAll submitted or already verified.' : '\nAll checks passed; nothing submitted.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
