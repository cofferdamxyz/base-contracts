import { ethers, network } from 'hardhat';
import { ENTRYPOINT_V07 } from './lib/accountLayer';
import { assertMainnetOwner, assertMainnetSigner, chainId as nodeChainId, getDeployer, readSafe } from './lib/chain';
import { readDeployments, refuseRecordedGeneration, writeDeployments } from './lib/deployments';
import { DEV_KEY_EXCEPTION, devKeyExceptionRequested, mainnetRegistryOwner } from './lib/devKeyException';
import { accountCodeFingerprint } from './lib/paymaster';
import { RELAY_PAYMASTER, relayPaymasterMaxCost, relayPaymasterRelayer, relayerRefusal } from './lib/relayPaymaster';

// Deploys CofferdamRelayPaymaster, the production generation's paymaster (the
// founder's ruling P9 of 2026-11-26, amending decisions 0017 (4) and 0071 (3)):
// it sponsors only the ops the plane's relayer submits for an account of the
// generation's factory, within a per-op cap, and is owned by the company Safe
// from its first block (the owner is a constructor argument, never a transfer).
//
// On Base mainnet (chain 8453) only through the Ledger (`--network base`,
// LEDGER_ADDRESS), or a fork dry run (`--network baseFork`); never under the M2
// dev-key exception. Off mainnet (a local node, or Base Sepolia for the
// rehearsal with a throwaway 2-of-3 Safe) the usual signer deploys it.
//
//   GENERATION              Base mainnet: the generation's deployments file, which records
//                           the factory and the WebAuthn module (deploy-auth.ts first)
//   REGISTRY_OWNER          the owner: the company Safe on Base mainnet, checked on chain
//                           (Safe v1.4.1, at least 3 owners, threshold at least 2, no module);
//                           required off the local networks, else the deployer
//   RELAYER_ADDRESS         the plane's relayer (on mainnet the CDP Server Wallet account);
//                           required on Base mainnet and public testnets, no default there
//   PAYMASTER_MAX_COST_WEI  the largest maxCost one op may carry, in wei; required on Base
//                           mainnet (at most 0.01 ETH there) and public testnets
//   FACTORY, HIGH_MODULE    default the deployments file's CofferdamAccountFactory4337 and
//                           WebAuthnPasskeyAuthority; on mainnet they may only repeat them
//
// Then fund the deposit (anyone may send ETH to the paymaster; from the Safe,
// SAFE_ACTION=paymaster-deposit with scripts/safe-propose.ts) and pin the
// paymaster in the plane's relay policy.
async function main() {
  const chainId = await nodeChainId();
  const mainnet = chainId === 8453n;
  if (mainnet && devKeyExceptionRequested()) {
    throw new Error(`${RELAY_PAYMASTER} deploys on Base mainnet through the Ledger only, never under the dev-key exception (${DEV_KEY_EXCEPTION.env})`);
  }
  const deployer = await getDeployer();
  console.log(`Deploying ${RELAY_PAYMASTER} on ${network.name} (chain ${chainId}) from ${deployer.address}`);
  await assertMainnetSigner(deployer.address);
  const local = network.name === 'hardhat' || network.name === 'localhost';

  const owner = mainnet ? mainnetRegistryOwner() : process.env.REGISTRY_OWNER?.trim() || (local ? deployer.address : '');
  if (!owner) throw new Error('REGISTRY_OWNER is required off the local networks: the Safe that owns the paymaster');
  if (!ethers.isAddress(owner)) throw new Error(`REGISTRY_OWNER ${owner} is not an address`);
  await assertMainnetOwner(owner, { deployer: deployer.address, recordedSafe: readDeployments(network.name, chainId).CofferdamSafe?.address });

  const relayer = ethers.getAddress(relayPaymasterRelayer(process.env.RELAYER_ADDRESS, { mainnet, local, deployer: deployer.address }));
  const relayerProblem = relayerRefusal(relayer, { owner, deployer: deployer.address, mainnet, code: await ethers.provider.getCode(relayer) });
  if (relayerProblem) throw new Error(relayerProblem);
  const ownerSafe = await readSafe(owner);
  if (ownerSafe?.owners.some((o) => o.toLowerCase() === relayer.toLowerCase())) {
    throw new Error(`The relayer ${relayer} is an owner of the Safe ${owner}: a Safe signer is never the relayer`);
  }
  const maxCost = relayPaymasterMaxCost(process.env.PAYMASTER_MAX_COST_WEI, { mainnet, local });

  if (mainnet) refuseRecordedGeneration(network.name, chainId, [RELAY_PAYMASTER]);
  const recorded = readDeployments(network.name, chainId);
  const pick = (name: string, env: string | undefined, file: string | undefined): string => {
    const v = env?.trim();
    if (mainnet && v && file && v.toLowerCase() !== file.toLowerCase()) throw new Error(`${name} ${v} differs from the generation's ${file}`);
    if (mainnet && v && !file) throw new Error(`${name} is not recorded in the generation's file: deploy the account layer first (deploy-auth.ts)`);
    const address = v || file;
    if (!address || !ethers.isAddress(address)) throw new Error(`No ${name}: deploy the account layer first, or set it`);
    return ethers.getAddress(address);
  };
  const factory = pick('FACTORY', process.env.FACTORY, recorded.CofferdamAccountFactory4337?.address);
  const highModule = pick('HIGH_MODULE', process.env.HIGH_MODULE, recorded.WebAuthnPasskeyAuthority?.address);
  const f = await ethers.getContractAt('CofferdamAccountFactory4337', factory);
  if ((await f.ENTRY_POINT()).toLowerCase() !== ENTRYPOINT_V07.toLowerCase()) throw new Error(`The factory ${factory} does not pin EntryPoint v0.7`);

  const fp = await accountCodeFingerprint(factory, highModule);
  console.log({
    owner,
    ownerSafe: ownerSafe ? `${ownerSafe.threshold}-of-${ownerSafe.owners.length}` : 'not a Safe',
    relayer,
    maxCostPerOp: `${maxCost} wei (${ethers.formatEther(maxCost)} ETH)`,
    factory,
    accountCodeHash: fp.codeHash,
    accountCodeSize: fp.codeSize,
    maskOffsets: fp.maskOffsets.join(', '),
  });

  const Paymaster = await ethers.getContractFactory(RELAY_PAYMASTER, deployer);
  const paymaster = await Paymaster.deploy(ENTRYPOINT_V07, owner, relayer, maxCost, fp.codeHash, fp.codeSize, fp.maskOffsets);
  await paymaster.waitForDeployment();
  const address = await paymaster.getAddress();
  console.log(`${RELAY_PAYMASTER}:`, address);

  // Read back what the constructor set, at the block that mined it.
  const receipt = await paymaster.deploymentTransaction()!.wait();
  const at = { blockTag: receipt!.blockNumber };
  const p = await ethers.getContractAt(RELAY_PAYMASTER, address);
  const check = (what: string, actual: unknown, wanted: unknown) => {
    if (String(actual).toLowerCase() !== String(wanted).toLowerCase()) throw new Error(`${what}: read ${actual}, expected ${wanted}`);
    console.log(`  ${what}: ${actual}`);
  };
  check('owner', await p.owner(at), owner);
  check('pendingOwner', await p.pendingOwner(at), ethers.ZeroAddress);
  check('relayer', await p.relayer(at), relayer);
  check('maxCostPerOp', await p.maxCostPerOp(at), maxCost);
  check('paused', await p.paused(at), false);
  check('ENTRY_POINT', await p.ENTRY_POINT(at), ENTRYPOINT_V07);
  check('ACCOUNT_CODE_HASH', await p.ACCOUNT_CODE_HASH(at), fp.codeHash);
  console.log(`  gas ${receipt!.gasUsed}`);

  console.log('Wrote', writeDeployments(network.name, chainId, { [RELAY_PAYMASTER]: address }));
  console.log('Next: fund the deposit (send ETH to the paymaster; from the Safe, SAFE_ACTION=paymaster-deposit with safe-propose.ts) and pin it in the plane.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
