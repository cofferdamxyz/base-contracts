// The Base Sepolia deploy of CofferdamHandleAnchor (workspace decision 0086,
// rule 3; docs/runbooks/handles-build.md step 2) for
// scripts/deploy-handle-anchor.ts: its parameters, its refusals, the deploy
// and the read-back, the deployments entries and the plane's env lines.
// Imports nothing from Hardhat, so the tests drive it on the in-process network.
//
// Base mainnet is refused outright, a fork of it included: handles are tested
// on Sepolia only, and the mainnet anchor waits on Cofferdam Inc.'s Ledger and
// the production Safe (ruling I). Its delays are pinned by
// `mainnetDelaysRefusal` for the mainnet script that comes then.

import * as fs from 'fs';
import { ethers } from 'ethers';
import { DEV_KEY_EXCEPTION, SAFE_V141, type SafeFacts } from './devKeyException';
import { HANDLE_ANCHOR_DOMAIN_NAME, HANDLE_ANCHOR_DOMAIN_VERSION, HANDLE_ANCHOR_MAINNET } from './handleAnchor';

export const BASE_MAINNET_CHAIN_ID = 8453n;
export const BASE_SEPOLIA_CHAIN_ID = 84532n;

const DAY = 24n * 3600n;
/** The contract's bounds off mainnet (`MAX_DELAY`, `MAX_QUARANTINE`), checked before any gas is spent. */
export const HANDLE_ANCHOR_MAX_DELAY = 30n * DAY;
export const HANDLE_ANCHOR_MAX_QUARANTINE = 730n * DAY;

export type HandleAnchorDelays = { changeDelay: bigint; freezeDuration: bigint; quarantine: bigint; safeDelay: bigint };

/**
 * Sepolia's short delays, so a rename, a removal and a freeze finish within a
 * device-test session: owner changes wait 10 minutes, a hold freezes for 30,
 * a released label is quarantined for a day, the Safe's timelock is 10 minutes.
 */
export const HANDLE_ANCHOR_SEPOLIA_DEFAULTS: HandleAnchorDelays = {
  changeDelay: 600n,
  freezeDuration: 1800n,
  quarantine: DAY,
  safeDelay: 600n,
};

/** The variable that overrides each delay, in seconds. */
export const HANDLE_ANCHOR_DELAY_ENV: Record<keyof HandleAnchorDelays, string> = {
  changeDelay: 'HANDLE_CHANGE_DELAY_SECONDS',
  freezeDuration: 'HANDLE_FREEZE_SECONDS',
  quarantine: 'HANDLE_QUARANTINE_SECONDS',
  safeDelay: 'HANDLE_SAFE_DELAY_SECONDS',
};

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Why this script may not deploy on this chain, or null: Base Sepolia, or a local development node that is not chain 8453. */
export function chainRefusal(chainId: bigint, localDevNode: boolean): string | null {
  if (chainId === BASE_MAINNET_CHAIN_ID) {
    return (
      'CofferdamHandleAnchor never deploys to Base mainnet (chain 8453) from this script, a fork of it included: handles are tested on Base Sepolia only, ' +
      "and the mainnet anchor waits on Cofferdam Inc.'s Ledger and the production Safe (ruling I), with a script of its own that pins 0086's delays"
    );
  }
  if (chainId === BASE_SEPOLIA_CHAIN_ID || localDevNode) return null;
  return `Chain ${chainId} is neither Base Sepolia (${BASE_SEPOLIA_CHAIN_ID}) nor a local development node`;
}

/** The delays from the environment, Sepolia's short defaults otherwise, within the contract's bounds. */
export function sepoliaDelaysFrom(env: NodeJS.ProcessEnv): HandleAnchorDelays {
  const out = { ...HANDLE_ANCHOR_SEPOLIA_DEFAULTS };
  for (const key of Object.keys(HANDLE_ANCHOR_DELAY_ENV) as (keyof HandleAnchorDelays)[]) {
    const name = HANDLE_ANCHOR_DELAY_ENV[key];
    const raw = env[name]?.trim();
    if (!raw) continue;
    if (!/^\d{1,12}$/.test(raw)) throw new Error(`${name} is a whole number of seconds; got ${raw}`);
    out[key] = BigInt(raw);
  }
  const refusal = delaysRefusal(out);
  if (refusal) throw new Error(refusal);
  return out;
}

/** The constructor's own bounds off mainnet: each delay at most 30 days, the quarantine at most 730, the freeze never 0. */
export function delaysRefusal(d: HandleAnchorDelays): string | null {
  for (const key of ['changeDelay', 'freezeDuration', 'safeDelay'] as const) {
    if (d[key] > HANDLE_ANCHOR_MAX_DELAY) return `${HANDLE_ANCHOR_DELAY_ENV[key]} ${d[key]} exceeds the contract's ${HANDLE_ANCHOR_MAX_DELAY} (30 days)`;
  }
  if (d.quarantine > HANDLE_ANCHOR_MAX_QUARANTINE) {
    return `${HANDLE_ANCHOR_DELAY_ENV.quarantine} ${d.quarantine} exceeds the contract's ${HANDLE_ANCHOR_MAX_QUARANTINE} (730 days)`;
  }
  if (d.freezeDuration === 0n) return `${HANDLE_ANCHOR_DELAY_ENV.freezeDuration} is never 0: a hold that freezes nothing`;
  return null;
}

/**
 * Decision 0086's values, the only delays a Base mainnet anchor takes (72 h,
 * 14 d, 365 d, 72 h). The contract enforces the same on chain 8453; the
 * mainnet script, written once the Ledger and the production Safe exist,
 * checks them with this before it spends gas.
 */
export function mainnetDelaysRefusal(d: HandleAnchorDelays): string | null {
  const wrong = (Object.keys(HANDLE_ANCHOR_MAINNET) as (keyof HandleAnchorDelays)[]).filter((k) => d[k] !== HANDLE_ANCHOR_MAINNET[k]);
  if (wrong.length === 0) return null;
  return `On Base mainnet the anchor takes decision 0086's delays only: ${wrong.map((k) => `${k} ${d[k]}, not ${HANDLE_ANCHOR_MAINNET[k]}`).join('; ')}`;
}

/** The registrar: the plane's own hot key (ruling P), one address. */
export function registrarFrom(env: NodeJS.ProcessEnv): string {
  const raw = env.HANDLE_REGISTRAR_ADDRESS?.trim();
  if (!raw || !ethers.isAddress(raw)) {
    throw new Error(
      `HANDLE_REGISTRAR_ADDRESS is required: the address of the plane's registrar key (its own hot key, never the relayer's or the deployer's); got ${raw || 'nothing'}`,
    );
  }
  if (same(raw, ethers.ZeroAddress)) throw new Error('HANDLE_REGISTRAR_ADDRESS is the zero address');
  return ethers.getAddress(raw);
}

/** Why `safe` may not own the anchor, or null: a Safe v1.4.1 proxy on this chain, not the deployer. */
export function safeRefusal(safe: string, facts: SafeFacts | null, deployer: string): string | null {
  if (same(safe, deployer)) return `The anchor's owner ${safe} is the deployer: the anchor is owned by a Safe from its first block, and the deployer holds no role`;
  if (!facts) return `No Safe at ${safe} on this chain (create one: yarn safe:create:sepolia)`;
  if (!same(facts.singleton, SAFE_V141.singletonL2) && !same(facts.singleton, SAFE_V141.singleton)) {
    return `${safe} is not a Safe v1.4.1 proxy (singleton ${facts.singleton})`;
  }
  if (facts.threshold < 1n || facts.owners.length === 0) return `The Safe ${safe} has no owners or a zero threshold`;
  return null;
}

/**
 * Why `registrar` may not be listed, or null. Ruling P: the plane's own hot
 * key, never the relayer's key (the paymaster's `relayer`, RELAYER_ADDRESS),
 * never the deployer, never the CofferdamDev wallet, never the Safe or one of
 * its signers, and an EOA, since the anchor recovers its ECDSA signatures.
 */
export function registrarRefusal(o: {
  registrar: string;
  deployer: string;
  safe: string;
  safeOwners: string[];
  relayers: string[];
  registrarHasCode: boolean;
}): string | null {
  const r = o.registrar;
  if (same(r, o.deployer)) return `The registrar ${r} is the deployer: the deployer holds no role after the deploy`;
  if (same(r, DEV_KEY_EXCEPTION.signer)) return `The registrar ${r} is the CofferdamDev wallet: the registrar is the plane's own hot key`;
  if (o.relayers.some((x) => same(x, r))) return `The registrar ${r} is the plane's relayer: the registrar is a key of its own`;
  if (same(r, o.safe)) return `The registrar ${r} is the Safe that owns the anchor`;
  if (o.safeOwners.some((x) => same(x, r))) return `The registrar ${r} signs for the Safe that owns the anchor: the hot key and the cold Safe stay apart`;
  if (o.registrarHasCode) return `The registrar ${r} has code: the anchor recovers a registrar's ECDSA signature, so it is an EOA`;
  return null;
}

export const HANDLE_ANCHOR_DEPLOY_ABI = [
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function isRegistrar(address) view returns (bool)',
  'function CHANGE_DELAY() view returns (uint256)',
  'function FREEZE_DURATION() view returns (uint256)',
  'function QUARANTINE() view returns (uint256)',
  'function SAFE_DELAY() view returns (uint256)',
  'function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)',
];

export interface HandleAnchorDeployment {
  chainId: bigint;
  address: string;
  txHash: string;
  blockNumber: number;
  deployer: string;
  safe: string;
  registrar: string;
  delays: HandleAnchorDelays;
}

/**
 * Check everything, then deploy (unless `dryRun`, which estimates the gas and
 * stops), then read the anchor back at the block that mined it: the delays,
 * the Safe as owner with no pending owner, the registrar listed, the deployer
 * neither owner nor registrar, and the EIP-712 domain the plane signs under.
 * Returns null on a dry run.
 */
export async function deployHandleAnchor(o: {
  /** CofferdamHandleAnchor's factory, connected to the deployer. */
  factory: ethers.ContractFactory;
  deployer: ethers.Signer;
  provider: ethers.Provider;
  /** The node is a local development node (scripts/lib/chain.ts `isLocalFork`). */
  localDevNode: boolean;
  env: NodeJS.ProcessEnv;
  /** The Safe that owns the anchor from its first block. */
  safe: string;
  readSafe: (address: string) => Promise<SafeFacts | null>;
  /** Keys the registrar may never be: the plane's relayer. */
  relayers: string[];
  /** The anchor the deployments file already records, if any. */
  recordedAnchor?: string;
  dryRun?: boolean;
  log?: (line: string) => void;
}): Promise<HandleAnchorDeployment | null> {
  const log = o.log ?? (() => {});
  const chainId = (await o.provider.getNetwork()).chainId;
  const chain = chainRefusal(chainId, o.localDevNode);
  if (chain) throw new Error(chain);

  const deployer = ethers.getAddress(await o.deployer.getAddress());
  const delays = sepoliaDelaysFrom(o.env);
  const registrar = registrarFrom(o.env);
  if (!ethers.isAddress(o.safe)) throw new Error(`The Safe ${o.safe} is not an address`);
  const safe = ethers.getAddress(o.safe);
  const facts = await o.readSafe(safe);
  const safeRefused = safeRefusal(safe, facts, deployer);
  if (safeRefused) throw new Error(safeRefused);
  const registrarRefused = registrarRefusal({
    registrar,
    deployer,
    safe,
    safeOwners: facts!.owners,
    relayers: o.relayers,
    registrarHasCode: (await o.provider.getCode(registrar)) !== '0x',
  });
  if (registrarRefused) throw new Error(registrarRefused);
  if (o.recordedAnchor && o.env.HANDLE_ANCHOR_REDEPLOY?.trim() !== '1') {
    throw new Error(
      `The deployments file already records CofferdamHandleAnchor at ${o.recordedAnchor}: a new anchor strands every handle claimed on it; set HANDLE_ANCHOR_REDEPLOY=1 to replace it`,
    );
  }

  log(`  owner (Safe): ${safe} (owners ${facts!.owners.join(', ')}; threshold ${facts!.threshold})`);
  if (facts!.owners.some((x) => same(x, deployer))) {
    log('  the deployer signs for the Safe (a test Safe, as zkp-test-1\'s); it holds no role on the anchor itself');
  }
  log(`  registrar: ${registrar}`);
  for (const key of Object.keys(delays) as (keyof HandleAnchorDelays)[]) log(`  ${key}: ${delays[key]} s`);

  const args = [safe, delays.changeDelay, delays.freezeDuration, delays.quarantine, delays.safeDelay, [registrar]] as const;
  if (o.dryRun) {
    const tx = await o.factory.getDeployTransaction(...args);
    const gas = await o.provider.estimateGas({ ...tx, from: deployer });
    log(`DRY RUN: the deploy would take about ${gas} gas; nothing sent`);
    return null;
  }

  const contract = await o.factory.deploy(...args);
  const sent = contract.deploymentTransaction();
  if (!sent) throw new Error('The factory returned no deployment transaction');
  const receipt = await sent.wait();
  if (!receipt || receipt.status !== 1 || !receipt.contractAddress) throw new Error(`The deploy ${sent.hash} did not create a contract`);
  const address = ethers.getAddress(receipt.contractAddress);
  log(`CofferdamHandleAnchor: ${address} (tx ${receipt.hash}, block ${receipt.blockNumber}, gas ${receipt.gasUsed})`);

  // Read back at the block that mined it.
  const anchor = new ethers.Contract(address, HANDLE_ANCHOR_DEPLOY_ABI, o.provider);
  const at = { blockTag: receipt.blockNumber };
  const expect = (what: string, actual: unknown, wanted: unknown) => {
    const a = typeof actual === 'string' ? actual.toLowerCase() : actual;
    const w = typeof wanted === 'string' ? wanted.toLowerCase() : wanted;
    if (a !== w) throw new Error(`The deployed anchor ${address} reads ${what} ${actual}, expected ${wanted}`);
  };
  expect('CHANGE_DELAY', await anchor.CHANGE_DELAY(at), delays.changeDelay);
  expect('FREEZE_DURATION', await anchor.FREEZE_DURATION(at), delays.freezeDuration);
  expect('QUARANTINE', await anchor.QUARANTINE(at), delays.quarantine);
  expect('SAFE_DELAY', await anchor.SAFE_DELAY(at), delays.safeDelay);
  expect('owner', await anchor.owner(at), safe);
  expect('pendingOwner', await anchor.pendingOwner(at), ethers.ZeroAddress);
  expect('isRegistrar(registrar)', await anchor.isRegistrar(registrar, at), true);
  expect('isRegistrar(deployer)', await anchor.isRegistrar(deployer, at), false);
  const domain = await anchor.eip712Domain(at);
  expect('the EIP-712 name', domain.name, HANDLE_ANCHOR_DOMAIN_NAME);
  expect('the EIP-712 version', domain.version, HANDLE_ANCHOR_DOMAIN_VERSION);
  expect('the EIP-712 chainId', domain.chainId, chainId);
  expect('the EIP-712 verifyingContract', domain.verifyingContract, address);
  log('  read back: delays, owner = the Safe, no pending owner, the registrar listed, the deployer no role, the EIP-712 domain');

  return { chainId, address, txHash: receipt.hash, blockNumber: receipt.blockNumber, deployer, safe, registrar, delays };
}

/**
 * The deployments file's entries: the anchor with its creation transaction,
 * block and deployer (the plane scans from that block; verify.ts finds the
 * creation by its hash), and the anchor's Safe under its own key, as
 * safe-exec.ts's `anchor-*` actions read it.
 */
export function handleAnchorEntries(d: HandleAnchorDeployment): Record<string, Record<string, string | number>> {
  return {
    CofferdamHandleAnchor: { address: d.address, txHash: d.txHash, blockNumber: d.blockNumber, deployer: d.deployer },
    CofferdamHandleAnchorSafe: { address: d.safe },
  };
}

/** Merge the entries into the deployments file at `file`, keeping every other entry, as scripts/lib/deployments.ts writes it. */
export function recordHandleAnchor(file: string, d: HandleAnchorDeployment): void {
  const registry = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  Object.assign(registry, handleAnchorEntries(d));
  fs.writeFileSync(file, JSON.stringify(registry, null, 2) + '\n');
}

/** The plane's variables for this anchor (cofferdam-api: the anchor it reads and the block its scans start from). */
export function planeEnvLines(d: HandleAnchorDeployment): string[] {
  return [`HANDLE_ANCHOR_ADDRESS=${d.address}`, `HANDLE_ANCHOR_FROM_BLOCK=${d.blockNumber}`];
}
