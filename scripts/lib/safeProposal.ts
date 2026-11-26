// Owner actions through a Safe whose threshold is 2 or more (the company Safe,
// 2-of-3; the founder's ruling of 2026-11-26): scripts/safe-propose.ts builds
// one call for an action, writes it as a Safe Transaction Builder file the
// Safe{Wallet} app imports, and prints the Safe transaction hash for the
// nonce, so the owners sign it in the app with their hardware wallets and the
// phone; scripts/safe-readback.ts then checks the effect once it is executed.
// scripts/safe-exec.ts stays the threshold-1 path (zkp-test-1's throwaway Safe).
//
// Takes an ethers provider, never Hardhat's, so the fork test drives it
// without the scripts. Signs nothing and holds no key.

import { ethers } from 'ethers';
import { SAFE_V141, type SafeFacts } from './devKeyException';
import { ANCHOR_SAFE_ACTIONS, AnchorSafeAction, anchorCall, isAnchorSafeAction } from './handleAnchor';
import { HANDLE_ANCHOR_EXEC_ABI } from './handleAnchorExec';
import { zkpCircuitsVersion } from './identity';
import { RELAY_PAYMASTER, parseWei, relayPaymasterMaxCost, relayerRefusal } from './relayPaymaster';
import { ADAPTER_CONTRACT, type AdapterKind, activationRefusal, adapterKeyForVersion, parseAllowed, reproposalRefusal } from './safe';

// ── The Safe transaction (Safe v1.4.1, EIP-712) ─────────────────────────────

export const SAFE_TX_TYPES = {
  SafeTx: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' },
    { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
};

export type SafeTx = {
  to: string;
  value: bigint;
  data: string;
  operation: 0;
  safeTxGas: bigint;
  baseGas: bigint;
  gasPrice: bigint;
  gasToken: string;
  refundReceiver: string;
  nonce: bigint;
};

/**
 * A plain call from the Safe, as Safe{Wallet} builds it for a one-transaction
 * batch: operation CALL, no gas refund (safeTxGas, baseGas, gasPrice 0, no gas
 * token or refund receiver).
 */
export function safeCallTx(to: string, value: bigint, data: string, nonce: bigint): SafeTx {
  return {
    to: ethers.getAddress(to),
    value,
    data: ethers.hexlify(data),
    operation: 0,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: ethers.ZeroAddress,
    refundReceiver: ethers.ZeroAddress,
    nonce,
  };
}

export const safeTxDomain = (chainId: bigint, safe: string) => ({ chainId, verifyingContract: ethers.getAddress(safe) });

/** `getTransactionHash` of Safe v1.4.1: the EIP-712 hash the owners sign. */
export function safeTxHash(chainId: bigint, safe: string, tx: SafeTx): string {
  return ethers.TypedDataEncoder.hash(safeTxDomain(chainId, safe), SAFE_TX_TYPES, tx);
}

/** The two hashes a hardware wallet shows when it signs the Safe transaction blind. */
export function safeTxHashParts(chainId: bigint, safe: string, tx: SafeTx): { domainHash: string; messageHash: string } {
  return {
    domainHash: ethers.TypedDataEncoder.hashDomain(safeTxDomain(chainId, safe)),
    messageHash: ethers.TypedDataEncoder.from(SAFE_TX_TYPES).hash(tx),
  };
}

/**
 * The `signatures` argument of `execTransaction`: each owner's 65-byte EIP-712
 * signature (r, s, v with v 27 or 28), ordered by owner address ascending, as
 * the Safe requires. Each signature is checked to recover to its owner.
 */
export function packSafeSignatures(hash: string, sigs: Array<{ owner: string; signature: string }>): string {
  const seen = new Set<string>();
  const sorted = [...sigs].sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : BigInt(a.owner) > BigInt(b.owner) ? 1 : 0));
  for (const { owner, signature } of sorted) {
    if (seen.has(owner.toLowerCase())) throw new Error(`Two signatures by ${owner}`);
    seen.add(owner.toLowerCase());
    if (ethers.getBytes(signature).length !== 65) throw new Error(`The signature by ${owner} is not 65 bytes`);
    if (ethers.recoverAddress(hash, signature).toLowerCase() !== owner.toLowerCase()) throw new Error(`The signature does not recover to ${owner}`);
  }
  return ethers.concat(sorted.map((s) => s.signature));
}

// ── The Safe Transaction Builder file (Safe{Wallet}'s import format) ────────

export interface BatchTransaction {
  to: string;
  value: string;
  data: string;
}
export interface BatchFile {
  version: string;
  chainId: string;
  createdAt: number;
  meta: { name: string; description: string; createdFromSafeAddress: string; checksum?: string };
  transactions: BatchTransaction[];
}

/** The Transaction Builder's deterministic serialisation (safe-react-apps, tx-builder `lib/checksum.ts`). */
function serializeJSONObject(json: unknown): string {
  const replacer = (_: string, value: unknown) => (value === undefined ? null : value);
  if (Array.isArray(json)) return `[${json.map((el) => serializeJSONObject(el)).join(',')}]`;
  if (typeof json === 'object' && json !== null) {
    const keys = Object.keys(json).sort();
    let acc = `{${JSON.stringify(keys, replacer)}`;
    for (const key of keys) acc += `${serializeJSONObject((json as Record<string, unknown>)[key])},`;
    return `${acc}}`;
  }
  return `${JSON.stringify(json, replacer)}`;
}

/** The checksum the Transaction Builder checks on import: keccak256 of the file, its name nulled and its checksum left out. */
export function txBuilderChecksum(file: BatchFile): string {
  const { checksum: _omit, ...meta } = file.meta;
  return ethers.keccak256(ethers.toUtf8Bytes(serializeJSONObject({ ...file, meta: { ...meta, name: null } })));
}

/** A one-transaction batch for the Safe at `safe`, with its checksum. */
export function txBuilderFile(o: { chainId: bigint; safe: string; createdAt: number; name: string; description: string; tx: BatchTransaction }): BatchFile {
  const file: BatchFile = {
    version: '1.0',
    chainId: o.chainId.toString(),
    createdAt: o.createdAt,
    meta: { name: o.name, description: o.description, createdFromSafeAddress: ethers.getAddress(o.safe) },
    transactions: [{ to: ethers.getAddress(o.tx.to), value: o.tx.value, data: o.tx.data }],
  };
  file.meta.checksum = txBuilderChecksum(file);
  return file;
}

// ── Read-back checks, run after the owners execute ──────────────────────────

/**
 * `call`: a view call at the execution's block, its return decoded as
 * `returns` and element `index` compared (`eq` or `ne`) with `value` (an
 * address lowercased, a number in decimal, a bool as true/false, bytes as
 * lowercase hex). `event`: a log in the execution's receipt from `address`
 * whose topics start with `topics`.
 */
export type ReadbackCheck =
  | { kind: 'call'; label: string; to: string; data: string; returns: string[]; index: number; op: 'eq' | 'ne'; value: string }
  | { kind: 'event'; label: string; address: string; topics: string[] };

const norm = (v: unknown): string =>
  typeof v === 'string' ? v.toLowerCase() : typeof v === 'bigint' ? v.toString() : typeof v === 'boolean' ? String(v) : String(v);

function callCheck(label: string, to: string, iface: ethers.Interface, fn: string, args: unknown[], op: 'eq' | 'ne', value: unknown, index = 0): ReadbackCheck {
  const f = iface.getFunction(fn, args);
  if (!f) throw new Error(`No ${fn} in the ABI`);
  return {
    kind: 'call',
    label,
    to: ethers.getAddress(to),
    data: iface.encodeFunctionData(f, args),
    returns: f.outputs.map((o) => o.format('sighash')),
    index,
    op,
    value: norm(value),
  };
}

/** One proposal: the Safe transaction, its hash, the import file and the checks. */
export interface SafeProposal {
  kind: 'cofferdam-safe-proposal-v1';
  action: string;
  describe: string;
  chainId: string;
  safe: string;
  nonce: string;
  safeTxHash: string;
  domainHash: string;
  messageHash: string;
  tx: { to: string; value: string; data: string; operation: 0 };
  checks: ReadbackCheck[];
}

export const SAFE_EXEC_EVENTS = [
  'event ExecutionSuccess(bytes32 indexed txHash, uint256 payment)',
  'event ExecutionFailure(bytes32 indexed txHash, uint256 payment)',
];

/**
 * Check a proposal after the owners executed it: `execTxHash`'s receipt holds
 * the Safe's `ExecutionSuccess` for this proposal's hash, then every check
 * passes at that block. Throws on the first failure; returns the block.
 */
export async function runReadback(
  provider: ethers.Provider,
  proposal: SafeProposal,
  execTxHash: string,
  log: (line: string) => void = () => {},
): Promise<number> {
  const receipt = await provider.getTransactionReceipt(execTxHash);
  if (!receipt) throw new Error(`No receipt for ${execTxHash} on this chain`);
  if (receipt.status !== 1) throw new Error(`${execTxHash} reverted`);
  const events = new ethers.Interface(SAFE_EXEC_EVENTS);
  const success = events.getEvent('ExecutionSuccess')!.topicHash;
  const failure = events.getEvent('ExecutionFailure')!.topicHash;
  const fromSafe = receipt.logs.filter((l) => l.address.toLowerCase() === proposal.safe.toLowerCase());
  const ours = (topic: string) => fromSafe.some((l) => l.topics[0] === topic && l.topics[1]?.toLowerCase() === proposal.safeTxHash.toLowerCase());
  if (ours(failure)) throw new Error(`${execTxHash} executed the Safe transaction ${proposal.safeTxHash} and it FAILED (ExecutionFailure)`);
  if (!ours(success)) throw new Error(`${execTxHash} holds no ExecutionSuccess of ${proposal.safe} for ${proposal.safeTxHash}: not this proposal's execution`);
  const block = receipt.blockNumber;
  log(`  ${proposal.safeTxHash} executed in ${execTxHash} (block ${block})`);
  const coder = ethers.AbiCoder.defaultAbiCoder();
  for (const c of proposal.checks) {
    if (c.kind === 'call') {
      const raw = await provider.call({ to: c.to, data: c.data, blockTag: block });
      const got = norm(coder.decode(c.returns, raw)[c.index]);
      const pass = c.op === 'eq' ? got === c.value : got !== c.value;
      if (!pass) throw new Error(`${c.label}: read ${got}, expected ${c.op === 'eq' ? '' : 'not '}${c.value}`);
      log(`  ${c.label}: ${got}`);
    } else {
      const hit = receipt.logs.some(
        (l) => l.address.toLowerCase() === c.address.toLowerCase() && c.topics.every((t, i) => l.topics[i]?.toLowerCase() === t.toLowerCase()),
      );
      if (!hit) throw new Error(`${c.label}: no such event in ${execTxHash}`);
      log(`  ${c.label}: in the receipt`);
    }
  }
  return block;
}

// ── The actions ─────────────────────────────────────────────────────────────

export const PAYMASTER_SAFE_ACTIONS = [
  'paymaster-set-relayer',
  'paymaster-pause',
  'paymaster-unpause',
  'paymaster-set-max-cost',
  'paymaster-withdraw',
  'paymaster-deposit',
  'paymaster-transfer-ownership',
  'paymaster-cancel-ownership-transfer',
  'paymaster-accept-ownership',
] as const;
export const IDENTITY_PROPOSE_ACTIONS = ['pause', 'unpause', 'set-test-account', 'adapter-propose', 'adapter-activate', 'adapter-cancel'] as const;
/** What safe-propose.ts takes. safe-exec's drills are two transactions each: propose their steps one by one. */
export const PROPOSE_ACTIONS = [...IDENTITY_PROPOSE_ACTIONS, ...ANCHOR_SAFE_ACTIONS, ...PAYMASTER_SAFE_ACTIONS] as const;
export type ProposeAction = (typeof PROPOSE_ACTIONS)[number];

export function parseProposeAction(value: string | undefined): ProposeAction {
  const action = value?.trim();
  if (action === 'pause-drill') throw new Error('pause-drill is two Safe transactions: propose SAFE_ACTION=pause, then SAFE_ACTION=unpause');
  if (action === 'adapter-drill') {
    throw new Error('adapter-drill is two Safe transactions: propose SAFE_ACTION=adapter-propose, then SAFE_ACTION=adapter-cancel, for a recorded copy');
  }
  if (!action || !(PROPOSE_ACTIONS as readonly string[]).includes(action)) {
    throw new Error(`SAFE_ACTION is one of ${PROPOSE_ACTIONS.join(', ')}; got ${action || 'nothing'}`);
  }
  return action as ProposeAction;
}

/** The contract an action calls, its deployments-file key and the Safe it is owned by. */
export function actionTarget(action: ProposeAction): { key: string; env: string; safeKeys: string[] } {
  if ((PAYMASTER_SAFE_ACTIONS as readonly string[]).includes(action)) return { key: RELAY_PAYMASTER, env: 'RELAY_PAYMASTER', safeKeys: ['CofferdamSafe'] };
  if (isAnchorSafeAction(action)) return { key: 'CofferdamHandleAnchor', env: 'HANDLE_ANCHOR', safeKeys: ['CofferdamHandleAnchorSafe', 'CofferdamSafe'] };
  return { key: 'CofferdamIdentityRegistry', env: 'IDENTITY_REGISTRY', safeKeys: ['CofferdamSafe'] };
}

/** The Safe's call for an action: what it sends, a description, and its read-back. */
export interface SafeCall {
  to: string;
  value: bigint;
  data: string;
  describe: string;
  checks: ReadbackCheck[];
  notes: string[];
}

export interface BuildContext {
  action: ProposeAction;
  env: NodeJS.ProcessEnv;
  provider: ethers.Provider;
  chainId: bigint;
  safe: string;
  safeFacts: SafeFacts;
  /** The contract the action calls (the paymaster, the identity registry or the anchor). */
  target: string;
  recorded: Record<string, { address: string } | undefined>;
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export const RELAY_PAYMASTER_ABI = [
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function relayer() view returns (address)',
  'function maxCostPerOp() view returns (uint256)',
  'function paused() view returns (bool)',
  'function ENTRY_POINT() view returns (address)',
  'function setRelayer(address newRelayer)',
  'function setPaused(bool paused_)',
  'function setMaxCostPerOp(uint256 newMaxCost)',
  'function withdrawTo(address withdrawAddress, uint256 amount)',
  'function transferOwnership(address newOwner)',
  'function acceptOwnership()',
];
export const ENTRY_POINT_ABI = [
  'function balanceOf(address account) view returns (uint256)',
  'event Deposited(address indexed account, uint256 totalDeposit)',
  'event Withdrawn(address indexed account, address withdrawAddress, uint256 amount)',
];
export const IDENTITY_REGISTRY_PROPOSE_ABI = [
  'function owner() view returns (address)',
  'function paused() view returns (bool)',
  'function setPaused(bool _paused)',
  'function isTestAccount(address) view returns (bool)',
  'function setTestAccount(address account, bool allowed)',
  'function isAdapter(address) view returns (bool)',
  'function adapterReadyAt(address) view returns (uint256)',
  'function ADAPTER_GRACE() view returns (uint256)',
  'function proposeAdapter(address adapter)',
  'function activateAdapter(address adapter)',
  'function cancelAdapterProposal(address adapter)',
];
const ADAPTER_ABI = [
  'function VERSION() view returns (bytes32)',
  'function HELPER() view returns (address)',
  'function ROOT_VERIFIER() view returns (address)',
  'function vkeyHashes() view returns (bytes32[])',
  'function outerVerifier(bytes32) view returns (address)',
];
const ROOT_VERIFIER_ABI = ['function getHelper(bytes32 version) view returns (address)', 'function getSubVerifier(bytes32 version) view returns (address)'];
const SUB_VERIFIER_ABI = ['function proofVerifiers(bytes32 vkeyHash) view returns (address)'];

function envAddress(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name]?.trim();
  if (!v || !ethers.isAddress(v) || /^0x0{40}$/i.test(v)) throw new Error(`${name} is required: a non-zero address; got ${v || 'nothing'}`);
  return ethers.getAddress(v);
}

/**
 * Build the Safe's call for `ctx.action`, after checking the target is owned
 * by the Safe (or, for an acceptance, names it as pending owner) and the
 * action's own preconditions. The caller pre-flights the call from the Safe.
 */
export async function buildSafeCall(ctx: BuildContext): Promise<SafeCall> {
  if ((PAYMASTER_SAFE_ACTIONS as readonly string[]).includes(ctx.action)) return paymasterCall(ctx);
  if (isAnchorSafeAction(ctx.action)) return anchorSafeCall(ctx, ctx.action);
  return identityCall(ctx);
}

async function paymasterCall(ctx: BuildContext): Promise<SafeCall> {
  const iface = new ethers.Interface(RELAY_PAYMASTER_ABI);
  const p = new ethers.Contract(ctx.target, RELAY_PAYMASTER_ABI, ctx.provider);
  const owner: string = await p.owner();
  const accepting = ctx.action === 'paymaster-accept-ownership';
  if (accepting) {
    const pending: string = await p.pendingOwner();
    if (!same(pending, ctx.safe)) throw new Error(`The paymaster's pending owner is ${pending}, not the Safe ${ctx.safe}`);
  } else if (!same(owner, ctx.safe)) {
    throw new Error(`The paymaster ${ctx.target} is owned by ${owner}, not the Safe ${ctx.safe}`);
  }
  const mainnet = ctx.chainId === 8453n;
  const call = (fn: string, args: unknown[], describe: string, checks: ReadbackCheck[], notes: string[] = []): SafeCall => ({
    to: ctx.target,
    value: 0n,
    data: iface.encodeFunctionData(fn, args),
    describe,
    checks,
    notes,
  });
  const check = (label: string, fn: string, value: unknown, op: 'eq' | 'ne' = 'eq') => callCheck(label, ctx.target, iface, fn, [], op, value);
  const entryPoint: string = await p.ENTRY_POINT();
  const ep = new ethers.Contract(entryPoint, ENTRY_POINT_ABI, ctx.provider);
  const epIface = ep.interface;
  const paymasterTopic = ethers.zeroPadValue(ctx.target, 32);

  switch (ctx.action) {
    case 'paymaster-set-relayer': {
      const relayer = envAddress(ctx.env, 'RELAYER_ADDRESS');
      const ledger = ctx.env.LEDGER_ADDRESS?.trim() || '';
      const refusal = relayerRefusal(relayer, { owner: ctx.safe, deployer: ledger, mainnet, code: await ctx.provider.getCode(relayer) });
      if (refusal) throw new Error(refusal);
      if (ctx.safeFacts.owners.some((o) => same(o, relayer))) throw new Error(`The relayer ${relayer} is an owner of the Safe: a Safe signer is never the relayer`);
      const current: string = await p.relayer();
      if (same(current, relayer)) throw new Error(`The relayer is ${relayer} already`);
      return call('setRelayer', [relayer], `setRelayer(${relayer}) (was ${current})`, [check('relayer', 'relayer', relayer)]);
    }
    case 'paymaster-pause':
    case 'paymaster-unpause': {
      const paused = ctx.action === 'paymaster-pause';
      if ((await p.paused()) === paused) throw new Error(`The paymaster is ${paused ? 'paused' : 'unpaused'} already`);
      return call('setPaused', [paused], `setPaused(${paused})`, [check('paused', 'paused', paused)]);
    }
    case 'paymaster-set-max-cost': {
      const cap = relayPaymasterMaxCost(ctx.env.PAYMASTER_MAX_COST_WEI, { mainnet, local: false });
      const current: bigint = await p.maxCostPerOp();
      if (current === cap) throw new Error(`maxCostPerOp is ${cap} already`);
      return call('setMaxCostPerOp', [cap], `setMaxCostPerOp(${cap} wei, ${ethers.formatEther(cap)} ETH) (was ${current})`, [
        check('maxCostPerOp', 'maxCostPerOp', cap),
      ]);
    }
    case 'paymaster-withdraw': {
      const to = ctx.env.WITHDRAW_TO?.trim() ? envAddress(ctx.env, 'WITHDRAW_TO') : ethers.getAddress(ctx.safe);
      const amount = parseWei('AMOUNT_WEI', ctx.env.AMOUNT_WEI);
      const deposit: bigint = await ep.balanceOf(ctx.target);
      if (amount > deposit) throw new Error(`AMOUNT_WEI ${amount} is more than the deposit ${deposit}`);
      const notes = same(to, ctx.safe) ? [] : [`WITHDRAW_TO ${to} is not the Safe: check it on every signer's screen`];
      return call(
        'withdrawTo',
        [to, amount],
        `withdrawTo(${to}, ${amount} wei = ${ethers.formatEther(amount)} ETH) from a deposit of ${ethers.formatEther(deposit)} ETH`,
        [{ kind: 'event', label: `EntryPoint Withdrawn(${ctx.target})`, address: entryPoint, topics: [epIface.getEvent('Withdrawn')!.topicHash, paymasterTopic] }],
        notes,
      );
    }
    case 'paymaster-deposit': {
      const amount = parseWei('AMOUNT_WEI', ctx.env.AMOUNT_WEI);
      const balance = await ctx.provider.getBalance(ctx.safe);
      if (amount > balance) throw new Error(`AMOUNT_WEI ${amount} is more than the Safe's balance ${balance}`);
      return {
        to: ctx.target,
        value: amount,
        data: '0x',
        describe: `send ${amount} wei (${ethers.formatEther(amount)} ETH) to the paymaster, credited to its EntryPoint deposit`,
        checks: [{ kind: 'event', label: `EntryPoint Deposited(${ctx.target})`, address: entryPoint, topics: [epIface.getEvent('Deposited')!.topicHash, paymasterTopic] }],
        notes: [],
      };
    }
    case 'paymaster-transfer-ownership': {
      const next = envAddress(ctx.env, 'NEW_SAFE');
      if (same(next, ctx.safe)) throw new Error('NEW_SAFE is this Safe');
      return call('transferOwnership', [next], `transferOwnership(${next}) (two-step: the new Safe accepts)`, [check('pendingOwner', 'pendingOwner', next)], [
        `Then, from the new Safe: SAFE_ACTION=paymaster-accept-ownership SAFE_ADDRESS=${next}`,
      ]);
    }
    case 'paymaster-cancel-ownership-transfer': {
      const pending: string = await p.pendingOwner();
      if (pending === ethers.ZeroAddress) throw new Error('No ownership transfer is pending');
      return call('transferOwnership', [ethers.ZeroAddress], `transferOwnership(0x0): withdraws the nomination of ${pending}`, [
        check('pendingOwner', 'pendingOwner', ethers.ZeroAddress),
      ]);
    }
    case 'paymaster-accept-ownership':
      return call('acceptOwnership', [], `acceptOwnership() by ${ctx.safe} (from ${owner})`, [
        check('owner', 'owner', ctx.safe),
        check('pendingOwner', 'pendingOwner', ethers.ZeroAddress),
      ], [`Record ${ctx.safe} as the paymaster's Safe in the generation's deployments file`]);
  }
  throw new Error(`Not a paymaster action: ${ctx.action}`);
}

async function anchorSafeCall(ctx: BuildContext, action: AnchorSafeAction): Promise<SafeCall> {
  const call = anchorCall(action, ctx.env);
  const anchor = new ethers.Contract(ctx.target, HANDLE_ANCHOR_EXEC_ABI, ctx.provider);
  const iface = anchor.interface;
  const owner: string = await anchor.owner();
  if (action === 'anchor-accept-ownership') {
    const pending: string = await anchor.pendingOwner();
    if (!same(pending, ctx.safe)) throw new Error(`The anchor's pending owner is ${pending}, not the Safe ${ctx.safe}`);
  } else if (!same(owner, ctx.safe)) {
    throw new Error(`The anchor ${ctx.target} is owned by ${owner}, not the Safe ${ctx.safe}`);
  }
  const notes: string[] = [];
  const c = (label: string, fn: string, args: unknown[], value: unknown, op: 'eq' | 'ne' = 'eq', index = 0) =>
    callCheck(label, ctx.target, iface, fn, args, op, value, index);
  const checks: ReadbackCheck[] = [];
  const opIdOf = async (): Promise<string | null> => {
    if (action === 'anchor-registrar-schedule' || action === 'anchor-registrar-add') return anchor.addRegistrarOpId(call.args[0]);
    if (action === 'anchor-rekey-schedule' || action === 'anchor-rekey') return anchor.rekeyOpId(...(call.args as [string, string, string]));
    if (action === 'anchor-force-release-schedule' || action === 'anchor-force-release') return anchor.forceReleaseOpId(...(call.args as [string, boolean]));
    return null;
  };
  const opId = await opIdOf();
  if (opId && (action === 'anchor-registrar-add' || action === 'anchor-rekey' || action === 'anchor-force-release')) {
    const readyAt: bigint = await anchor.safeOpReadyAt(opId);
    if (readyAt === 0n) throw new Error(`${call.describe}: not scheduled (op ${opId}); schedule it first`);
    const grace: bigint = await anchor.SAFE_OP_GRACE();
    notes.push(`Executable from ${new Date(Number(readyAt) * 1000).toISOString()} until ${new Date(Number(readyAt + grace) * 1000).toISOString()}`);
  }
  switch (action) {
    case 'anchor-registrar-schedule':
    case 'anchor-rekey-schedule':
    case 'anchor-force-release-schedule':
      checks.push(c(`safeOpReadyAt(${opId})`, 'safeOpReadyAt', [opId], 0n, 'ne'));
      break;
    case 'anchor-registrar-add':
      checks.push(c('isRegistrar', 'isRegistrar', [call.args[0]], true));
      break;
    case 'anchor-registrar-remove':
      checks.push(c('isRegistrar', 'isRegistrar', [call.args[0]], false));
      break;
    case 'anchor-rekey':
      checks.push(c('owner', 'resolve', [call.args[0]], call.args[1], 'eq', 0), c('metaAddress', 'resolve', [call.args[0]], call.args[2], 'eq', 2));
      break;
    case 'anchor-force-release':
      checks.push(c('owner', 'resolve', [call.args[0]], ethers.ZeroAddress, 'eq', 0));
      break;
    case 'anchor-cancel-op':
      checks.push(c('safeOpReadyAt', 'safeOpReadyAt', [call.args[0]], 0n));
      break;
    case 'anchor-lift-freeze':
      checks.push(c('isFrozen', 'isFrozen', [call.args[0]], false));
      break;
    case 'anchor-transfer-ownership':
      checks.push(c('pendingOwner', 'pendingOwner', [], call.args[0]));
      break;
    case 'anchor-cancel-ownership-transfer':
      checks.push(c('pendingOwner', 'pendingOwner', [], ethers.ZeroAddress));
      break;
    case 'anchor-accept-ownership':
      checks.push(c('owner', 'owner', [], ctx.safe));
      notes.push(`Record ${ctx.safe} as CofferdamHandleAnchorSafe in the generation's deployments file`);
      break;
  }
  return { to: ctx.target, value: 0n, data: iface.encodeFunctionData(call.fn, call.args), describe: call.describe, checks, notes };
}

/** Which adapter contract is at `address`: the pepper's answers `vkeyHashes()`. */
async function adapterKind(provider: ethers.Provider, address: string): Promise<AdapterKind> {
  try {
    await new ethers.Contract(address, ADAPTER_ABI, provider).vkeyHashes();
    return 'pepper';
  } catch (e) {
    const { code, message } = e as { code?: string; message?: string };
    if (code === 'CALL_EXCEPTION' || code === 'BAD_DATA' || /execution reverted/i.test(message ?? '')) return 'root-verifier';
    throw e;
  }
}

async function identityCall(ctx: BuildContext): Promise<SafeCall> {
  const iface = new ethers.Interface(IDENTITY_REGISTRY_PROPOSE_ABI);
  const registry = new ethers.Contract(ctx.target, IDENTITY_REGISTRY_PROPOSE_ABI, ctx.provider);
  const owner: string = await registry.owner();
  if (!same(owner, ctx.safe)) throw new Error(`The registry ${ctx.target} is owned by ${owner}, not the Safe ${ctx.safe}`);
  const c = (label: string, fn: string, args: unknown[], value: unknown, op: 'eq' | 'ne' = 'eq') => callCheck(label, ctx.target, iface, fn, args, op, value);
  const call = (fn: string, args: unknown[], describe: string, checks: ReadbackCheck[], notes: string[] = []): SafeCall => ({
    to: ctx.target,
    value: 0n,
    data: iface.encodeFunctionData(fn, args),
    describe,
    checks,
    notes,
  });

  if (ctx.action === 'pause' || ctx.action === 'unpause') {
    const paused = ctx.action === 'pause';
    if ((await registry.paused()) === paused) throw new Error(`The registry is ${paused ? 'paused' : 'unpaused'} already`);
    return call('setPaused', [paused], `setPaused(${paused})`, [c('paused', 'paused', [], paused)]);
  }
  if (ctx.action === 'set-test-account') {
    const account = envAddress(ctx.env, 'ACCOUNT');
    const allowed = parseAllowed(ctx.env.ALLOWED);
    return call('setTestAccount', [account, allowed], `setTestAccount(${account}, ${allowed})`, [c('isTestAccount', 'isTestAccount', [account], allowed)]);
  }

  // The adapter actions, on a copy the generation's file records under its
  // version's key (deploying a copy is a deployer transaction, not the Safe's;
  // safe-exec.ts does it for a threshold-1 Safe only).
  const versionLabel = ctx.env.ZKP_CIRCUITS_VERSION?.trim();
  const kindEnv = ctx.env.ZKP_ADAPTER_KIND?.trim() || 'root-verifier';
  if (kindEnv !== 'root-verifier' && kindEnv !== 'pepper') throw new Error(`ZKP_ADAPTER_KIND is root-verifier (the default) or pepper; got ${kindEnv}`);
  const key = adapterKeyForVersion(versionLabel, kindEnv);
  const version = zkpCircuitsVersion(versionLabel!);
  const adapter = ctx.recorded[key]?.address;
  if (!adapter) throw new Error(`No ${key} in the generation's deployments file: the copy is deployed before the Safe proposes it`);
  const kind = await adapterKind(ctx.provider, adapter);
  if (kind !== kindEnv) throw new Error(`${key} ${adapter} is a ${ADAPTER_CONTRACT[kind]}, not a ${ADAPTER_CONTRACT[kindEnv]}`);
  const isActive: boolean = await registry.isAdapter(adapter);
  const readyAt: bigint = await registry.adapterReadyAt(adapter);
  const grace: bigint = await registry.ADAPTER_GRACE();
  const now = BigInt((await ctx.provider.getBlock('latest'))!.timestamp);

  /** The copy pins this version and RootVerifier's helper for it now, and (the pepper's) outer verifiers ZKPassport still lists. */
  const checkLive = async () => {
    const a = new ethers.Contract(adapter, ADAPTER_ABI, ctx.provider);
    const pinned: string = await a.VERSION();
    if (pinned !== version) throw new Error(`${key} ${adapter} pins another circuits version (${pinned})`);
    const root = new ethers.Contract(await a.ROOT_VERIFIER(), ROOT_VERIFIER_ABI, ctx.provider);
    const helper: string = await root.getHelper(version);
    const adapterHelper: string = await a.HELPER();
    if (!same(helper, adapterHelper)) {
      throw new Error(`${key} ${adapter} pins the helper ${adapterHelper}, but RootVerifier names ${helper} for ${versionLabel} now: it would refuse every proof`);
    }
    if (kind === 'pepper') {
      const sub = new ethers.Contract(await root.getSubVerifier(version), SUB_VERIFIER_ABI, ctx.provider);
      for (const h of (await a.vkeyHashes()) as string[]) {
        const mine: string = await a.outerVerifier(h);
        const listed: string = await sub.proofVerifiers(h);
        if (!same(mine, listed)) throw new Error(`${key} ${adapter} pins the outer verifier ${mine} for ${h}; ZKPassport lists ${listed} now`);
      }
    }
  };

  if (ctx.action === 'adapter-propose') {
    if (isActive) throw new Error(`${key} ${adapter} is active already`);
    const refusal = reproposalRefusal(readyAt, now, grace);
    if (refusal) throw new Error(`${key} ${adapter}: ${refusal}`);
    await checkLive();
    return call('proposeAdapter', [adapter], `proposeAdapter(${adapter}) (${key}; the timelock starts when it executes)`, [
      c('adapterReadyAt', 'adapterReadyAt', [adapter], 0n, 'ne'),
      c('isAdapter', 'isAdapter', [adapter], false),
    ]);
  }
  if (ctx.action === 'adapter-activate') {
    if (isActive) throw new Error(`${key} ${adapter} is active already`);
    const refusal = activationRefusal(readyAt, now, grace);
    if (refusal) throw new Error(`${key} ${adapter} cannot be activated: ${refusal}`);
    await checkLive();
    return call(
      'activateAdapter',
      [adapter],
      `activateAdapter(${adapter}) (${key})`,
      [c('isAdapter', 'isAdapter', [adapter], true), c('adapterReadyAt', 'adapterReadyAt', [adapter], 0n)],
      [`Execute by ${new Date(Number(readyAt + grace) * 1000).toISOString()}, when the proposal expires`],
    );
  }
  // adapter-cancel
  if (isActive) throw new Error(`${key} ${adapter} is active: a cancel cannot undo that`);
  if (readyAt === 0n) throw new Error(`${key} ${adapter} is not proposed`);
  return call('cancelAdapterProposal', [adapter], `cancelAdapterProposal(${adapter}) (${key})`, [c('adapterReadyAt', 'adapterReadyAt', [adapter], 0n)]);
}

// ── The Safe ────────────────────────────────────────────────────────────────

/**
 * Why safe-propose.ts may not propose through the Safe at `address`, or null:
 * a Safe v1.4.1 proxy whose threshold is 2 or more (a threshold-1 Safe is
 * safe-exec.ts's), and the recorded one when one is recorded.
 */
export function safeProposeRefusal(address: string, safe: SafeFacts | null, recorded?: string): string | null {
  if (recorded && !same(recorded, address)) return `The Safe ${address} is not the generation's recorded Safe ${recorded}`;
  if (!safe) return `No Safe at ${address} on this chain`;
  if (!same(safe.singleton, SAFE_V141.singletonL2) && !same(safe.singleton, SAFE_V141.singleton)) {
    return `${address} is not a Safe v1.4.1 proxy (singleton ${safe.singleton})`;
  }
  if (safe.threshold < 2n) return `The Safe ${address} has threshold ${safe.threshold}: one owner executes alone with safe-exec.ts`;
  return null;
}

/** The proposal's nonce: SAFE_NONCE, else the Safe's current nonce; never one already used. */
export function proposalNonce(value: string | undefined, current: bigint): bigint {
  const v = value?.trim();
  if (!v) return current;
  if (!/^[0-9]{1,20}$/.test(v)) throw new Error(`SAFE_NONCE is a Safe nonce, a decimal integer; got ${v}`);
  const n = BigInt(v);
  if (n < current) throw new Error(`SAFE_NONCE ${n} is used already: the Safe's nonce is ${current}`);
  return n;
}
