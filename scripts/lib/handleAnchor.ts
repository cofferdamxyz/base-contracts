// CofferdamHandleAnchor (workspace decision 0086, rule 3): its EIP-712 types,
// its mainnet values and the Safe actions of scripts/safe-exec.ts.
// Imports nothing from Hardhat, so the tests call it without a network.

import { ethers } from 'ethers';

/** Decision 0086's delays, in seconds: the only values the constructor accepts on chain 8453. */
export const HANDLE_ANCHOR_MAINNET = {
  changeDelay: 72n * 3600n,
  freezeDuration: 14n * 24n * 3600n,
  quarantine: 365n * 24n * 3600n,
  safeDelay: 72n * 3600n,
} as const;

/** `handleId = keccak256("cofferdam-handle-v1:" ‖ label)`, the label ENSIP-15 normalised, without `@` (0086 rule 2). */
export function handleId(label: string): string {
  if (!label || label.startsWith('@')) throw new Error(`A handle label without @; got ${label || 'nothing'}`);
  return ethers.keccak256(ethers.toUtf8Bytes(`cofferdam-handle-v1:${label}`));
}

/** The anchor's EIP-712 domain name and version, as the SDK's `identity/handle.ts` (runbook step 1) has them. */
export const HANDLE_ANCHOR_DOMAIN_NAME = 'CofferdamHandleAnchor';
export const HANDLE_ANCHOR_DOMAIN_VERSION = '1';

export function handleAnchorDomain(chainId: bigint, verifyingContract: string): ethers.TypedDataDomain {
  return { name: HANDLE_ANCHOR_DOMAIN_NAME, version: HANDLE_ANCHOR_DOMAIN_VERSION, chainId, verifyingContract };
}

const f = (name: string, type: string) => ({ name, type }) as const;

/**
 * Every signed struct of the anchor, copied from the SDK's
 * `HANDLE_ANCHOR_TYPES` (cofferdam-sdk `packages/core/src/identity/handle.ts`,
 * runbook step 1), which owns them. `nonce` is the record's one per-handle
 * counter; `pendingNonce` names a pending change; `frozenUntil` names a
 * freeze. The contract's `*_TYPEHASH` constants are the keccak256 of these
 * encodings, and test/handle-anchor.test.ts pins both against the SDK's
 * fixture test/fixtures/handleAnchorTypes.json.
 */
export const HANDLE_ANCHOR_TYPES = {
  RegistrarClaim: [f('handleId', 'bytes32'), f('owner', 'address'), f('serial', 'uint64'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  OwnerClaim: [f('handleId', 'bytes32'), f('metaAddress', 'bytes'), f('serial', 'uint64')],
  TransferOwner: [f('handleId', 'bytes32'), f('newOwner', 'address'), f('newMetaAddress', 'bytes'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  TransferOwnerAccept: [f('handleId', 'bytes32'), f('previousOwner', 'address'), f('newMetaAddress', 'bytes'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  SetMetaAddress: [f('handleId', 'bytes32'), f('newMetaAddress', 'bytes'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  Release: [f('handleId', 'bytes32'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  Cancel: [f('handleId', 'bytes32'), f('pendingNonce', 'uint256'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  Advance: [f('handleId', 'bytes32'), f('newOwner', 'address'), f('newMetaAddress', 'bytes'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  AdvanceAccept: [f('handleId', 'bytes32'), f('previousOwner', 'address'), f('newMetaAddress', 'bytes'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  RegistrarAdvance: [
    f('handleId', 'bytes32'),
    f('previousOwner', 'address'),
    f('newOwner', 'address'),
    f('newMetaAddress', 'bytes'),
    f('nonce', 'uint256'),
    f('deadline', 'uint64'),
  ],
  Hold: [f('handleId', 'bytes32'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  RenewHold: [f('handleId', 'bytes32'), f('frozenUntil', 'uint64'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  Veto: [f('handleId', 'bytes32'), f('pendingNonce', 'uint256'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  // ASSUMPTION(0086 q15): unfreeze exists, signed by the owner and a registrar.
  Unfreeze: [f('handleId', 'bytes32'), f('frozenUntil', 'uint64'), f('nonce', 'uint256'), f('deadline', 'uint64')],
  RegistrarUnfreeze: [f('handleId', 'bytes32'), f('frozenUntil', 'uint64'), f('nonce', 'uint256'), f('deadline', 'uint64')],
} as const;

export type HandleAnchorType = keyof typeof HANDLE_ANCHOR_TYPES;

/** `Name(type name,...)`, the EIP-712 encodeType of one struct (none references another). */
export function encodeType(name: HandleAnchorType): string {
  return `${name}(${HANDLE_ANCHOR_TYPES[name].map((f) => `${f.type} ${f.name}`).join(',')})`;
}

/** The types object for one primary type, as `signTypedData` wants it. */
export function typesFor(name: HandleAnchorType): Record<string, ethers.TypedDataField[]> {
  return { [name]: HANDLE_ANCHOR_TYPES[name].map((f) => ({ ...f })) };
}

/** Why `meta` is not a scheme 1 meta-address the anchor accepts, or null: 66 bytes, both keys prefixed 0x02 or 0x03. */
export function metaAddressRefusal(meta: string): string | null {
  if (!ethers.isHexString(meta)) return 'not hex';
  const bytes = ethers.getBytes(meta);
  if (bytes.length !== 66) return `${bytes.length} bytes, not 66`;
  if (![2, 3].includes(bytes[0]) || ![2, 3].includes(bytes[33])) return 'a key is not a compressed secp256k1 point (prefix 0x02 or 0x03)';
  return null;
}

// ── The Safe's actions (scripts/safe-exec.ts) ───────────────────────────────

export const ANCHOR_SAFE_ACTIONS = [
  'anchor-registrar-schedule',
  'anchor-registrar-add',
  'anchor-registrar-remove',
  'anchor-rekey-schedule',
  'anchor-rekey',
  'anchor-force-release-schedule',
  'anchor-force-release',
  'anchor-cancel-op',
  'anchor-lift-freeze',
  'anchor-transfer-ownership',
  'anchor-accept-ownership',
] as const;
export type AnchorSafeAction = (typeof ANCHOR_SAFE_ACTIONS)[number];

export function isAnchorSafeAction(action: string): action is AnchorSafeAction {
  return (ANCHOR_SAFE_ACTIONS as readonly string[]).includes(action);
}

/** One anchor call the Safe makes: the function, its arguments, and the op id it schedules or consumes, if any. */
export type AnchorCall = { fn: string; args: unknown[]; describe: string };

function addressFrom(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name]?.trim();
  if (!v || !ethers.isAddress(v)) throw new Error(`${name} is required: an address; got ${v || 'nothing'}`);
  return ethers.getAddress(v);
}

function handleIdFrom(env: NodeJS.ProcessEnv): string {
  const id = env.HANDLE_ID?.trim();
  const label = env.HANDLE_LABEL?.trim();
  if (id && label) {
    if (handleId(label).toLowerCase() !== id.toLowerCase()) throw new Error(`HANDLE_ID ${id} is not the handleId of ${label}`);
    return id;
  }
  if (label) return handleId(label);
  if (id && /^0x[0-9a-fA-F]{64}$/.test(id)) return id;
  throw new Error('HANDLE_LABEL (the label, without @) or HANDLE_ID (a bytes32) is required');
}

function metaFrom(env: NodeJS.ProcessEnv): string {
  const meta = env.META_ADDRESS?.trim();
  if (!meta) throw new Error('META_ADDRESS is required: the 66-byte scheme 1 meta-address, 0x-hex');
  const refusal = metaAddressRefusal(meta);
  if (refusal) throw new Error(`META_ADDRESS: ${refusal}`);
  return meta;
}

function quarantineFrom(env: NodeJS.ProcessEnv): boolean {
  const v = env.QUARANTINE?.trim() ?? '';
  if (v === '' || v === '1') return true;
  if (v === '0') return false;
  throw new Error(`QUARANTINE is 1 (quarantine the label, the default) or 0 (waive it, for the rightful holder); got ${v}`);
}

/**
 * The anchor call for a Safe action, from the environment:
 *   REGISTRAR                       anchor-registrar-schedule / -add / -remove
 *   HANDLE_LABEL or HANDLE_ID       the rekey, force-release and lift-freeze actions
 *   NEW_OWNER, META_ADDRESS         anchor-rekey-schedule / anchor-rekey
 *   QUARANTINE 1 (default) or 0     anchor-force-release-schedule / anchor-force-release
 *   SAFE_OP_ID                      anchor-cancel-op
 *   NEW_SAFE                        anchor-transfer-ownership
 */
export function anchorCall(action: AnchorSafeAction, env: NodeJS.ProcessEnv): AnchorCall {
  switch (action) {
    case 'anchor-registrar-schedule': {
      const r = addressFrom(env, 'REGISTRAR');
      return { fn: 'scheduleAddRegistrar', args: [r], describe: `scheduleAddRegistrar(${r})` };
    }
    case 'anchor-registrar-add': {
      const r = addressFrom(env, 'REGISTRAR');
      return { fn: 'executeAddRegistrar', args: [r], describe: `executeAddRegistrar(${r})` };
    }
    case 'anchor-registrar-remove': {
      const r = addressFrom(env, 'REGISTRAR');
      return { fn: 'removeRegistrar', args: [r], describe: `removeRegistrar(${r})` };
    }
    case 'anchor-rekey-schedule':
    case 'anchor-rekey': {
      const id = handleIdFrom(env);
      const owner = addressFrom(env, 'NEW_OWNER');
      const meta = metaFrom(env);
      const fn = action === 'anchor-rekey' ? 'executeRekey' : 'scheduleRekey';
      return { fn, args: [id, owner, meta], describe: `${fn}(${id}, ${owner}, ${meta})` };
    }
    case 'anchor-force-release-schedule':
    case 'anchor-force-release': {
      const id = handleIdFrom(env);
      const q = quarantineFrom(env);
      const fn = action === 'anchor-force-release' ? 'executeForceRelease' : 'scheduleForceRelease';
      return { fn, args: [id, q], describe: `${fn}(${id}, quarantine ${q})` };
    }
    case 'anchor-cancel-op': {
      const op = env.SAFE_OP_ID?.trim();
      if (!op || !/^0x[0-9a-fA-F]{64}$/.test(op)) throw new Error(`SAFE_OP_ID is required: the bytes32 op id; got ${op || 'nothing'}`);
      return { fn: 'cancelSafeOp', args: [op], describe: `cancelSafeOp(${op})` };
    }
    case 'anchor-lift-freeze': {
      const id = handleIdFrom(env);
      return { fn: 'liftFreeze', args: [id], describe: `liftFreeze(${id})` };
    }
    case 'anchor-transfer-ownership': {
      const s = addressFrom(env, 'NEW_SAFE');
      return { fn: 'transferOwnership', args: [s], describe: `transferOwnership(${s})` };
    }
    case 'anchor-accept-ownership':
      return { fn: 'acceptOwnership', args: [], describe: 'acceptOwnership()' };
  }
}
