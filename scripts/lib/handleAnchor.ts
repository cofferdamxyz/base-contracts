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

export const HANDLE_ANCHOR_DOMAIN_NAME = 'Cofferdam Handle Anchor';
export const HANDLE_ANCHOR_DOMAIN_VERSION = '1';

export function handleAnchorDomain(chainId: bigint, verifyingContract: string): ethers.TypedDataDomain {
  return { name: HANDLE_ANCHOR_DOMAIN_NAME, version: HANDLE_ANCHOR_DOMAIN_VERSION, chainId, verifyingContract };
}

/**
 * Every signed struct of the anchor, as ethers' `signTypedData` takes them.
 * The contract's `*_TYPEHASH` constants are the keccak256 of these encodings;
 * test/handle-anchor.test.ts pins both against each other.
 */
export const HANDLE_ANCHOR_TYPES = {
  RegistrarClaim: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'owner', type: 'address' },
    { name: 'serial', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  OwnerClaim: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'metaAddress', type: 'bytes' },
    { name: 'serial', type: 'uint256' },
  ],
  TransferOwner: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'newOwner', type: 'address' },
    { name: 'newMetaAddress', type: 'bytes' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  SetMetaAddress: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'newMetaAddress', type: 'bytes' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Release: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Cancel: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Advance: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'newOwner', type: 'address' },
    { name: 'newMetaAddress', type: 'bytes' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Unfreeze: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Hold: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
  Veto: [
    { name: 'handleId', type: 'bytes32' },
    { name: 'changeNonce', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
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
