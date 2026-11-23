// Sending a transaction through a single-signer Safe v1.4.1 (scripts/safe-exec.ts).
// Imports nothing from Hardhat, so the tests call it without a network.

import { SAFE_V141, type SafeFacts } from './devKeyException';
import { ANCHOR_SAFE_ACTIONS } from './handleAnchor';

export const SAFE_EXEC_ABI = [
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes signatures) payable returns (bool success)',
  'function nonce() view returns (uint256)',
  'event ExecutionSuccess(bytes32 indexed txHash, uint256 payment)',
  'event ExecutionFailure(bytes32 indexed txHash, uint256 payment)',
];

/** What `SAFE_ACTION` may name: the identity registry's actions, then the handle anchor's (`anchor-*`, ./handleAnchor.ts). */
export const SAFE_ACTIONS = [
  'pause-drill', 'adapter-drill', 'adapter-propose', 'adapter-activate', 'adapter-cancel', 'set-test-account', 'pause', 'unpause',
  ...ANCHOR_SAFE_ACTIONS,
] as const;
export type SafeAction = (typeof SAFE_ACTIONS)[number];

export function parseSafeAction(value: string | undefined): SafeAction {
  const action = value?.trim();
  if (!action || !(SAFE_ACTIONS as readonly string[]).includes(action)) {
    throw new Error(`SAFE_ACTION is one of ${SAFE_ACTIONS.join(', ')}; got ${action || 'nothing'}`);
  }
  return action as SafeAction;
}

/**
 * The signature of an owner that sends `execTransaction` itself: Safe's
 * pre-validated form (v = 1), r = the owner, s = 0. The Safe accepts it
 * because msg.sender is that owner; nothing is signed off chain.
 */
export function senderOwnerSignature(owner: string): string {
  const hex = owner.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(hex)) throw new Error(`Not an address: ${owner}`);
  return '0x' + hex.padStart(64, '0') + '0'.repeat(64) + '01';
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/**
 * Why `signer` may not execute alone through the Safe at `address`, or null.
 * The Safe is a v1.4.1 proxy, lists the signer, has threshold 1 (one owner's
 * pre-validated signature is enough), and is the generation's recorded Safe
 * when one is recorded.
 */
export function safeExecRefusal(address: string, safe: SafeFacts | null, signer: string, recorded?: string): string | null {
  if (recorded && !same(recorded, address)) return `The Safe ${address} is not the generation's recorded CofferdamSafe ${recorded}`;
  if (!safe) return `No Safe at ${address} on this chain`;
  if (!same(safe.singleton, SAFE_V141.singletonL2) && !same(safe.singleton, SAFE_V141.singleton)) {
    return `${address} is not a Safe v1.4.1 proxy (singleton ${safe.singleton})`;
  }
  if (!safe.owners.some((o) => same(o, signer))) return `The Safe ${address} does not list the signer ${signer}`;
  if (safe.threshold !== 1n) {
    return `The Safe ${address} has threshold ${safe.threshold}: this script executes with one owner's signature only; collect the others in the Safe app`;
  }
  return null;
}

/** The two adapter contracts a generation's registry can run (decision 0080): through RootVerifier, or the pepper's. */
export type AdapterKind = 'root-verifier' | 'pepper';
export const ADAPTER_CONTRACT = {
  'root-verifier': 'ZKPassportEvidenceAdapter',
  pepper: 'CofferdamZKPassportPepperAdapter',
} as const satisfies Record<AdapterKind, string>;

/**
 * The deployments-file key of the adapter for a ZKPassport circuits version,
 * e.g. `ZKPassportEvidenceAdapterV0_22_0` for 0.22.0, or
 * `CofferdamZKPassportPepperAdapterV0_24_0` for a pepper generation's. The
 * generation's first adapter keeps its plain contract name.
 */
export function adapterKeyForVersion(version: string | undefined, kind: AdapterKind = 'root-verifier'): string {
  const v = version?.trim();
  if (!v || !/^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(v)) throw new Error(`ZKP_CIRCUITS_VERSION is a circuits version such as 0.22.0; got ${v || 'nothing'}`);
  return `${ADAPTER_CONTRACT[kind]}V${v.replace(/\./g, '_')}`;
}

/** The deployments-file key of adapter-drill's never-activated copy, one per kind. */
export function adapterDrillKey(kind: AdapterKind): string {
  return `${ADAPTER_CONTRACT[kind]}Drill`;
}

/**
 * The live adapter safe-exec copies: `IDENTITY_ADAPTER`, else the one adapter
 * the generation recorded. A generation that records both must name one.
 */
export function liveAdapterAddress(fromEnv: string | undefined, recorded: Record<string, { address: string } | undefined>): string {
  const env = fromEnv?.trim();
  if (env) return env;
  const root = recorded[ADAPTER_CONTRACT['root-verifier']]?.address;
  const pepper = recorded[ADAPTER_CONTRACT.pepper]?.address;
  if (root && pepper) throw new Error('This generation records both adapters: set IDENTITY_ADAPTER to the live one');
  const live = root || pepper;
  if (!live) throw new Error('No live adapter to copy: set IDENTITY_ADAPTER');
  return live;
}

/** Why a proposed adapter may not be activated at `now`, or null (the registry's own rule). */
export function activationRefusal(readyAt: bigint, now: bigint, grace: bigint): string | null {
  if (readyAt === 0n) return 'it is not proposed (or was activated or cancelled)';
  if (now < readyAt) return `its timelock ends at ${new Date(Number(readyAt) * 1000).toISOString()}`;
  if (now > readyAt + grace) return `its proposal expired at ${new Date(Number(readyAt + grace) * 1000).toISOString()}: propose it again`;
  return null;
}

/**
 * Why an adapter may not be proposed at `now`, or null. A live proposal (in
 * its timelock or its activation window) is refused, since proposing again
 * would restart the clock; an expired one may be proposed again, which the
 * registry allows and which restarts the timelock.
 */
export function reproposalRefusal(readyAt: bigint, now: bigint, grace: bigint): string | null {
  if (readyAt === 0n || now > readyAt + grace) return null;
  const iso = (t: bigint) => new Date(Number(t) * 1000).toISOString();
  return `it is proposed already: activate it from ${iso(readyAt)} to ${iso(readyAt + grace)}, or cancel it (SAFE_ACTION=adapter-cancel)`;
}

/** `ALLOWED` for set-test-account: unset or 1 adds the account, 0 removes it; anything else is refused. */
export function parseAllowed(value: string | undefined): boolean {
  const v = value?.trim() ?? '';
  if (v === '' || v === '1') return true;
  if (v === '0') return false;
  throw new Error(`ALLOWED is 1 (add, the default) or 0 (remove); got ${v}`);
}
