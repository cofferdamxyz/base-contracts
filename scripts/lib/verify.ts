// Basescan verification of a generation's contracts (scripts/verify.ts).
// Imports nothing from Hardhat, so the tests call it without a network.

import { getCreateAddress } from 'ethers';

/** Deployments-file entries we verify, and the contract each one is. */
export const VERIFY_CONTRACTS: Record<string, string> = {
  ZKPassportEvidenceAdapter: 'ZKPassportEvidenceAdapter',
  ZKPassportEvidenceAdapterDrill: 'ZKPassportEvidenceAdapter',
  CofferdamIdentityRegistry: 'CofferdamIdentityRegistry',
  WebAuthnPasskeyAuthority: 'WebAuthnPasskeyAuthority',
  PasskeyAuthority: 'PasskeyAuthority',
  PartnerPasskeyAuthority: 'PartnerPasskeyAuthority',
  SessionKeyAuthorityLowManaged: 'SessionKeyAuthority',
  CofferdamModuleRegistry: 'CofferdamModuleRegistry',
  CofferdamCeremonyAttesterRegistry: 'CofferdamCeremonyAttesterRegistry',
  CofferdamAccountFactory4337: 'CofferdamAccountFactory4337',
  CofferdamPaymaster: 'CofferdamPaymaster',
  CofferdamHandleAnchor: 'CofferdamHandleAnchor',
};

/**
 * Entries that are not ours to verify: the canonical EntryPoint (verified by
 * its authors) and the Safe (a proxy from Safe's own factory); the script
 * only reports whether Basescan shows their source.
 */
export const VERIFY_NOT_OURS = ['EntryPoint', 'CofferdamSafe', 'CofferdamHandleAnchorSafe'] as const;

/** Entries of a deployments file that are records, not contracts. */
const RECORDS = ['devKeyException'];

export interface VerifyPlan {
  /** `txHash`: the creation transaction, when the deployments file records it. */
  ours: { key: string; contract: string; address: string; txHash?: string }[];
  notOurs: { key: string; address: string }[];
}

/**
 * What to verify in a deployments file. An entry the script does not know
 * stops it, so nothing is skipped silently.
 */
export function verifyPlan(recorded: Record<string, { address?: string; txHash?: string } | undefined>): VerifyPlan {
  const plan: VerifyPlan = { ours: [], notOurs: [] };
  const unknown: string[] = [];
  for (const [key, entry] of Object.entries(recorded)) {
    if (RECORDS.includes(key)) continue;
    const address = entry?.address;
    if (!address) continue;
    if ((VERIFY_NOT_OURS as readonly string[]).includes(key)) plan.notOurs.push({ key, address });
    else if (VERIFY_CONTRACTS[key]) plan.ours.push({ key, contract: VERIFY_CONTRACTS[key], address, txHash: entry?.txHash });
    else if (/^ZKPassportEvidenceAdapterV\d+_\d+_\d+$/.test(key)) plan.ours.push({ key, contract: 'ZKPassportEvidenceAdapter', address });
    else unknown.push(key);
  }
  if (unknown.length > 0) throw new Error(`The deployments file records ${unknown.join(', ')}, which scripts/lib/verify.ts does not know: add it to VERIFY_CONTRACTS or VERIFY_NOT_OURS`);
  return plan;
}

/**
 * The entries named by `keys` (VERIFY_KEYS, comma-separated), or all of them
 * when `keys` is empty. Base Sepolia's single file mixes contracts of every
 * era, most of which this script does not know, so a Sepolia run names its
 * keys. A key the file does not record stops it.
 */
export function selectRecorded<T>(recorded: Record<string, T>, keys: string | undefined): Record<string, T> {
  const wanted = (keys ?? '').split(',').map((k) => k.trim()).filter(Boolean);
  if (wanted.length === 0) return recorded;
  const missing = wanted.filter((k) => !(k in recorded));
  if (missing.length > 0) throw new Error(`VERIFY_KEYS names ${missing.join(', ')}, which the deployments file does not record`);
  return Object.fromEntries(wanted.map((k) => [k, recorded[k]]));
}

/**
 * The deployer's nonce whose CREATE made `address`, or null when no nonce
 * below `nonceNow` did (another deployer, or CREATE2 through a factory).
 */
export function createNonce(deployer: string, address: string, nonceNow: number): number | null {
  for (let nonce = 0; nonce < nonceNow; nonce++) {
    if (getCreateAddress({ from: deployer, nonce }).toLowerCase() === address.toLowerCase()) return nonce;
  }
  return null;
}

/**
 * The creation transaction was built from other sources or compiler settings
 * than this checkout's: a contract deployed before a later change to its
 * source. verify.ts accepts it only when Basescan already shows its source.
 */
export class BytecodeMismatchError extends Error {
  constructor() {
    super(
      'The creation transaction does not start with the compiled bytecode: the sources or compiler settings differ from what was deployed (check out the deploy commit and compile)',
    );
    this.name = 'BytecodeMismatchError';
  }
}

/**
 * The ABI-encoded constructor arguments: what follows the compiled creation
 * bytecode in the creation transaction's input. Refuses when the input does
 * not start with that bytecode, since Basescan would refuse the source too.
 */
export function constructorArgsHex(input: string, bytecode: string): string {
  const tx = input.toLowerCase().replace(/^0x/, '');
  const code = bytecode.toLowerCase().replace(/^0x/, '');
  if (code.length === 0) throw new Error('The artifact has no creation bytecode');
  if (!tx.startsWith(code)) throw new BytecodeMismatchError();
  return '0x' + tx.slice(code.length);
}
