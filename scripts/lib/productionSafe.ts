// The company Safe on Base mainnet (decision 0017 (2); the founder's ruling of
// 2026-11-26): a Safe v1.4.1, 2-of-3, its owners the deployer Ledger, the
// founder's phone (Safe{Mobile}) and a second hardware wallet of another make,
// created once with all three owners and threshold 2 before the production
// generation, and the owner of every contract from its first block.
//
// The M2 dev-key exception's throwaway Safe (zkp-test-1, threshold 1, the
// CofferdamDev wallet its only owner) is checked by ./devKeyException.ts
// instead. Imports nothing from Hardhat, so the tests call it without a network.

import { DEV_KEY_EXCEPTION, SAFE_V141, type SafeFacts } from './devKeyException';

export const PRODUCTION_SAFE = { owners: 3, threshold: 2n } as const;

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const isAddress = (a: string) => /^0x[0-9a-fA-F]{40}$/.test(a);

/**
 * Why create-safe.ts may not create this Safe on chain 8453 outside the
 * exception, or null: exactly three distinct owners, threshold 2, and never the
 * CofferdamDev hot wallet (a hot dev key never owns the company's Safe, even
 * for a moment).
 */
export function productionSafeSetupRefusal(owners: string[], threshold: bigint): string | null {
  if (owners.length !== PRODUCTION_SAFE.owners) {
    return `The company Safe has exactly ${PRODUCTION_SAFE.owners} owners (the Ledger, the phone, the second hardware wallet); SAFE_OWNERS lists ${owners.length}`;
  }
  if (threshold !== PRODUCTION_SAFE.threshold) {
    return `The company Safe's threshold is ${PRODUCTION_SAFE.threshold}; SAFE_THRESHOLD is ${threshold}`;
  }
  const bad = owners.find((o) => !isAddress(o));
  if (bad) return `SAFE_OWNERS: ${bad} is not an address`;
  if (new Set(owners.map((o) => o.toLowerCase())).size !== owners.length) return 'SAFE_OWNERS lists an owner twice';
  if (owners.some((o) => same(o, DEV_KEY_EXCEPTION.signer))) {
    return `The CofferdamDev hot wallet ${DEV_KEY_EXCEPTION.signer} never owns the company Safe`;
  }
  return null;
}

/**
 * Why `owner` may not own a contract of a Base mainnet generation outside the
 * exception, or null. It must be a Safe v1.4.1 proxy, read on chain: at least
 * three owners and threshold at least 2 (and no more than its owners), no
 * module enabled (a module executes without the owners' signatures), and
 * never listing the CofferdamDev wallet. `safe` is null when the address has
 * no code or does not answer as a Safe.
 */
export function productionOwnerRefusal(owner: string, safe: SafeFacts | null): string | null {
  if (!safe) return `REGISTRY_OWNER ${owner} is not a Safe on this chain: on Base mainnet every contract is owned by the company Safe (2-of-3)`;
  if (!same(safe.singleton, SAFE_V141.singletonL2) && !same(safe.singleton, SAFE_V141.singleton)) {
    return `REGISTRY_OWNER ${owner} is not a Safe v1.4.1 proxy (singleton ${safe.singleton})`;
  }
  if (safe.owners.length < PRODUCTION_SAFE.owners) {
    return `The Safe ${owner} has ${safe.owners.length} owners; the company Safe has at least ${PRODUCTION_SAFE.owners}`;
  }
  if (safe.threshold < PRODUCTION_SAFE.threshold || safe.threshold > BigInt(safe.owners.length)) {
    return `The Safe ${owner} has threshold ${safe.threshold} over ${safe.owners.length} owners; the company Safe needs at least ${PRODUCTION_SAFE.threshold}`;
  }
  if (safe.owners.some((o) => same(o, DEV_KEY_EXCEPTION.signer))) {
    return `The Safe ${owner} lists the CofferdamDev hot wallet ${DEV_KEY_EXCEPTION.signer}: it is not the company Safe`;
  }
  if (safe.modules === undefined) return `The Safe ${owner}'s modules could not be read`;
  if (safe.modules.length > 0) {
    return `The Safe ${owner} has modules enabled (${safe.modules.join(', ')}): a module executes without the owners' signatures`;
  }
  return null;
}
