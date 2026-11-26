// CofferdamRelayPaymaster's settings (the founder's ruling P9, 2026-11-26):
// the relayer and the per-op cap a deploy takes, and the checks the Safe's
// actions on it repeat. Imports nothing from Hardhat, so the tests call it
// without a network.

import { DEV_KEY_EXCEPTION } from './devKeyException';

/** The deployments-file key. */
export const RELAY_PAYMASTER = 'CofferdamRelayPaymaster';

/**
 * The largest per-op cap the scripts accept on Base mainnet, 0.01 ETH: a guard
 * against a cap mistyped by orders of magnitude, not a policy. A sponsored op
 * on Base costs a few millionths of an ETH; the cap bounds what one op may
 * take from the deposit.
 */
export const MAINNET_MAX_COST_CEILING = 10n ** 16n;
/** The cap a local network takes when none is given (0.01 ETH). */
export const LOCAL_DEFAULT_MAX_COST = 10n ** 16n;

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Wei as a decimal integer, positive. */
export function parseWei(name: string, value: string | undefined): bigint {
  const v = value?.trim();
  if (!v || !/^[0-9]{1,30}$/.test(v)) throw new Error(`${name} is an amount in wei, a decimal integer; got ${v || 'nothing'}`);
  const wei = BigInt(v);
  if (wei === 0n) throw new Error(`${name} must be above zero`);
  return wei;
}

/**
 * PAYMASTER_MAX_COST_WEI: required on chain 8453 and on public testnets, at
 * most MAINNET_MAX_COST_CEILING on chain 8453; local networks default to
 * LOCAL_DEFAULT_MAX_COST.
 */
export function relayPaymasterMaxCost(value: string | undefined, o: { mainnet: boolean; local: boolean }): bigint {
  if (!value?.trim()) {
    if (o.local && !o.mainnet) return LOCAL_DEFAULT_MAX_COST;
    throw new Error('PAYMASTER_MAX_COST_WEI is required: the largest maxCost (wei) one sponsored op may carry');
  }
  const cap = parseWei('PAYMASTER_MAX_COST_WEI', value);
  if (o.mainnet && cap > MAINNET_MAX_COST_CEILING) {
    throw new Error(`PAYMASTER_MAX_COST_WEI ${cap} is above ${MAINNET_MAX_COST_CEILING} wei (0.01 ETH): refused on Base mainnet as a likely typo`);
  }
  return cap;
}

/**
 * Why `relayer` may not be the paymaster's relayer, or null. Never the owner
 * (the Safe), never the deployer (decision 0017: the hardware wallet is never
 * the relayer), never the CofferdamDev hot wallet on chain 8453, and an EOA:
 * `tx.origin` is never a contract (an EIP-7702 delegation, code 0xef0100…, is
 * an EOA).
 */
export function relayerRefusal(relayer: string, o: { owner: string; deployer: string; mainnet: boolean; code: string }): string | null {
  if (!/^0x[0-9a-fA-F]{40}$/.test(relayer) || /^0x0{40}$/.test(relayer)) return `The relayer ${relayer} is not a non-zero address`;
  if (same(relayer, o.owner)) return `The relayer ${relayer} is the owner`;
  if (o.mainnet && same(relayer, o.deployer)) return `The relayer ${relayer} is the deployer: the Ledger is never the relayer (decision 0017)`;
  if (o.mainnet && same(relayer, DEV_KEY_EXCEPTION.signer)) return `The relayer ${relayer} is the CofferdamDev hot wallet: never on Base mainnet`;
  const code = o.code.toLowerCase();
  if (code !== '0x' && !code.startsWith('0xef0100')) return `The relayer ${relayer} is a contract: tx.origin is always an EOA`;
  return null;
}

/**
 * RELAYER_ADDRESS: required on chain 8453 (no default) and on public
 * testnets; local networks default to the deployer.
 */
export function relayPaymasterRelayer(value: string | undefined, o: { mainnet: boolean; local: boolean; deployer: string }): string {
  const v = value?.trim();
  if (v) return v;
  if (o.local && !o.mainnet) return o.deployer;
  throw new Error("RELAYER_ADDRESS is required: the plane's relayer (on Base mainnet the CDP Server Wallet account's address)");
}
