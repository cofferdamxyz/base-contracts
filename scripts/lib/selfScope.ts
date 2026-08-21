/**
 * Self.xyz scope derivation, mirrored for Base.
 *
 * `NullifierRegistry.expectedScope` is an **immutable**: changing it means
 * redeploying the registry and re-binding every user. It must equal the
 * `scope` public signal the Self circuit emits, which the app controls via
 * `SelfAppBuilder`. If the two diverge, every `verifyAndBind` call reverts
 * `WrongScope(expected, got)`.
 *
 * Rather than trusting a pasted magic number, this module re-derives the
 * value from the same primitives Self uses, so a unit test can assert the
 * constant is actually correct.
 *
 * Ported from `self/common/src/utils/scope.ts` (`hashEndpointWithScope`)
 * and `self/common/src/utils/hash.ts` (`flexiblePoseidon`).
 */
import {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} from 'poseidon-lite';

/** Verify endpoint host. Only the host contributes to the scope. */
export const COFFERDAM_SELF_HOST = 'cofferdam.xyz';

/**
 * Scope string, capped at 31 ASCII chars by `SelfAppBuilder`.
 * MUST match `buildCofferdamSelfApp()` in
 * `cofferdam-app/src/features/self/selfAppConfig.ts`.
 */
export const COFFERDAM_SELF_SCOPE_STRING = 'cofferdam-bind-v1';

const POSEIDON = [
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
];

/** Mirrors `flexiblePoseidon` — dispatches on input arity, 1..16. */
function flexiblePoseidon(inputs: bigint[]): bigint {
  const fn = POSEIDON[inputs.length - 1];
  if (!fn) throw new Error(`flexiblePoseidon: unsupported arity ${inputs.length}`);
  return fn(inputs);
}

/**
 * Mirrors `stringToBigInt` — big-endian ASCII byte packing, max 31 bytes.
 */
export function stringToBigInt(str: string): bigint {
  if (!/^[\x00-\x7F]*$/.test(str)) {
    throw new Error('Input must contain only ASCII characters (0-127)');
  }
  let result = 0n;
  for (let i = 0; i < str.length; i++) {
    result = (result << 8n) | BigInt(str.charCodeAt(i));
  }
  if (result > (1n << 248n) - 1n) {
    throw new Error(`Resulting BigInt exceeds maximum size of 31 bytes: ${str}`);
  }
  return result;
}

/**
 * Mirrors `formatEndpoint` — strips the scheme and keeps ONLY the host, so
 * the path of the verify endpoint does not affect the scope.
 */
export function formatEndpoint(endpoint: string): string {
  if (!endpoint) return '';
  const formatted = endpoint.replace(/^https?:\/\//, '').split('/')[0];
  // Contract addresses are lowercased to match Solidity's addressToHexString.
  return formatted.startsWith('0x') ? formatted.toLowerCase() : formatted;
}

/**
 * Mirrors `hashEndpointWithScope` — `poseidon2([H(hostChunks), scope])`.
 */
export function hashEndpointWithScope(endpoint: string, scope: string): bigint {
  const formattedEndpoint = formatEndpoint(endpoint);

  const endpointChunks: string[] = [];
  let remaining = formattedEndpoint;
  while (remaining.length > 0) {
    endpointChunks.push(remaining.slice(0, 31));
    remaining = remaining.slice(31);
  }
  if (endpointChunks.length > 16) {
    throw new Error('Endpoint must be less than 496 characters');
  }

  const endpointHash = flexiblePoseidon(endpointChunks.map(stringToBigInt));
  return poseidon2([endpointHash, stringToBigInt(scope)]);
}

/**
 * Scope pinned into `NullifierRegistry.expectedScope` on Base.
 *
 * Asserted against `hashEndpointWithScope()` in
 * `test/self-nullifier-registry.test.ts`, so this literal cannot silently
 * drift from the derivation.
 */
export const COFFERDAM_BIND_V1_SCOPE =
  9385173979550103756914225592429331034074493553395666193753061396908251355773n;

/**
 * Derive the scope for the pinned host/scope-string pair. Deploy scripts
 * call this instead of using the literal, so a bad literal fails loudly.
 */
export function deriveCofferdamScope(): bigint {
  return hashEndpointWithScope(COFFERDAM_SELF_HOST, COFFERDAM_SELF_SCOPE_STRING);
}
