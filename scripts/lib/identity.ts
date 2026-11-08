import { AbiCoder, concat, getAddress, getBytes, keccak256, toBeArray, toUtf8Bytes } from 'ethers';

// Encodings shared by CofferdamIdentityRegistry, ZKPassportEvidenceAdapter,
// their tests and the deploy scripts (decision 0080). `@cofferdam/sdk` must
// produce the same bytes: test/fixtures/identity-digest.json pins them.

const abi = AbiCoder.defaultAbiCoder();

/** The action tags; the registry folds `keccak256(tag)` into the digest. */
export const IDENTITY_ACTIONS = {
  bind: keccak256(toUtf8Bytes('cofferdam-identity-bind-v1')),
  rebind: keccak256(toUtf8Bytes('cofferdam-identity-rebind-v1')),
  relink: keccak256(toUtf8Bytes('cofferdam-identity-relink-v1')),
} as const;
export type IdentityAction = keyof typeof IDENTITY_ACTIONS;

/** `CofferdamIdentityRegistry.digest(action, account)` for a given nonce. */
export function identityDigest(
  action: IdentityAction,
  chainId: bigint,
  registry: string,
  account: string,
  nonce: bigint,
): string {
  return keccak256(
    abi.encode(
      ['bytes32', 'uint256', 'address', 'address', 'uint256'],
      [IDENTITY_ACTIONS[action], chainId, registry, account, nonce],
    ),
  );
}

/** The ZKPassport `custom_data` a proof must be bound to: the digest as lowercase 0x hex, 66 characters. */
export function zkpCustomData(digest: string): string {
  const hex = digest.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hex)) throw new Error(`Not a 32-byte digest: ${digest}`);
  return hex;
}

// ── ZKPassport ────────────────────────────────────────────────────────────────

export const ZKP_ROOT_VERIFIER = '0x1D000001000EFD9a6371f4d90bB8920D5431c0D8';
export const ZKP_DOMAIN = 'cofferdam.xyz';
/** ZKPassport identifier types; the adapter accepts only the first two. */
export const ZKP_IDENTIFIER_TYPE = { nonSalted: 0, salted: 1, nonSaltedMock: 2, saltedMock: 3, none: 4 } as const;

/** ZKPassport's bytes32 encoding of a circuits version: three big-endian uint16, then zeros. */
export function zkpCircuitsVersion(version: string): string {
  const parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 0xffff) || parts.every((p) => p === 0)) {
    throw new Error(`Invalid circuits version: ${version}`);
  }
  return '0x' + parts.map((p) => p.toString(16).padStart(4, '0')).join('').padEnd(64, '0');
}

/** `ZKPassportEvidenceAdapter.identifierKind()` for a type and OPRF key hash (0 for non-salted). */
export function zkpIdentifierKind(identifierType: number, oprfKeyHash = '0x' + '00'.repeat(32)): string {
  return keccak256(abi.encode(['string', 'uint8', 'bytes32'], ['zkpassport-identifier-v1', identifierType, oprfKeyHash]));
}

/** `ZKPassportEvidenceAdapter.scopeId()` for a scope under cofferdam.xyz. */
export function zkpScopeId(scope: string): string {
  return keccak256(abi.encode(['string', 'string'], [ZKP_DOMAIN, scope]));
}

/** One committed-input section: `[type:1][length:2][data]`. */
export function zkpSection(type: number, data: Uint8Array | number[]): Uint8Array {
  const bytes = Uint8Array.from(data);
  return getBytes(concat([Uint8Array.from([type, bytes.length >> 8, bytes.length & 0xff]), bytes]));
}

/** The bind section (type 8, 509 bytes) as the SDK writes it. Fields left undefined are omitted. */
export function zkpBindSection(bound: { userAddress?: string; chainId?: bigint; customData?: string }): Uint8Array {
  const out: number[] = [];
  if (bound.userAddress) {
    const a = getBytes(getAddress(bound.userAddress));
    out.push(1, 0, a.length, ...a);
  }
  if (bound.chainId !== undefined) {
    const c = toBeArray(bound.chainId);
    out.push(2, 0, c.length, ...c);
  }
  if (bound.customData) {
    const s = toUtf8Bytes(bound.customData);
    out.push(3, s.length >> 8, s.length & 0xff, ...s);
  }
  if (out.length > 509) throw new Error('Bound data too long');
  while (out.length < 509) out.push(0);
  return zkpSection(8, out);
}

/** `ZKPassportEvidenceAdapter` evidence: `abi.encode(vkeyHash, proof, publicInputs, committedInputs)`. */
export function encodeZkpEvidence(p: {
  vkeyHash: string;
  proof: string | Uint8Array;
  publicInputs: string[];
  committedInputs: string | Uint8Array;
}): string {
  return abi.encode(['bytes32', 'bytes', 'bytes32[]', 'bytes'], [p.vkeyHash, p.proof, p.publicInputs, p.committedInputs]);
}
