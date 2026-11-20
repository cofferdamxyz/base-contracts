import { AbiCoder, Interface, concat, getAddress, getBytes, keccak256, sha256, toBeArray, toBeHex, toUtf8Bytes } from 'ethers';

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

/** `zkp-test-1`, the one generation on Base mainnet whose identifiers are unsalted (T2, accepted in writing 2026-11-15); deployed 2026-11-15. */
export const UNSALTED_MAINNET_GENERATION = 'zkp-test-1';

/**
 * The identifier type `deploy-identity.ts` deploys. On chain 8453 it must be
 * named (`ZKP_IDENTIFIER_TYPE`), never defaulted, and Base mainnet itself (not
 * a local fork) refuses `non-salted` outright: decision 0080 rule 4 keeps every
 * real user's unsalted identifier off the chain, the registry pins its kind for
 * good, and the one unsalted generation T2 accepted, `zkp-test-1`, is deployed.
 * A fork rehearsal may run it. Elsewhere the default is `salted` for the pepper
 * adapter and `non-salted` otherwise.
 */
export function identifierTypeFor(
  env: { ZKP_IDENTIFIER_TYPE?: string },
  o: { mainnet: boolean; fork: boolean; pepper: boolean },
): 'salted' | 'non-salted' {
  const named = env.ZKP_IDENTIFIER_TYPE?.trim();
  if (o.mainnet && !named) {
    throw new Error('On chain 8453 set ZKP_IDENTIFIER_TYPE (salted, or non-salted for a fork rehearsal): it is pinned for the generation');
  }
  const typeName = named || (o.pepper ? 'salted' : 'non-salted');
  if (typeName !== 'non-salted' && typeName !== 'salted') throw new Error('ZKP_IDENTIFIER_TYPE is non-salted or salted');
  if (o.pepper && typeName !== 'salted') throw new Error('The pepper adapter takes salted identifiers only');
  if (o.mainnet && !o.fork && typeName === 'non-salted') {
    throw new Error(
      `non-salted identifiers never reach Base mainnet again: ${UNSALTED_MAINNET_GENERATION}, the one T2 accepted, is deployed (decision 0080, rule 4): deploy salted`,
    );
  }
  return typeName;
}

/** `ZKPassportEvidenceAdapter.scopeId()` for a scope under cofferdam.xyz. */
export function zkpScopeId(scope: string): string {
  return keccak256(abi.encode(['string', 'string'], [ZKP_DOMAIN, scope]));
}

// ── The pepper: CofferdamZKPassportPepperAdapter (decision 0080, P1) ──────────

/**
 * ZKPassport's global OPRF key hash on Base mainnet, the 0.23.0 sub-verifier's
 * `globalOPRFPubKeyHash()` read 2026-11-19. The pepper adapter refuses it.
 */
export const ZKP_GLOBAL_OPRF_KEY_HASH = '0x029ad69ef5e692aa43cd3635002a473d72b412d10741d2cba30700df1e895334';

/**
 * The outer-proof verifiers of circuits 0.23.0 on Base mainnet, by
 * verification-key hash: the `ProofVerifierAdded` events of the version's
 * sub-verifier (0xBEcf247a16aEEa812256D1aBdAaF95Ab062084b2, block 58320674),
 * each confirmed against `proofVerifiers(vkeyHash)` on 2026-11-19. The pepper
 * adapter pins them and checks them again against the chain at deployment.
 */
export const ZKP_OUTER_VERIFIERS_0_23_0: Readonly<Record<string, string>> = {
  '0x0345a25899029830ed562e47667bb6da8c07e5355e5a4d18d7b4a0507dd1b890': '0x58fFFf2B6Ffd44f3bfa4e3968EEB8D6CCECA53CF',
  '0x086b6104133cfce2bfc1bd89fa1c0f4d44499a6fa638ccca1842d10223e261ee': '0xB213e4cCFDc2CF597eF7390c1169a459D3854204',
  '0x259d9ac1c92499dffc83c15f85ace25c51e34c3fba52e0f4db94f936bc1e21b2': '0xaE729d77F10ceF0691cf8a0794e83468441B3D48',
  '0x17b5cc890adda9b3d4f2e278a1dc33199a66fe4547a38d066f669b6dea0d0a09': '0x7DD1dc29A6121a0CE2199e6B064A9f8902559f41',
  '0x2b231a73ce09ae03936db30861f69d2b7afef42118736b57a970bd5ef22e6b4b': '0x1fd8552c8BA59A4ee1573327fDd2651c615c1448',
  '0x0ba9bda5ed8feb20117e04edade722d588fffc3f686873b8c18e33abbf13bb4b': '0x6F0f129B0f4dd8898254E0b08D4E604d56A261d3',
  '0x01af51387480391d39772760fc43f21e2d839a57580da51209ba193e29ef8875': '0x3e89f1E177022A36526Fa48C4554C648F5B4cB9c',
  '0x2705cc052c4e7b0f9d56d7c7ce7652e4d88e3ae4d64a27d82da69195bc5437de': '0x37D0C91a81E78DC859d15892ec407703388aDb60',
  '0x0b5cd3365308dfebd3279b7e3a36b29282f68efd405b960432dfc92fc380886c': '0xAfEd263bA88A11fA48a5FF9cBD1b675d820C69a6',
  '0x182060d3c0edf4ce03c8b8b4645f114ed756914dc1019ad3b85b60c3b2ce4831': '0xD35cdBcFb3687dA105976D2f9A5754175DD5aDcd',
  '0x01cb2a9cc9d0cdbc96253fa28828a3a74c11d368cbdd51cc19a99c040803f332': '0x1aBe61bbDdeD5aaabF6051Fa49E1Ef22288D71d8',
  '0x07620e594d8b5c5f63ed244cfc6f078d54fa65a28991bb9451aca0aeb8196f8e': '0xf0CeBB573306C6F717Fd0C6bB3dEe1f524fa247b',
};

/** The public input a domain or scope must equal: its SHA-256 with the last byte dropped (ZKPassport's `SubVerifier`). */
export function zkpScopeHash(s: string): string {
  return s === '' ? '0x' + '00'.repeat(32) : toBeHex(BigInt(sha256(toUtf8Bytes(s))) >> 8n, 32);
}

/** The parameter commitment of one committed-input section (type, length and data): SHA-256, the last byte dropped. */
export function zkpParamCommitment(section: Uint8Array | string): string {
  return toBeHex(BigInt(sha256(section)) >> 8n, 32);
}

/** The expiry section (type 3): the proof's bounds on the document's expiry date, in seconds; no upper bound is 0. */
export function zkpExpirySection(minDate: bigint, maxDate = 0n): Uint8Array {
  return zkpSection(3, [...getBytes(toBeHex8(minDate)), ...getBytes(toBeHex8(maxDate))]);
}

function toBeHex8(n: bigint): string {
  return '0x' + n.toString(16).padStart(16, '0');
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

/** A compressed-EVM proof as SDK 0.19.3's `getSolidityVerifierParameters` returns it. */
export type ZkpSolidityParams = {
  version: string;
  proofVerificationData: { vkeyHash: string; proof: string; publicInputs: string[] };
  committedInputs: string;
  serviceConfig: { validityPeriodInSeconds: number; domain: string; scope: string; devMode: boolean };
};

/** The adapter's evidence from SDK parameters: only the proof's own fields; version and configuration stay pinned. */
export function zkpEvidenceFromParams(p: ZkpSolidityParams, committedInputs = p.committedInputs): string {
  return encodeZkpEvidence({ ...p.proofVerificationData, committedInputs });
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

/**
 * Text with every run of 32 bytes or more of hex, with or without `0x`,
 * replaced by `<N bytes withheld>`: a registry error names the identifier,
 * and ethers prints an undecoded custom error's data without its `0x`
 * (2026-11-17), so a run is withheld whole.
 */
export function withholdWords(text: string): string {
  return text.replace(/(?:0x)?[0-9a-fA-F]{64,}/g, (run) => {
    const digits = run.startsWith('0x') ? run.length - 2 : run.length;
    return `<${Math.floor(digits / 2)} bytes withheld>`;
  });
}

/**
 * A custom error from `iface` named with its arguments, every bytes32 argument
 * withheld; null when the data is not one of `iface`'s errors.
 */
export function describeCustomError(iface: Interface, data: string): string | null {
  let parsed: ReturnType<Interface['parseError']>;
  try {
    parsed = iface.parseError(data);
  } catch {
    return null;
  }
  if (!parsed) return null;
  // A bytes32, or an integer too large to be a count, a date or an enum, may be an identifier:
  // the adapter's WrongIdentifierType(expected, got) carried one when circuits 0.23.0 moved the
  // public inputs (2026-11-18).
  const args = parsed.fragment.inputs.map((input, i) => {
    const value = parsed!.args[i];
    if (input.type === 'bytes32') return '<32 bytes withheld>';
    if (typeof value === 'bigint' && value >= 2n ** 64n) return `<${input.type} withheld>`;
    return String(value);
  });
  return `${parsed.name}(${args.join(', ')})`;
}

/**
 * A revert's reason for printing: the error decoded from the first of `ifaces`
 * that knows it, its bytes32 and large integer arguments withheld, from ethers' revert data or anvil's message ("custom
 * error 0x<selector>: <hex>", which reaches ethers undecoded); otherwise the
 * first line of the message with every long hex run withheld. The registry's
 * IdentifierAlreadyBound, AccountAlreadyBound and RetiredIdentifier carry the
 * identifier, which a script never prints.
 */
export function revertReason(ifaces: Interface | Interface[], e: unknown): string {
  const err = (e ?? {}) as { shortMessage?: string; message?: string; data?: unknown };
  const text = `${err.shortMessage ?? ''}\n${err.message ?? String(e)}`;
  const anvil = /custom error (0x[0-9a-fA-F]{8}):\s*([0-9a-fA-F]*)/.exec(text);
  const data = typeof err.data === 'string' && err.data.length >= 10 ? err.data : anvil ? anvil[1] + anvil[2] : null;
  for (const iface of Array.isArray(ifaces) ? ifaces : [ifaces]) {
    const described = data ? describeCustomError(iface, data) : null;
    if (described) return `reverted ${described}`;
  }
  return withholdWords(err.shortMessage ?? (err.message ?? String(e)).split('\n')[0]);
}
