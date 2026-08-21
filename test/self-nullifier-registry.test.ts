import { expect } from 'chai';
import { ethers } from 'hardhat';

import {
  COFFERDAM_BIND_V1_SCOPE,
  COFFERDAM_SELF_HOST,
  COFFERDAM_SELF_SCOPE_STRING,
  hashEndpointWithScope,
} from '../scripts/lib/selfScope';
import {
  COFFERDAM_SELF_DEST_CHAIN_ID,
  buildUserContextData,
  calculateUserIdentifierHash,
} from '../scripts/lib/selfUserContext';

const MOCK_VERIFIER = 'contracts/test/MockGroth16Verifier.sol:MockGroth16Verifier';
const REJECTING_VERIFIER = 'contracts/test/MockGroth16Verifier.sol:RejectingGroth16Verifier';

// Public-signal indices, mirroring contracts/self/SelfPublicSignals.sol.
const IDX = {
  NULLIFIER: 7,
  ATTESTATION_ID: 8,
  SCOPE: 19,
  USER_IDENTIFIER: 20,
} as const;

const E_PASSPORT_ATTESTATION_ID = 1n;
const NULLIFIER = 0x5eedn;

// Groth16 proof points are never inspected by the mocks.
const A: [bigint, bigint] = [0n, 0n];
const B: [[bigint, bigint], [bigint, bigint]] = [
  [0n, 0n],
  [0n, 0n],
];
const C: [bigint, bigint] = [0n, 0n];

interface BindOptions {
  account: string;
  scope?: bigint;
  nullifier?: bigint;
  attestationId?: bigint;
  /** Defaults to `account`; override to simulate a UUID or wrong address. */
  userId?: string;
  userDefinedData?: string;
  destChainId?: number;
  /** Override the emitted signal to decouple it from `context`. */
  userIdentifier?: bigint;
}

/**
 * Build the 21-element public-signal array the `vc_and_disclose` circuit emits,
 * plus the matching `userContextData` preimage.
 *
 * `userIdentifier` is derived exactly as Self does — a ripemd160(sha256(...))
 * commitment over (destChainId, userId, userDefinedData) — not the raw address.
 */
function buildBind(opts: BindOptions): { pubSignals: bigint[]; context: string } {
  const destChainId = opts.destChainId ?? COFFERDAM_SELF_DEST_CHAIN_ID;
  const userId = opts.userId ?? opts.account;
  const userDefinedData = opts.userDefinedData ?? '';

  const pubSignals = new Array<bigint>(21).fill(0n);
  pubSignals[IDX.NULLIFIER] = opts.nullifier ?? NULLIFIER;
  pubSignals[IDX.ATTESTATION_ID] = opts.attestationId ?? E_PASSPORT_ATTESTATION_ID;
  pubSignals[IDX.SCOPE] = opts.scope ?? COFFERDAM_BIND_V1_SCOPE;
  pubSignals[IDX.USER_IDENTIFIER] =
    opts.userIdentifier ?? calculateUserIdentifierHash(destChainId, userId, userDefinedData);

  return {
    pubSignals,
    context: buildUserContextData(destChainId, userId, userDefinedData),
  };
}

async function deployFixture(
  opts: { rejectProofs?: boolean; scope?: bigint; selfDestChainId?: number } = {}
) {
  const [deployer, attester, account, other, outsider] = await ethers.getSigners();

  const Verifier = await ethers.getContractFactory(
    opts.rejectProofs ? REJECTING_VERIFIER : MOCK_VERIFIER
  );
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();

  const AttesterRegistry = await ethers.getContractFactory('SelfAttesterRegistry');
  const attesterRegistry = await AttesterRegistry.deploy(deployer.address, [attester.address]);
  await attesterRegistry.waitForDeployment();

  const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
  const registry = await NullifierRegistry.deploy(
    await verifier.getAddress(),
    await attesterRegistry.getAddress(),
    opts.scope ?? COFFERDAM_BIND_V1_SCOPE,
    opts.selfDestChainId ?? COFFERDAM_SELF_DEST_CHAIN_ID
  );
  await registry.waitForDeployment();

  /**
   * Reproduce the attester Worker's signature: EIP-191 personal_sign over
   * `keccak256(abi.encode(chainid, registry, account, pubSignals))`.
   */
  async function signBind(
    pubSignals: bigint[],
    signer = attester,
    target = registry
  ): Promise<string> {
    const msgHash = await target.attesterMessageHash(account.address, pubSignals);
    return signer.signMessage(ethers.getBytes(msgHash));
  }

  return {
    deployer,
    attester,
    account,
    other,
    outsider,
    verifier,
    attesterRegistry,
    registry,
    signBind,
  };
}

describe('Self scope derivation', () => {
  /**
   * `expectedScope` is immutable — a wrong literal is only discoverable
   * after deploy, when every bind reverts WrongScope. Re-derive it from
   * Self's own primitives so the literal cannot silently drift.
   */
  it('pinned literal matches hashEndpointWithScope', () => {
    expect(hashEndpointWithScope(COFFERDAM_SELF_HOST, COFFERDAM_SELF_SCOPE_STRING)).to.equal(
      COFFERDAM_BIND_V1_SCOPE
    );
  });

  it('ignores the endpoint path, but not the host', () => {
    const withPath = hashEndpointWithScope(
      `https://${COFFERDAM_SELF_HOST}/v1/self/verify`,
      COFFERDAM_SELF_SCOPE_STRING
    );
    expect(withPath).to.equal(COFFERDAM_BIND_V1_SCOPE);

    const otherHost = hashEndpointWithScope('example.com', COFFERDAM_SELF_SCOPE_STRING);
    expect(otherHost).to.not.equal(COFFERDAM_BIND_V1_SCOPE);
  });

  it('is sensitive to the scope string', () => {
    // The value previously deployed by mistake, from scope 'cofferdam-sepolia'.
    expect(hashEndpointWithScope(COFFERDAM_SELF_HOST, 'cofferdam-sepolia')).to.not.equal(
      COFFERDAM_BIND_V1_SCOPE
    );
  });

  it('rejects scope strings over the 31-byte field limit', () => {
    expect(() => hashEndpointWithScope(COFFERDAM_SELF_HOST, 'x'.repeat(32))).to.throw(
      /exceeds maximum size of 31 bytes/
    );
  });
});

describe('Self userIdentifier derivation', () => {
  /**
   * Pinned against the inline snapshots committed in Self's own
   * `common/src/utils/hash.test.ts`. If these drift, our mirror of
   * `calculateUserIdentifierHash` has diverged from upstream and the
   * on-chain commitment check will reject every real proof.
   */
  it('matches Self upstream snapshots', () => {
    expect(calculateUserIdentifierHash(42, 'abcdef12-3456-7890-abcd-ef1234567890', 'Test data')).to.equal(
      525133570835708563534412370019423387022853755228n
    );
    expect(calculateUserIdentifierHash(42, '0xabcdef1234567890', 'Test data')).to.equal(
      830654111289877969679298811043657652615780822337n
    );
  });

  it('treats a 0x prefix as optional', () => {
    expect(calculateUserIdentifierHash(42, '0xabcdef1234567890', 'Test data')).to.equal(
      calculateUserIdentifierHash(42, 'abcdef1234567890', 'Test data')
    );
  });

  it('is a 160-bit value, so it always fits uint160', () => {
    const hash = calculateUserIdentifierHash(42220, ethers.Wallet.createRandom().address, '');
    expect(hash).to.be.lessThan(1n << 160n);
  });

  it('produces a context whose layout the contract can slice', () => {
    const account = ethers.Wallet.createRandom().address;
    const context = buildUserContextData(COFFERDAM_SELF_DEST_CHAIN_ID, account, '');

    // 32-byte chainId + 32-byte userId, with no trailing userDefinedData.
    expect(ethers.dataLength(context)).to.equal(64);
    expect(BigInt(ethers.dataSlice(context, 0, 32))).to.equal(
      BigInt(COFFERDAM_SELF_DEST_CHAIN_ID)
    );
    expect(ethers.dataSlice(context, 32, 64)).to.equal(
      ethers.zeroPadValue(account.toLowerCase(), 32)
    );
  });
});

describe('NullifierRegistry', () => {
  it('deploys with the pinned scope', async () => {
    const { registry } = await deployFixture();
    expect(await registry.expectedScope()).to.equal(COFFERDAM_BIND_V1_SCOPE);
  });

  it('deploys with the pinned Self destination chain id', async () => {
    const { registry } = await deployFixture();
    expect(await registry.selfDestChainId()).to.equal(COFFERDAM_SELF_DEST_CHAIN_ID);
  });

  it('rejects zero addresses in the constructor', async () => {
    const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
    await expect(
      NullifierRegistry.deploy(
        ethers.ZeroAddress,
        ethers.ZeroAddress,
        COFFERDAM_BIND_V1_SCOPE,
        COFFERDAM_SELF_DEST_CHAIN_ID
      )
    ).to.be.revertedWithCustomError(NullifierRegistry, 'ZeroAddress');
  });

  /**
   * Regression: a stale `SELF_SCOPE=0` in `.env` is truthy in JS and
   * `BigInt('0') === 0n`, which once deployed a registry whose immutable
   * `expectedScope` was 0 — reverting `WrongScope` on every real proof.
   * The constructor must refuse it so the deploy tx fails instead.
   */
  it('rejects a zero expectedScope in the constructor', async () => {
    const { verifier, attesterRegistry } = await deployFixture();
    const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
    await expect(
      NullifierRegistry.deploy(
        await verifier.getAddress(),
        await attesterRegistry.getAddress(),
        0,
        COFFERDAM_SELF_DEST_CHAIN_ID
      )
    ).to.be.revertedWithCustomError(NullifierRegistry, 'ZeroScope');
  });

  it('rejects a zero selfDestChainId in the constructor', async () => {
    const { verifier, attesterRegistry } = await deployFixture();
    const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
    await expect(
      NullifierRegistry.deploy(
        await verifier.getAddress(),
        await attesterRegistry.getAddress(),
        COFFERDAM_BIND_V1_SCOPE,
        0
      )
    ).to.be.revertedWithCustomError(NullifierRegistry, 'ZeroDestChainId');
  });

  it('binds a nullifier and records both directions', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await expect(registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig))
      .to.emit(registry, 'NullifierBound')
      .withArgs(account.address, NULLIFIER, E_PASSPORT_ATTESTATION_ID, COFFERDAM_BIND_V1_SCOPE);

    expect(await registry.nullifierToAccount(NULLIFIER)).to.equal(account.address);
    expect(await registry.accountToNullifier(account.address)).to.equal(NULLIFIER);
    expect(await registry.isAccountBound(account.address)).to.equal(true);
    expect(await registry.isNullifierBound(NULLIFIER)).to.equal(true);
  });

  it('accepts a bind carrying non-empty userDefinedData', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({
      account: account.address,
      userDefinedData: 'cofferdam-bind:v1',
    });
    const sig = await signBind(pubSignals);

    // Trailing context bytes are part of the commitment, so an arbitrary-length
    // payload must still verify.
    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.emit(registry, 'NullifierBound');
  });

  it('lets anyone relay a validly attested bind', async () => {
    const { registry, account, outsider, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    // The bind is authorised by the attester signature, not msg.sender.
    await expect(
      (registry.connect(outsider) as any).verifyAndBind(
        account.address,
        A,
        B,
        C,
        pubSignals,
        context,
        sig
      )
    ).to.emit(registry, 'NullifierBound');
  });

  it('reverts ZeroAddress for a zero account', async () => {
    const { registry, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: ethers.ZeroAddress });
    const sig = await signBind(pubSignals);

    await expect(
      registry.verifyAndBind(ethers.ZeroAddress, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'ZeroAddress');
  });

  it('reverts WrongScope when the proof scope does not match', async () => {
    const { registry, account, signBind } = await deployFixture();
    const wrongScope = hashEndpointWithScope(COFFERDAM_SELF_HOST, 'cofferdam-sepolia');
    const { pubSignals, context } = buildBind({ account: account.address, scope: wrongScope });
    const sig = await signBind(pubSignals);

    await expect(registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig))
      .to.be.revertedWithCustomError(registry, 'WrongScope')
      .withArgs(COFFERDAM_BIND_V1_SCOPE, wrongScope);
  });

  it('reverts WrongAttestationId for non-passport attestations', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address, attestationId: 2n });
    const sig = await signBind(pubSignals);

    await expect(registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig))
      .to.be.revertedWithCustomError(registry, 'WrongAttestationId')
      .withArgs(E_PASSPORT_ATTESTATION_ID, 2n);
  });

  it('reverts MalformedUserContext for a context shorter than 64 bytes', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, ethers.ZeroHash, sig)
    )
      .to.be.revertedWithCustomError(registry, 'MalformedUserContext')
      .withArgs(32);
  });

  it('reverts WrongDestChainId when the context targets another chain', async () => {
    const { registry, account, signBind } = await deployFixture();
    // Self folds its own destChainID into the commitment; a proof generated for
    // a different declared chain must not bind here.
    const { pubSignals, context } = buildBind({ account: account.address, destChainId: 8453 });
    const sig = await signBind(pubSignals);

    await expect(registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig))
      .to.be.revertedWithCustomError(registry, 'WrongDestChainId')
      .withArgs(COFFERDAM_SELF_DEST_CHAIN_ID, 8453);
  });

  it('reverts UserIdentifierMismatch when the context names another account', async () => {
    const { registry, account, other, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({
      account: account.address,
      userId: other.address,
    });
    const sig = await signBind(pubSignals);

    // The commitment is internally consistent, but it does not name `account`.
    await expect(registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig))
      .to.be.revertedWithCustomError(registry, 'UserIdentifierMismatch')
      .withArgs(account.address, other.address);
  });

  /**
   * Guards the userIdType regression: the app defaults `SelfApp.userId` to a
   * random UUID. That yields a perfectly valid Self commitment, so the proof
   * itself verifies — but the context does not name the AA account, so the
   * bind can never succeed. The SelfApp config must use the AA address.
   */
  it('reverts UserIdentifierMismatch for a UUID userId', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({
      account: account.address,
      userId: '5f2b1c8a-9d4e-4f7a-b3c6-d8e1f2a3b4c5',
    });
    const sig = await signBind(pubSignals);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UserIdentifierMismatch');
  });

  it('reverts UserIdentifierCommitmentMismatch when context and signal disagree', async () => {
    const { registry, account, signBind } = await deployFixture();
    // Signal derived with userDefinedData set, context built without it: the
    // account and chain checks pass, only the recomputed hash catches this.
    const { pubSignals } = buildBind({
      account: account.address,
      userDefinedData: 'tampered',
    });
    const { context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UserIdentifierCommitmentMismatch');
  });

  it('reverts UntrustedAttester for a signature from an unknown key', async () => {
    const { registry, account, outsider, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals, outsider);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
  });

  it('reverts UntrustedAttester after the attester is removed', async () => {
    const { registry, attesterRegistry, attester, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await (await attesterRegistry.removeAttester(attester.address)).wait();

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
  });

  /**
   * `attesterMessageHash` commits to chainid and the registry address, so a
   * signature harvested from one deployment cannot be replayed against a
   * second registry on the same chain.
   */
  it('does not accept a signature bound to a different registry', async () => {
    const { registry, verifier, attesterRegistry, account, signBind } = await deployFixture();
    const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
    const otherRegistry = await NullifierRegistry.deploy(
      await verifier.getAddress(),
      await attesterRegistry.getAddress(),
      COFFERDAM_BIND_V1_SCOPE,
      COFFERDAM_SELF_DEST_CHAIN_ID
    );
    await otherRegistry.waitForDeployment();

    const { pubSignals, context } = buildBind({ account: account.address });
    // Signed for `otherRegistry`, replayed against `registry`.
    const sig = await signBind(pubSignals, undefined, otherRegistry);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
  });

  it('reverts if the pubSignals are tampered with after signing', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    const tampered = [...pubSignals];
    tampered[IDX.NULLIFIER] = NULLIFIER + 1n;

    await expect(
      registry.verifyAndBind(account.address, A, B, C, tampered, context, sig)
    ).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
  });

  it('reverts InvalidProof when the verifier rejects', async () => {
    const { registry, account, signBind } = await deployFixture({ rejectProofs: true });
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'InvalidProof');
  });

  it('reverts NullifierAlreadyBound when one passport targets a second account', async () => {
    const { registry, account, other, attester, signBind } = await deployFixture();
    const first = buildBind({ account: account.address });
    await (
      await registry.verifyAndBind(
        account.address,
        A,
        B,
        C,
        first.pubSignals,
        first.context,
        await signBind(first.pubSignals)
      )
    ).wait();

    // Same nullifier, different account — the sybil case this contract exists to stop.
    const second = buildBind({ account: other.address });
    const msgHash = await registry.attesterMessageHash(other.address, second.pubSignals);
    const sig = await attester.signMessage(ethers.getBytes(msgHash));

    await expect(
      registry.verifyAndBind(other.address, A, B, C, second.pubSignals, second.context, sig)
    )
      .to.be.revertedWithCustomError(registry, 'NullifierAlreadyBound')
      .withArgs(NULLIFIER, account.address);
  });

  it('reverts AccountAlreadyBound when one account presents a second passport', async () => {
    const { registry, account, signBind } = await deployFixture();
    const first = buildBind({ account: account.address });
    await (
      await registry.verifyAndBind(
        account.address,
        A,
        B,
        C,
        first.pubSignals,
        first.context,
        await signBind(first.pubSignals)
      )
    ).wait();

    const second = buildBind({ account: account.address, nullifier: NULLIFIER + 1n });
    await expect(
      registry.verifyAndBind(
        account.address,
        A,
        B,
        C,
        second.pubSignals,
        second.context,
        await signBind(second.pubSignals)
      )
    )
      .to.be.revertedWithCustomError(registry, 'AccountAlreadyBound')
      .withArgs(account.address, NULLIFIER);
  });

  it('reverts AccountAlreadyBound on an exact replay', async () => {
    const { registry, account, signBind } = await deployFixture();
    const { pubSignals, context } = buildBind({ account: account.address });
    const sig = await signBind(pubSignals);

    await (
      await registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).wait();
    await expect(
      registry.verifyAndBind(account.address, A, B, C, pubSignals, context, sig)
    ).to.be.revertedWithCustomError(registry, 'AccountAlreadyBound');
  });
});

describe('SelfAttesterRegistry', () => {
  it('registers initial attesters from the constructor', async () => {
    const { attesterRegistry, attester } = await deployFixture();
    expect(await attesterRegistry.isTrustedAttester(attester.address)).to.equal(true);
    expect(await attesterRegistry.trustedAttesterCount()).to.equal(1n);
  });

  it('restricts attester mutation to the owner', async () => {
    const { attesterRegistry, outsider } = await deployFixture();
    await expect(
      (attesterRegistry.connect(outsider) as any).addAttester(outsider.address)
    ).to.be.revertedWithCustomError(attesterRegistry, 'NotOwner');
    await expect(
      (attesterRegistry.connect(outsider) as any).removeAttester(outsider.address)
    ).to.be.revertedWithCustomError(attesterRegistry, 'NotOwner');
  });

  it('rejects malformed signatures', async () => {
    const { attesterRegistry } = await deployFixture();
    await expect(
      attesterRegistry.verifyAttesterSig(ethers.ZeroHash, '0xdead')
    ).to.be.revertedWithCustomError(attesterRegistry, 'InvalidSignatureLength');
  });

  it('rejects high-s (malleable) signatures', async () => {
    const { attesterRegistry, attester } = await deployFixture();
    const digest = ethers.id('malleability-probe');
    const sig = ethers.Signature.from(await attester.signMessage(ethers.getBytes(digest)));

    // Flip to the equivalent high-s form; EIP-2 canonicalisation must reject it.
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const highS = ethers.zeroPadValue(ethers.toBeHex(N - BigInt(sig.s)), 32);
    const flipped = ethers.concat([sig.r, highS, new Uint8Array([sig.v === 27 ? 28 : 27])]);

    await expect(
      attesterRegistry.verifyAttesterSig(digest, flipped)
    ).to.be.revertedWithCustomError(attesterRegistry, 'InvalidSignatureValueS');
  });

  it('supports two-step ownership transfer', async () => {
    const { attesterRegistry, deployer, other } = await deployFixture();
    await (await attesterRegistry.transferOwnership(other.address)).wait();
    expect(await attesterRegistry.owner()).to.equal(deployer.address);

    await (await (attesterRegistry.connect(other) as any).acceptOwnership()).wait();
    expect(await attesterRegistry.owner()).to.equal(other.address);
    expect(await attesterRegistry.pendingOwner()).to.equal(ethers.ZeroAddress);
  });
});
