import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import type { Signer } from 'ethers';
import { TIER, NO_PERMISSION, permission, sessionKey, webauthnKey, packSig, userOp } from './helpers/keys';
import { COFFERDAM_BIND_V1_SCOPE } from '../scripts/lib/selfScope';
import {
  COFFERDAM_SELF_DEST_CHAIN_ID,
  buildUserContextData,
  calculateUserIdentifierHash,
} from '../scripts/lib/selfUserContext';

const MOCK_VERIFIER = 'contracts/test/MockGroth16Verifier.sol:MockGroth16Verifier';
const REJECTING_VERIFIER = 'contracts/test/MockGroth16Verifier.sol:RejectingGroth16Verifier';
const IDX = { NULLIFIER: 7, ATTESTATION_ID: 8, SCOPE: 19, USER_IDENTIFIER: 20 } as const;
const NULLIFIER = 0x5eedn;
const PROOF = { a: [0n, 0n], b: [[0n, 0n], [0n, 0n]], c: [0n, 0n] };
const DAY = 86400n;
const PROBATION = 3n * DAY;
const PARTNER_ID = ethers.id('offshoresync');

/** A `disclose` proof's public signals and `userContextData` for `account`. */
function proofFor(account: string, nullifier = NULLIFIER, userId = account) {
  const pubSignals = new Array<bigint>(21).fill(0n);
  pubSignals[IDX.NULLIFIER] = nullifier;
  pubSignals[IDX.ATTESTATION_ID] = 1n;
  pubSignals[IDX.SCOPE] = COFFERDAM_BIND_V1_SCOPE;
  pubSignals[IDX.USER_IDENTIFIER] = calculateUserIdentifierHash(COFFERDAM_SELF_DEST_CHAIN_ID, userId, '');
  return { ...PROOF, pubSignals, userContextData: buildUserContextData(COFFERDAM_SELF_DEST_CHAIN_ID, userId, '') };
}

describe('CofferdamAccount4337 hard recovery and probation (decision 0023)', () => {
  let entryPoint: Signer;
  let epAddr: string;
  let owner: Signer;
  let relayer: Signer;
  let selfAttester: ReturnType<typeof ethers.Wallet.createRandom>;
  let ceremonyAttester: ReturnType<typeof ethers.Wallet.createRandom>;
  let partnerBackend: ReturnType<typeof ethers.Wallet.createRandom>;
  let moduleRegistry: any;
  let ceremonyRegistry: any;
  let selfAttesterRegistry: any;
  let highModule: any;
  let partnerModule: any;
  let managedModule: any;
  let counter: any;
  let counterAddr: string;
  let INC: string;
  let ACTION: string;

  before(async () => {
    [owner, entryPoint, relayer] = await ethers.getSigners();
    epAddr = await entryPoint.getAddress();
    selfAttester = ethers.Wallet.createRandom();
    ceremonyAttester = ethers.Wallet.createRandom();
    partnerBackend = ethers.Wallet.createRandom();

    highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
    partnerModule = await (await ethers.getContractFactory('PartnerPasskeyAuthority')).deploy();
    managedModule = await (await ethers.getContractFactory('SessionKeyAuthority')).deploy();
    moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(
      await owner.getAddress(),
      [highModule, partnerModule, managedModule].map((m) => m.target as string),
    );
    ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(
      await owner.getAddress(),
      [ceremonyAttester.address],
    );
    selfAttesterRegistry = await (await ethers.getContractFactory('SelfAttesterRegistry')).deploy(
      await owner.getAddress(),
      [selfAttester.address],
    );
    counter = await (await ethers.getContractFactory('MockCounter')).deploy();
    counterAddr = await counter.getAddress();
    INC = counter.interface.getFunction('increment')!.selector;
  });

  async function nullifierRegistry(rejectProofs = false) {
    const verifier = await (await ethers.getContractFactory(rejectProofs ? REJECTING_VERIFIER : MOCK_VERIFIER)).deploy();
    return (await ethers.getContractFactory('NullifierRegistry')).deploy(
      verifier,
      selfAttesterRegistry,
      COFFERDAM_BIND_V1_SCOPE,
      COFFERDAM_SELF_DEST_CHAIN_ID,
      0n,
    ) as Promise<any>;
  }

  /** A High-genesis account, bound to `nullifier` on `registry` unless `bind` is false. */
  async function setup(opts: { delay?: bigint; bind?: boolean; registry?: any; nullifier?: bigint } = {}) {
    const registry = opts.registry ?? (await nullifierRegistry());
    const high = webauthnKey();
    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account: any = await Account.deploy(
      epAddr, moduleRegistry, ceremonyRegistry, registry, opts.delay ?? 0n, highModule, high.config, NO_PERMISSION,
    );
    const addr = await account.getAddress();
    if (opts.bind ?? true) {
      const p = proofFor(addr, opts.nullifier ?? NULLIFIER);
      const sig = await selfAttester.signMessage(ethers.getBytes(await registry.attesterMessageHash(addr, p.pubSignals)));
      await registry.verifyAndBind(addr, p.a, p.b, p.c, p.pubSignals, p.userContextData, sig);
    }
    ACTION = await account.ACTION_RECOVER_HIGH();
    return { account, addr, registry, high };
  }

  /** Everything `recoverHigh` needs for `newKey`, bound to the current nonce. */
  async function bundle(
    account: any,
    registry: any,
    newKey = webauthnKey(),
    o: { proof?: ReturnType<typeof proofFor>; selfSigner?: any; ceremonySigner?: any; nonce?: bigint; assertion?: string } = {},
  ) {
    const addr = await account.getAddress();
    const nonce = o.nonce ?? (await account.ceremonyNonce());
    const proof = o.proof ?? proofFor(addr);
    const selfSig = await (o.selfSigner ?? selfAttester).signMessage(
      ethers.getBytes(await registry.recoveryMessageHash(addr, proof.pubSignals, nonce)),
    );
    const now = BigInt(await time.latest());
    const [notBefore, expiry] = [now - 60n, now + 600n];
    const h = await account.ceremonyHash(ACTION, ethers.keccak256(newKey.config), ethers.ZeroHash, nonce, notBefore, expiry);
    const attestation = { notBefore, expiry, signature: await (o.ceremonySigner ?? ceremonyAttester).signMessage(ethers.getBytes(h)) };
    const assertion = o.assertion ?? newKey.sign(await account.recoveryChallenge(nonce));
    return { newKey, args: [highModule.target, newKey.config, assertion, proof, selfSig, attestation] as const };
  }

  function recover(account: any, b: { args: readonly unknown[] }) {
    return account.connect(relayer).recoverHigh(...b.args);
  }

  function validate(account: any, addr: string, authorityId: bigint | number, callData: string, sign: (h: string) => string) {
    const hash = ethers.hexlify(ethers.randomBytes(32));
    return account.connect(entryPoint).validateUserOp.staticCall(userOp(addr, callData, packSig(authorityId, sign(hash))), hash, 0);
  }

  const enc = (account: any, fn: string, args: unknown[]) => account.interface.encodeFunctionData(fn, args);

  // ── recoverHigh ────────────────────────────────────────────────────────────

  describe('recoverHigh', () => {
    it('replaces every High with the new passkey at once when the delay is zero, keeping grants', async () => {
      const { account, addr, registry, high } = await setup();
      await account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION); // id 1
      const managed = sessionKey();
      await account.connect(entryPoint).addAuthority(managedModule, managed.config, permission([[counterAddr, INC]])); // id 2
      expect(await account.passkeyCount()).to.equal(2);

      const b = await bundle(account, registry);
      await expect(recover(account, b))
        .to.emit(account, 'AuthorityRevoked').withArgs(0)
        .and.to.emit(account, 'AuthorityRevoked').withArgs(1)
        .and.to.emit(account, 'HighRecovered').withArgs(3);

      expect(await account.passkeyCount()).to.equal(1);
      expect((await account.getAuthority(0)).active).to.be.false;
      expect((await account.getAuthority(1)).active).to.be.false;
      expect((await account.getAuthority(2)).active).to.be.true; // the grant stays
      expect(await account.probationEndsAt(3)).to.equal(0); // the recovered key is not probationary
      expect(await account.ceremonyNonce()).to.equal(1);
      expect(await registry.accountToNullifier(addr)).to.equal(NULLIFIER); // the binding stays

      const add = enc(account, 'addAuthority', [highModule.target, webauthnKey().config, NO_PERMISSION]);
      expect(await validate(account, addr, 3, add, (h) => b.newKey.sign(h))).to.equal(0n);
      await expect(validate(account, addr, 0, add, (h) => high.sign(h)))
        .to.be.revertedWithCustomError(account, 'InactiveAuthority').withArgs(0);
    });

    it('is single-use: the same bundle never works twice', async () => {
      const { account, registry } = await setup();
      const b = await bundle(account, registry);
      await recover(account, b);
      await expect(recover(account, b)).to.be.reverted;
    });

    it('needs the identity bound to this account', async () => {
      const unbound = await setup({ bind: false });
      await expect(recover(unbound.account, await bundle(unbound.account, unbound.registry)))
        .to.be.revertedWithCustomError(unbound.account, 'NotBoundIdentity');

      // Another passport, bound elsewhere, proves a different nullifier.
      const { account, addr, registry } = await setup();
      const other = await bundle(account, registry, webauthnKey(), { proof: proofFor(addr, NULLIFIER + 1n) });
      await expect(recover(account, other)).to.be.revertedWithCustomError(account, 'NotBoundIdentity');
    });

    it('needs a proof naming this account', async () => {
      const { account, registry } = await setup();
      const stranger = ethers.Wallet.createRandom().address;
      const b = await bundle(account, registry, webauthnKey(), { proof: proofFor(stranger) });
      await expect(recover(account, b)).to.be.revertedWithCustomError(registry, 'UserIdentifierMismatch');
    });

    it('needs a valid Groth16 proof', async () => {
      const { account, registry } = await setup({ registry: await nullifierRegistry(true), bind: false });
      await expect(recover(account, await bundle(account, registry)))
        .to.be.revertedWithCustomError(registry, 'InvalidProof');
    });

    it("needs the Self attester's co-sign on this nonce", async () => {
      const { account, registry } = await setup();
      const forged = await bundle(account, registry, webauthnKey(), { selfSigner: ethers.Wallet.createRandom() });
      await expect(recover(account, forged)).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
      const stale = await bundle(account, registry, webauthnKey(), { nonce: 7n });
      await expect(recover(account, stale)).to.be.reverted;
    });

    it('a bind signature never replays as a recovery co-sign', async () => {
      const { account, addr, registry } = await setup();
      const p = proofFor(addr);
      const bindSig = await selfAttester.signMessage(ethers.getBytes(await registry.attesterMessageHash(addr, p.pubSignals)));
      const b = await bundle(account, registry);
      const args = [...b.args] as unknown[];
      args[4] = bindSig;
      await expect(account.connect(relayer).recoverHigh(...args)).to.be.revertedWithCustomError(registry, 'UntrustedAttester');
    });

    it("needs the ceremony attester's co-sign over the new key", async () => {
      const { account, registry } = await setup();
      const forged = await bundle(account, registry, webauthnKey(), { ceremonySigner: ethers.Wallet.createRandom() });
      await expect(recover(account, forged)).to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');

      // The co-sign names one key; another key cannot ride on it.
      const b = await bundle(account, registry);
      const swapped = webauthnKey();
      const args = [...b.args] as unknown[];
      args[1] = swapped.config;
      args[2] = swapped.sign(await account.recoveryChallenge(await account.ceremonyNonce()));
      await expect(account.connect(relayer).recoverHigh(...args))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
    });

    it('needs a cofferdam.xyz passkey that signed the recovery challenge', async () => {
      const { account, registry } = await setup();
      const key = webauthnKey();
      const nonce = await account.ceremonyNonce();
      const wrongRp = await bundle(account, registry, key, { assertion: key.sign(await account.recoveryChallenge(nonce), { signedRpId: 'evil.com' }) });
      await expect(recover(account, wrongRp)).to.be.revertedWithCustomError(account, 'InvalidNewKeyAssertion');
      const firstHighChallenge = await bundle(account, registry, key, { assertion: key.sign(await account.firstHighChallenge(nonce)) });
      await expect(recover(account, firstHighChallenge)).to.be.revertedWithCustomError(account, 'InvalidNewKeyAssertion');

      const b = await bundle(account, registry);
      const args = [...b.args] as unknown[];
      args[0] = partnerModule.target;
      await expect(account.connect(relayer).recoverHigh(...args))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(TIER.Partner);
    });

    it('is not a path to the first High on a Partner account', async () => {
      const registry = await nullifierRegistry();
      const key = webauthnKey('offshoresync.com');
      const grant = permission([[counterAddr, INC]], { expiry: BigInt(await time.latest()) + 90n * DAY });
      const account: any = await (await ethers.getContractFactory('CofferdamAccount4337')).deploy(
        epAddr, moduleRegistry, ceremonyRegistry, registry, 0n, partnerModule, key.partnerConfig(PARTNER_ID, partnerBackend.address), grant,
      );
      ACTION = await account.ACTION_RECOVER_HIGH();
      await expect(recover(account, await bundle(account, registry)))
        .to.be.revertedWithCustomError(account, 'NoHighToRecover');
    });
  });

  // ── The recovery delay ─────────────────────────────────────────────────────

  describe('with a recovery delay', () => {
    it('waits, then anyone finalizes; the old High works meanwhile', async () => {
      const { account, addr, registry, high } = await setup({ delay: PROBATION });
      const b = await bundle(account, registry);
      await expect(recover(account, b)).to.emit(account, 'RecoveryRequested');
      const pending = await account.pendingRecovery();
      expect(pending.module).to.equal(highModule.target);
      expect(pending.nullifier).to.equal(NULLIFIER);
      expect(pending.config).to.equal(b.newKey.config);
      expect(await account.passkeyCount()).to.equal(1);

      const inc = enc(account, 'execute', [counterAddr, 0, counter.interface.encodeFunctionData('increment')]);
      expect(await validate(account, addr, 0, inc, (h) => high.sign(h))).to.equal(0n);
      await expect(account.finalizeRecovery()).to.be.revertedWithCustomError(account, 'RecoveryNotReady');

      await time.increaseTo(pending.readyAt);
      await expect(account.connect(relayer).finalizeRecovery()).to.emit(account, 'HighRecovered').withArgs(1);
      expect((await account.getAuthority(0)).active).to.be.false;
      expect((await account.pendingRecovery()).module).to.equal(ethers.ZeroAddress);
      await expect(account.finalizeRecovery()).to.be.revertedWithCustomError(account, 'NoPendingRecovery');
    });

    it('a mature High cancels; nobody else can', async () => {
      const { account, addr, registry, high } = await setup({ delay: PROBATION });
      await recover(account, await bundle(account, registry));
      await expect(account.connect(relayer).cancelRecovery()).to.be.revertedWithCustomError(account, 'NotFromEntryPoint');

      // Signed by the genesis High as the userOp's call or through execute to self.
      const cancel = enc(account, 'cancelRecovery', []);
      expect(await validate(account, addr, 0, cancel, (h) => high.sign(h))).to.equal(0n);
      expect(await validate(account, addr, 0, enc(account, 'execute', [addr, 0, cancel]), (h) => high.sign(h))).to.equal(0n);

      await expect(account.connect(entryPoint).cancelRecovery()).to.emit(account, 'RecoveryCancelled');
      await time.increase(PROBATION);
      await expect(account.finalizeRecovery()).to.be.revertedWithCustomError(account, 'NoPendingRecovery');
      expect((await account.getAuthority(0)).active).to.be.true;
    });

    it('a Partner or Managed grant may not cancel', async () => {
      const { account, addr, registry } = await setup({ delay: PROBATION });
      const managed = sessionKey();
      await account.connect(entryPoint).addAuthority(managedModule, managed.config, permission([[counterAddr, INC]]));
      await recover(account, await bundle(account, registry));
      const cancel = enc(account, 'cancelRecovery', []);
      await expect(validate(account, addr, 1, cancel, (h) => managed.sign(addr, h)))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
      await expect(validate(account, addr, 1, enc(account, 'execute', [addr, 0, cancel]), (h) => managed.sign(addr, h)))
        .to.be.revertedWithCustomError(account, 'CallNotPermitted');
    });

    it('a later request replaces a pending one', async () => {
      const { account, registry } = await setup({ delay: PROBATION });
      await recover(account, await bundle(account, registry));
      const second = await bundle(account, registry);
      await recover(account, second);
      expect((await account.pendingRecovery()).config).to.equal(second.newKey.config);
    });

    it('does not finalize once the identity has moved to another account', async () => {
      const { account, registry } = await setup({ delay: PROBATION });
      await recover(account, await bundle(account, registry));
      // Re-bind (decision 0022) moves the nullifier to a fresh account.
      const fresh = ethers.Wallet.createRandom().address;
      const p = proofFor(fresh);
      const sig = await selfAttester.signMessage(ethers.getBytes(await registry.rebindMessageHash(fresh, p.pubSignals, 0n)));
      await registry.rebind(fresh, p.a, p.b, p.c, p.pubSignals, p.userContextData, sig);
      await time.increase(PROBATION);
      await expect(account.finalizeRecovery()).to.be.revertedWithCustomError(account, 'NotBoundIdentity');
    });
  });

  // ── Probation ──────────────────────────────────────────────────────────────

  describe('probation of a High added by a High', () => {
    async function withSecondHigh() {
      const s = await setup({ bind: false });
      const second = webauthnKey();
      await s.account.connect(entryPoint).addAuthority(highModule, second.config, NO_PERMISSION); // id 1
      const endsAt = BigInt(await time.latest()) + PROBATION;
      return { ...s, second, endsAt, validAfter: endsAt << 208n };
    }

    it('records the probation end; genesis and recovered Highs have none', async () => {
      const { account, endsAt } = await withSecondHigh();
      expect(await account.PROBATION_PERIOD()).to.equal(PROBATION);
      expect(await account.probationEndsAt(0)).to.equal(0);
      expect(await account.probationEndsAt(1)).to.equal(endsAt);
    });

    it('may transact at once', async () => {
      const { account, addr, second } = await withSecondHigh();
      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 1, enc(account, 'execute', [counterAddr, 0, inc]), (h) => second.sign(h))).to.equal(0n);
      expect(await validate(account, addr, 1, enc(account, 'executeBatch', [[counterAddr], [0], [inc]]), (h) => second.sign(h))).to.equal(0n);
    });

    it('may not add, revoke or cancel a recovery until it matures', async () => {
      const { account, addr, second, validAfter } = await withSecondHigh();
      const sign = (h: string) => second.sign(h);
      const add = enc(account, 'addAuthority', [highModule.target, webauthnKey().config, NO_PERMISSION]);
      const revoke = enc(account, 'revokeAuthority', [0]);
      const inc = counter.interface.encodeFunctionData('increment');
      for (const callData of [
        add,
        revoke,
        enc(account, 'cancelRecovery', []),
        enc(account, 'execute', [addr, 0, revoke]),
        enc(account, 'executeBatch', [[counterAddr, addr], [0, 0], [inc, add]]),
      ]) {
        expect(await validate(account, addr, 1, callData, sign)).to.equal(validAfter);
      }
    });

    it('any older High may revoke it meanwhile', async () => {
      const { account, addr, high } = await withSecondHigh();
      expect(await validate(account, addr, 0, enc(account, 'revokeAuthority', [1]), (h) => high.sign(h))).to.equal(0n);
      await account.connect(entryPoint).revokeAuthority(1);
      expect((await account.getAuthority(1)).active).to.be.false;
    });

    it('every High added by a High starts its own probation', async () => {
      const { account, endsAt } = await withSecondHigh();
      await time.increaseTo(endsAt);
      await account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION); // id 2
      expect(await account.probationEndsAt(2)).to.equal(BigInt(await time.latest()) + PROBATION);
    });
  });
});
