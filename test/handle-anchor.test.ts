import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers';
import { ethers } from 'hardhat';
import { Wallet } from 'ethers';
import type { CofferdamHandleAnchor } from '../typechain-types';

import {
  ANCHOR_SAFE_ACTIONS,
  HANDLE_ANCHOR_DOMAIN_NAME,
  HANDLE_ANCHOR_MAINNET,
  HANDLE_ANCHOR_TYPES,
  HandleAnchorType,
  anchorCall,
  encodeType,
  handleAnchorDomain,
  handleId,
  metaAddressRefusal,
  typesFor,
} from '../scripts/lib/handleAnchor';
import { SAFE_ACTIONS, parseSafeAction } from '../scripts/lib/safe';

// Unit tests of CofferdamHandleAnchor (workspace decision 0086, rule 3;
// runbook docs/runbooks/handles-build.md step 2) on the in-process network,
// with 0086's own delays. The Safe is a plain signer here; the real Safe v1.4.1
// and the chain-8453 checks run in test/fork/handle-anchor-fork.test.ts.
//
// test/fixtures/handleAnchorTypes.json is the SDK's shared fixture (runbook
// step 1), copied byte for byte from cofferdam-sdk
// packages/core/test/fixtures/handleAnchorTypes.json (branch
// claude/handles-sdk, 2ceb529); the SDK owns the types and this contract
// matches them.

const DAY = 24 * 3600;
const { changeDelay: CHANGE_DELAY, freezeDuration: FREEZE, quarantine: QUARANTINE, safeDelay: SAFE_DELAY } = HANDLE_ANCHOR_MAINNET;
const SDK_FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'handleAnchorTypes.json'), 'utf8'));

/** Fixed test keys: never used outside tests. */
const key = (seed: string) => new Wallet(ethers.id(`cofferdam-handle-anchor-test:${seed}`));
const compressed = (seed: string) => ethers.SigningKey.computePublicKey(key(seed).signingKey.publicKey, true);
/** A scheme 1 meta-address from two fixed test keys, spending first. */
const metaOf = (seed: string) => ethers.concat([compressed(`${seed}:spend`), compressed(`${seed}:view`)]);

// The SDK fixture's registrar and the fixture phrase's epoch 0 and 1 keys and meta-addresses.
const REGISTRAR = new Wallet(SDK_FIXTURE.keys.registrar.privateKey);
const OWNER_E0 = new Wallet(SDK_FIXTURE.keys.owner.privateKey);
const OWNER_E1 = new Wallet(SDK_FIXTURE.keys.newOwner.privateKey);
const META_E0: string = SDK_FIXTURE.epochs[0].metaAddress;
const META_E1: string = SDK_FIXTURE.epochs[1].metaAddress;
const REGISTRAR_2 = key('registrar-2');
const OWNER_E2 = key('ana:epoch2');
const THIEF = key('thief');
const META_E2 = metaOf('ana:epoch2');
const LABEL = 'ana';
const ID = handleId(LABEL);
const FAR = 2n ** 48n;

describe('CofferdamHandleAnchor (decision 0086, rule 3)', function () {
  async function deploy() {
    const [safe, relayer, stranger, newSafe] = await ethers.getSigners();
    const Anchor = await ethers.getContractFactory('CofferdamHandleAnchor');
    const anchor = (await Anchor.deploy(safe.address, CHANGE_DELAY, FREEZE, QUARANTINE, SAFE_DELAY, [REGISTRAR.address])) as unknown as CofferdamHandleAnchor;
    await anchor.waitForDeployment();
    const domain = handleAnchorDomain((await ethers.provider.getNetwork()).chainId, await anchor.getAddress());
    return { anchor, safe, relayer, stranger, newSafe, domain };
  }

  type Ctx = Awaited<ReturnType<typeof deploy>>;

  const sign = (ctx: Ctx, signer: Wallet, type: HandleAnchorType, message: Record<string, unknown>) =>
    signer.signTypedData(ctx.domain, typesFor(type), message);
  const nonceOf = async (ctx: Ctx, id = ID) => ctx.anchor.nonceOf(id);
  const frozenUntilOf = async (ctx: Ctx, id = ID) => (await ctx.anchor.recordOf(id)).frozenUntil;

  async function claim(
    ctx: Ctx,
    o: { id?: string; owner?: Wallet; meta?: string; registrar?: Wallet; ownerSigner?: Wallet; nonce?: bigint; serial?: bigint; deadline?: bigint } = {},
  ) {
    const id = o.id ?? ID;
    const owner = o.owner ?? OWNER_E0;
    const meta = o.meta ?? META_E0;
    const serial = o.serial ?? (await ctx.anchor.recordOf(id)).serial + 1n;
    const nonce = o.nonce ?? (await nonceOf(ctx, id));
    const deadline = o.deadline ?? FAR;
    const rSig = await sign(ctx, o.registrar ?? REGISTRAR, 'RegistrarClaim', { handleId: id, owner: owner.address, serial, nonce, deadline });
    const oSig = await sign(ctx, o.ownerSigner ?? owner, 'OwnerClaim', { handleId: id, metaAddress: meta, serial });
    return ctx.anchor.connect(ctx.relayer).claim(id, owner.address, meta, deadline, rSig, oSig);
  }

  async function claimed() {
    const ctx = await deploy();
    await claim(ctx);
    return ctx;
  }

  async function queueTransfer(ctx: Ctx, o: { from?: Wallet; to?: Wallet; meta?: string; coSigner?: Wallet; deadline?: bigint } = {}) {
    const from = o.from ?? OWNER_E0;
    const to = o.to ?? OWNER_E1;
    const meta = o.meta ?? META_E1;
    const deadline = o.deadline ?? FAR;
    const nonce = await nonceOf(ctx);
    const previousOwner = (await ctx.anchor.recordOf(ID)).owner;
    const ownerSig = await sign(ctx, from, 'TransferOwner', { handleId: ID, newOwner: to.address, newMetaAddress: meta, nonce, deadline });
    const acceptSig = await sign(ctx, o.coSigner ?? to, 'TransferOwnerAccept', { handleId: ID, previousOwner, newMetaAddress: meta, nonce, deadline });
    return ctx.anchor.connect(ctx.relayer).transferOwner(ID, to.address, meta, deadline, ownerSig, acceptSig);
  }

  async function queueSetMeta(ctx: Ctx, o: { by?: Wallet; meta?: string } = {}) {
    const meta = o.meta ?? META_E1;
    const msg = { handleId: ID, newMetaAddress: meta, nonce: await nonceOf(ctx), deadline: FAR };
    return ctx.anchor.connect(ctx.relayer).setMetaAddress(ID, meta, FAR, await sign(ctx, o.by ?? OWNER_E0, 'SetMetaAddress', msg));
  }

  async function queueRelease(ctx: Ctx, o: { by?: Wallet; id?: string } = {}) {
    const id = o.id ?? ID;
    const msg = { handleId: id, nonce: await nonceOf(ctx, id), deadline: FAR };
    return ctx.anchor.connect(ctx.relayer).release(id, FAR, await sign(ctx, o.by ?? OWNER_E0, 'Release', msg));
  }

  async function cancelBy(ctx: Ctx, by: Wallet, pendingNonce?: bigint) {
    const pending = pendingNonce ?? (await ctx.anchor.recordOf(ID)).pendingNonce;
    const msg = { handleId: ID, pendingNonce: pending, nonce: await nonceOf(ctx), deadline: FAR };
    return ctx.anchor.connect(ctx.relayer).cancel(ID, pending, FAR, await sign(ctx, by, 'Cancel', msg));
  }

  async function advance(
    ctx: Ctx,
    o: { from?: Wallet; to?: Wallet; meta?: string; ownerSigner?: Wallet; newSigner?: Wallet; registrar?: Wallet } = {},
  ) {
    const from = o.from ?? OWNER_E0;
    const to = o.to ?? OWNER_E1;
    const meta = o.meta ?? META_E1;
    const nonce = await nonceOf(ctx);
    const sigs = await advanceSigs(ctx, { from, to, meta, nonce, ...o });
    return ctx.anchor.connect(ctx.relayer).advance(ID, to.address, meta, FAR, ...sigs);
  }

  async function advanceSigs(
    ctx: Ctx,
    o: { from: Wallet; to: Wallet; meta: string; nonce: bigint; ownerSigner?: Wallet; newSigner?: Wallet; registrar?: Wallet },
  ): Promise<[string, string, string]> {
    const base = { handleId: ID, newMetaAddress: o.meta, nonce: o.nonce, deadline: FAR };
    return [
      await sign(ctx, o.ownerSigner ?? o.from, 'Advance', { ...base, newOwner: o.to.address }),
      await sign(ctx, o.newSigner ?? o.to, 'AdvanceAccept', { ...base, previousOwner: o.from.address }),
      await sign(ctx, o.registrar ?? REGISTRAR, 'RegistrarAdvance', { ...base, previousOwner: o.from.address, newOwner: o.to.address }),
    ];
  }

  async function holdBy(ctx: Ctx, o: { registrar?: Wallet; id?: string } = {}) {
    const id = o.id ?? ID;
    const sig = await sign(ctx, o.registrar ?? REGISTRAR, 'Hold', { handleId: id, nonce: await nonceOf(ctx, id), deadline: FAR });
    return ctx.anchor.connect(ctx.relayer).hold(id, FAR, sig);
  }

  async function renewBy(ctx: Ctx, o: { registrar?: Wallet; frozenUntil?: bigint } = {}) {
    const frozenUntil = o.frozenUntil ?? (await frozenUntilOf(ctx));
    const sig = await sign(ctx, o.registrar ?? REGISTRAR, 'RenewHold', { handleId: ID, frozenUntil, nonce: await nonceOf(ctx), deadline: FAR });
    return ctx.anchor.connect(ctx.relayer).renewHold(ID, frozenUntil, FAR, sig);
  }

  async function vetoBy(ctx: Ctx, pendingNonce: bigint, o: { registrar?: Wallet } = {}) {
    const sig = await sign(ctx, o.registrar ?? REGISTRAR, 'Veto', { handleId: ID, pendingNonce, nonce: await nonceOf(ctx), deadline: FAR });
    return ctx.anchor.connect(ctx.relayer).veto(ID, pendingNonce, FAR, sig);
  }

  async function unfreezeBy(ctx: Ctx, o: { owner?: Wallet; registrar?: Wallet; frozenUntil?: bigint } = {}) {
    const frozenUntil = o.frozenUntil ?? (await frozenUntilOf(ctx));
    const msg = { handleId: ID, frozenUntil, nonce: await nonceOf(ctx), deadline: FAR };
    return ctx.anchor
      .connect(ctx.relayer)
      .unfreeze(ID, frozenUntil, FAR, await sign(ctx, o.owner ?? OWNER_E0, 'Unfreeze', msg), await sign(ctx, o.registrar ?? REGISTRAR, 'RegistrarUnfreeze', msg));
  }

  async function safeRekey(ctx: Ctx, to = OWNER_E2, meta = META_E2) {
    await ctx.anchor.connect(ctx.safe).scheduleRekey(ID, to.address, meta);
    await time.increase(SAFE_DELAY);
    return ctx.anchor.connect(ctx.safe).executeRekey(ID, to.address, meta);
  }

  // ── Types, constants and the SDK's fixture ─────────────────────────────────

  describe('EIP-712 types, constants and the SDK fixture', function () {
    it("pins every typehash to the SDK fixture's type strings and to scripts/lib/handleAnchor.ts", async function () {
      const { anchor } = await loadFixture(deploy);
      const onChain: Record<HandleAnchorType, string> = {
        RegistrarClaim: await anchor.REGISTRAR_CLAIM_TYPEHASH(),
        OwnerClaim: await anchor.OWNER_CLAIM_TYPEHASH(),
        TransferOwner: await anchor.TRANSFER_OWNER_TYPEHASH(),
        TransferOwnerAccept: await anchor.TRANSFER_OWNER_ACCEPT_TYPEHASH(),
        SetMetaAddress: await anchor.SET_META_ADDRESS_TYPEHASH(),
        Release: await anchor.RELEASE_TYPEHASH(),
        Cancel: await anchor.CANCEL_TYPEHASH(),
        Advance: await anchor.ADVANCE_TYPEHASH(),
        AdvanceAccept: await anchor.ADVANCE_ACCEPT_TYPEHASH(),
        RegistrarAdvance: await anchor.REGISTRAR_ADVANCE_TYPEHASH(),
        Hold: await anchor.HOLD_TYPEHASH(),
        RenewHold: await anchor.RENEW_HOLD_TYPEHASH(),
        Veto: await anchor.VETO_TYPEHASH(),
        Unfreeze: await anchor.UNFREEZE_TYPEHASH(),
        RegistrarUnfreeze: await anchor.REGISTRAR_UNFREEZE_TYPEHASH(),
      };
      const sdkTypes = SDK_FIXTURE.eip712.anchor.types as Record<string, { typeString: string; typeHash: string; fields: unknown[] }>;
      expect(Object.keys(sdkTypes).sort()).to.deep.equal(Object.keys(HANDLE_ANCHOR_TYPES).sort());
      for (const name of Object.keys(HANDLE_ANCHOR_TYPES) as HandleAnchorType[]) {
        expect(encodeType(name), name).to.equal(sdkTypes[name].typeString);
        expect(onChain[name], name).to.equal(sdkTypes[name].typeHash).and.to.equal(ethers.id(encodeType(name)));
        expect(HANDLE_ANCHOR_TYPES[name], name).to.deep.equal(sdkTypes[name].fields);
      }
    });

    it("uses the SDK's domain (CofferdamHandleAnchor, version 1) and reports it through EIP-5267", async function () {
      const { anchor, domain } = await loadFixture(deploy);
      const sdkDomain = SDK_FIXTURE.eip712.anchor.domain;
      expect(HANDLE_ANCHOR_DOMAIN_NAME).to.equal(sdkDomain.name);
      expect(sdkDomain.version).to.equal('1');
      expect(ethers.TypedDataEncoder.hashDomain(handleAnchorDomain(BigInt(sdkDomain.chainId), sdkDomain.verifyingContract))).to.equal(sdkDomain.separator);
      expect(await anchor.DOMAIN_SEPARATOR()).to.equal(ethers.TypedDataEncoder.hashDomain(domain));
      const d = await anchor.eip712Domain();
      expect([d.name, d.version, d.chainId, d.verifyingContract]).to.deep.equal([sdkDomain.name, '1', domain.chainId, domain.verifyingContract]);
    });

    it("reproduces every signed anchor vector of the SDK fixture: struct hash, digest and signer", function () {
      const sdkDomain = SDK_FIXTURE.eip712.anchor.domain;
      const domain = handleAnchorDomain(BigInt(sdkDomain.chainId), sdkDomain.verifyingContract);
      const anchorSigned = (SDK_FIXTURE.signed as Array<Record<string, any>>).filter((s) => s.domain === 'anchor');
      expect(anchorSigned.map((s) => s.primaryType).sort()).to.deep.equal(Object.keys(HANDLE_ANCHOR_TYPES).sort());
      for (const s of anchorSigned) {
        const name = s.primaryType as HandleAnchorType;
        const enc = ethers.TypedDataEncoder.from(typesFor(name));
        expect(enc.hashStruct(name, s.message), name).to.equal(s.structHash);
        expect(ethers.TypedDataEncoder.hash(domain, typesFor(name), s.message), name).to.equal(s.digest);
        expect(ethers.recoverAddress(s.digest, s.signature), name).to.equal(s.signerAddress);
      }
    });

    it("derives handleId as the SDK does: keccak256(\"cofferdam-handle-v1:\" ‖ label)", function () {
      for (const { label, handleId: id } of SDK_FIXTURE.handleIds as Array<{ label: string; handleId: string }>) expect(handleId(label)).to.equal(id);
      expect(() => handleId('@ana')).to.throw(/without @/);
    });

    it("carries 0086's mainnet values, the scheme id and the meta-address length", async function () {
      const { anchor } = await loadFixture(deploy);
      expect(await anchor.MAINNET_CHANGE_DELAY()).to.equal(HANDLE_ANCHOR_MAINNET.changeDelay).and.to.equal(72n * 3600n);
      expect(await anchor.MAINNET_FREEZE_DURATION()).to.equal(HANDLE_ANCHOR_MAINNET.freezeDuration).and.to.equal(14n * 86400n);
      expect(await anchor.MAINNET_QUARANTINE()).to.equal(HANDLE_ANCHOR_MAINNET.quarantine).and.to.equal(365n * 86400n);
      expect(await anchor.MAINNET_SAFE_DELAY()).to.equal(HANDLE_ANCHOR_MAINNET.safeDelay).and.to.equal(72n * 3600n);
      expect(await anchor.SCHEME_ID()).to.equal(1n);
      expect(await anchor.META_ADDRESS_LENGTH()).to.equal(66n);
    });

    it('checks a meta-address shape off chain as the contract does', function () {
      expect(metaAddressRefusal(META_E0)).to.equal(null);
      expect(metaAddressRefusal('0x' + '02'.repeat(65))).to.match(/65 bytes/);
      expect(metaAddressRefusal(ethers.concat(['0x04', ethers.dataSlice(META_E0, 1)]))).to.match(/compressed/);
    });
  });

  // ── Constructor ────────────────────────────────────────────────────────────

  describe('constructor', function () {
    it('refuses a zero owner, a zero freeze, delays over their bounds and a zero or duplicate registrar', async function () {
      const Anchor = await ethers.getContractFactory('CofferdamHandleAnchor');
      const [safe] = await ethers.getSigners();
      const ok = [CHANGE_DELAY, FREEZE, QUARANTINE, SAFE_DELAY] as const;
      await expect(Anchor.deploy(ethers.ZeroAddress, ...ok, [])).to.be.revertedWithCustomError(Anchor, 'ZeroAddress');
      await expect(Anchor.deploy(safe.address, CHANGE_DELAY, 0, QUARANTINE, SAFE_DELAY, [])).to.be.revertedWithCustomError(Anchor, 'ZeroFreeze');
      await expect(Anchor.deploy(safe.address, 31n * 86400n, FREEZE, QUARANTINE, SAFE_DELAY, [])).to.be.revertedWithCustomError(Anchor, 'DelayTooLong');
      await expect(Anchor.deploy(safe.address, CHANGE_DELAY, 31n * 86400n, QUARANTINE, SAFE_DELAY, [])).to.be.revertedWithCustomError(Anchor, 'DelayTooLong');
      await expect(Anchor.deploy(safe.address, CHANGE_DELAY, FREEZE, 731n * 86400n, SAFE_DELAY, [])).to.be.revertedWithCustomError(Anchor, 'DelayTooLong');
      await expect(Anchor.deploy(safe.address, CHANGE_DELAY, FREEZE, QUARANTINE, 31n * 86400n, [])).to.be.revertedWithCustomError(Anchor, 'DelayTooLong');
      await expect(Anchor.deploy(safe.address, ...ok, [ethers.ZeroAddress])).to.be.revertedWithCustomError(Anchor, 'ZeroAddress');
      await expect(Anchor.deploy(safe.address, ...ok, [REGISTRAR.address, REGISTRAR.address])).to.be.revertedWithCustomError(Anchor, 'RegistrarAlreadyListed');
    });

    it('takes short delays off mainnet (a Sepolia deploy), and lists the initial registrars', async function () {
      const Anchor = await ethers.getContractFactory('CofferdamHandleAnchor');
      const [safe] = await ethers.getSigners();
      const a = await Anchor.deploy(safe.address, 60, 120, 600, 0, [REGISTRAR.address, REGISTRAR_2.address]);
      expect(await a.CHANGE_DELAY()).to.equal(60n);
      expect(await a.FREEZE_DURATION()).to.equal(120n);
      expect(await a.QUARANTINE()).to.equal(600n);
      expect(await a.SAFE_DELAY()).to.equal(0n);
      expect(await a.isRegistrar(REGISTRAR_2.address)).to.equal(true);
      expect(await a.owner()).to.equal(safe.address);
    });
  });

  // ── Claim ──────────────────────────────────────────────────────────────────

  describe('claim', function () {
    it('claims once with serial 1 and the fixture keys; anyone may submit; a second claim is refused', async function () {
      const ctx = await loadFixture(deploy);
      await expect(claim(ctx)).to.emit(ctx.anchor, 'Claimed').withArgs(ID, OWNER_E0.address, 1n, META_E0, REGISTRAR.address);
      const [owner, serial, meta, derivable] = await ctx.anchor.resolve(ID);
      expect([owner, serial, meta, derivable]).to.deep.equal([OWNER_E0.address, 1n, META_E0, true]);
      expect(await ctx.anchor.stealthMetaAddressOf(ID)).to.deep.equal([1n, META_E0]);
      expect(await ctx.anchor.claimableAt(ID)).to.equal(ethers.MaxUint256);
      expect(await nonceOf(ctx)).to.equal(1n);
      await expect(claim(ctx, { owner: THIEF, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'AlreadyOwned').withArgs(ID);
    });

    it('refuses a claim without the registrar: a key off the list, or a removed registrar', async function () {
      const ctx = await loadFixture(deploy);
      await expect(claim(ctx, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar').withArgs(THIEF.address);
      await ctx.anchor.connect(ctx.safe).removeRegistrar(REGISTRAR.address);
      await expect(claim(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar').withArgs(REGISTRAR.address);
    });

    it("refuses a claim without the owner's signature, or with the owner's over another meta-address", async function () {
      const ctx = await loadFixture(deploy);
      await expect(claim(ctx, { ownerSigner: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E0.address, THIEF.address);
      const rSig = await sign(ctx, REGISTRAR, 'RegistrarClaim', { handleId: ID, owner: OWNER_E0.address, serial: 1n, nonce: 0n, deadline: FAR });
      const oSig = await sign(ctx, OWNER_E0, 'OwnerClaim', { handleId: ID, metaAddress: META_E1, serial: 1n });
      await expect(ctx.anchor.claim(ID, OWNER_E0.address, META_E0, FAR, rSig, oSig)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
    });

    it('refuses a registrar signature replayed with a used nonce, for an old serial, for another owner, or past its deadline', async function () {
      const ctx = await loadFixture(deploy);
      const rSig = await sign(ctx, REGISTRAR, 'RegistrarClaim', { handleId: ID, owner: OWNER_E0.address, serial: 1n, nonce: 0n, deadline: FAR });
      const oSig = await sign(ctx, OWNER_E0, 'OwnerClaim', { handleId: ID, metaAddress: META_E0, serial: 1n });
      await ctx.anchor.claim(ID, OWNER_E0.address, META_E0, FAR, rSig, oSig);
      await queueRelease(ctx);
      await time.increase(CHANGE_DELAY);
      await ctx.anchor.applyChange(ID);
      await time.increase(QUARANTINE);
      // The same pair again: the nonce and the serial moved, so the recovered signer is no registrar.
      await expect(ctx.anchor.claim(ID, OWNER_E0.address, META_E0, FAR, rSig, oSig)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      // An old serial with the current nonce.
      await expect(claim(ctx, { serial: 1n })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      // An old nonce with the current serial.
      await expect(claim(ctx, { nonce: 0n })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      // Signed for another owner.
      const nonce = await nonceOf(ctx);
      const r2 = await sign(ctx, REGISTRAR, 'RegistrarClaim', { handleId: ID, owner: OWNER_E1.address, serial: 2n, nonce, deadline: FAR });
      const o2 = await sign(ctx, THIEF, 'OwnerClaim', { handleId: ID, metaAddress: META_E2, serial: 2n });
      await expect(ctx.anchor.claim(ID, THIEF.address, META_E2, FAR, r2, o2)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      // Past its deadline.
      const past = BigInt(await time.latest()) - 1n;
      await expect(claim(ctx, { deadline: past })).to.be.revertedWithCustomError(ctx.anchor, 'Expired').withArgs(past);
      await expect(claim(ctx, { owner: OWNER_E1, meta: META_E1 })).to.emit(ctx.anchor, 'Claimed').withArgs(ID, OWNER_E1.address, 2n, META_E1, REGISTRAR.address);
    });

    it('refuses a zero label, a zero owner and a malformed meta-address', async function () {
      const ctx = await loadFixture(deploy);
      await expect(claim(ctx, { id: ethers.ZeroHash })).to.be.revertedWithCustomError(ctx.anchor, 'ZeroHandle');
      await expect(ctx.anchor.claim(ID, ethers.ZeroAddress, META_E0, FAR, '0x', '0x')).to.be.revertedWithCustomError(ctx.anchor, 'ZeroAddress');
      await expect(claim(ctx, { meta: ethers.dataSlice(META_E0, 0, 65) })).to.be.revertedWithCustomError(ctx.anchor, 'BadMetaAddress');
      await expect(claim(ctx, { meta: ethers.concat(['0x04', ethers.dataSlice(META_E0, 1)]) })).to.be.revertedWithCustomError(ctx.anchor, 'BadMetaAddress');
      await expect(claim(ctx, { meta: ethers.concat([ethers.dataSlice(META_E0, 0, 33), '0x05', ethers.dataSlice(META_E0, 34)]) })).to.be.revertedWithCustomError(
        ctx.anchor,
        'BadMetaAddress',
      );
    });

    it('refuses a claim inside the 365-day quarantine, and after it claims with a higher serial', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      await time.increase(CHANGE_DELAY);
      await expect(ctx.anchor.applyChange(ID)).to.emit(ctx.anchor, 'Released').withArgs(ID, 1n, true);
      const releasedAt = BigInt(await time.latest());
      expect(await ctx.anchor.claimableAt(ID)).to.equal(releasedAt + QUARANTINE);
      const [owner, serial, meta, derivable] = await ctx.anchor.resolve(ID);
      expect([owner, serial, meta, derivable]).to.deep.equal([ethers.ZeroAddress, 1n, '0x', false]);
      await expect(claim(ctx, { owner: OWNER_E2, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'InQuarantine').withArgs(releasedAt + QUARANTINE);
      await time.increaseTo(releasedAt + QUARANTINE - 2n);
      await expect(claim(ctx, { owner: OWNER_E2, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'InQuarantine');
      await time.increaseTo(releasedAt + QUARANTINE);
      await expect(claim(ctx, { owner: OWNER_E2, meta: META_E2 })).to.emit(ctx.anchor, 'Claimed').withArgs(ID, OWNER_E2.address, 2n, META_E2, REGISTRAR.address);
      expect((await ctx.anchor.recordOf(ID)).releasedAt).to.equal(0n);
    });
  });

  // ── Owner changes ──────────────────────────────────────────────────────────

  describe('owner changes (72 hours, one pending, cancel)', function () {
    it('applies a transferOwner only after 72 hours, then to the new key and meta-address, keeping the serial', async function () {
      const ctx = await loadFixture(claimed);
      await expect(queueTransfer(ctx)).to.emit(ctx.anchor, 'ChangeQueued');
      const readyAt = BigInt(await time.latest()) + CHANGE_DELAY;
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(false);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'ChangeNotReady').withArgs(readyAt);
      await time.increaseTo(readyAt - 2n); // the next block is at readyAt - 1
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'ChangeNotReady');
      await expect(ctx.anchor.connect(ctx.stranger).applyChange(ID)).to.emit(ctx.anchor, 'OwnerChanged').withArgs(ID, OWNER_E0.address, OWNER_E1.address, META_E1);
      const [owner, serial, meta, derivable] = await ctx.anchor.resolve(ID);
      expect([owner, serial, meta, derivable]).to.deep.equal([OWNER_E1.address, 1n, META_E1, true]);
    });

    it("refuses a transferOwner without the new key's co-signature, by a key that is not the owner, or to the same owner", async function () {
      const ctx = await loadFixture(claimed);
      await expect(queueTransfer(ctx, { coSigner: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E1.address, THIEF.address);
      await expect(queueTransfer(ctx, { from: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E0.address, THIEF.address);
      await expect(queueTransfer(ctx, { to: OWNER_E0 })).to.be.revertedWithCustomError(ctx.anchor, 'SameOwner');
    });

    it("refuses the owner's TransferOwner offered as the new key's TransferOwnerAccept", async function () {
      const ctx = await loadFixture(claimed);
      const msg = { handleId: ID, newOwner: OWNER_E1.address, newMetaAddress: META_E1, nonce: 1n, deadline: FAR };
      const ownerSig = await sign(ctx, OWNER_E0, 'TransferOwner', msg);
      const wrongType = await sign(ctx, OWNER_E1, 'TransferOwner', msg);
      await expect(ctx.anchor.transferOwner(ID, OWNER_E1.address, META_E1, FAR, ownerSig, wrongType)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
    });

    it('applies setMetaAddress after 72 hours', async function () {
      const ctx = await loadFixture(claimed);
      await queueSetMeta(ctx);
      await time.increase(CHANGE_DELAY - 2n);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'ChangeNotReady');
      await time.increase(2);
      await expect(ctx.anchor.applyChange(ID)).to.emit(ctx.anchor, 'MetaAddressChanged').withArgs(ID, META_E1);
      expect((await ctx.anchor.resolve(ID)).metaAddress).to.equal(META_E1);
      expect((await ctx.anchor.resolve(ID)).handleOwner).to.equal(OWNER_E0.address);
    });

    it('keeps one change pending at a time; the owner may cancel it, named, at once; a stranger may not', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      const pending = (await ctx.anchor.recordOf(ID)).pendingNonce;
      expect(pending).to.equal(1n);
      await expect(queueSetMeta(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'ChangePending').withArgs(pending);
      await expect(cancelBy(ctx, THIEF)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      await expect(cancelBy(ctx, OWNER_E0, pending + 1n)).to.be.revertedWithCustomError(ctx.anchor, 'WrongChange').withArgs(pending, pending + 1n);
      await expect(cancelBy(ctx, OWNER_E0)).to.emit(ctx.anchor, 'ChangeCancelled').withArgs(ID, pending);
      expect((await ctx.anchor.recordOf(ID)).pendingKind).to.equal(0n);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'NoPendingChange');
      await expect(cancelBy(ctx, OWNER_E0, pending)).to.be.revertedWithCustomError(ctx.anchor, 'NoPendingChange');
      await expect(queueSetMeta(ctx)).to.emit(ctx.anchor, 'ChangeQueued');
    });

    it('refuses an owner signature replayed with a used nonce, or past its deadline', async function () {
      const ctx = await loadFixture(claimed);
      const sig = await sign(ctx, OWNER_E0, 'Release', { handleId: ID, nonce: 1n, deadline: FAR });
      await ctx.anchor.release(ID, FAR, sig);
      await cancelBy(ctx, OWNER_E0);
      await expect(ctx.anchor.release(ID, FAR, sig)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      const past = BigInt(await time.latest());
      const late = await sign(ctx, OWNER_E0, 'Release', { handleId: ID, nonce: await nonceOf(ctx), deadline: past });
      await expect(ctx.anchor.release(ID, past, late)).to.be.revertedWithCustomError(ctx.anchor, 'Expired');
    });

    it("refuses an old owner's signature after the record moved", async function () {
      const ctx = await loadFixture(claimed);
      // Signed by epoch 0 with the nonce the record will have after the advance.
      const stale = await sign(ctx, OWNER_E0, 'Release', { handleId: ID, nonce: 2n, deadline: FAR });
      await advance(ctx);
      await expect(ctx.anchor.release(ID, FAR, stale)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E1.address, OWNER_E0.address);
    });

    it('refuses every owner change on an unowned label', async function () {
      const ctx = await loadFixture(deploy);
      await expect(queueRelease(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwned').withArgs(ID);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwned');
      await expect(advance(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwned');
      await expect(holdBy(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwned');
    });
  });

  // ── Advance ────────────────────────────────────────────────────────────────

  describe('advance (owner + new owner + registrar, at once)', function () {
    it('moves the record at once, keeps the serial and clears a pending release', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      await expect(advance(ctx))
        .to.emit(ctx.anchor, 'ChangeCancelled')
        .withArgs(ID, 1n)
        .and.to.emit(ctx.anchor, 'Advanced')
        .withArgs(ID, OWNER_E0.address, OWNER_E1.address, META_E1, REGISTRAR.address);
      const r = await ctx.anchor.recordOf(ID);
      expect([r.owner, r.serial, r.metaAddress, r.pendingKind]).to.deep.equal([OWNER_E1.address, 1n, META_E1, 0n]);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
    });

    it('is refused without any one of its three signatures, or with a signature of the wrong type', async function () {
      const ctx = await loadFixture(claimed);
      await expect(advance(ctx, { ownerSigner: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E0.address, THIEF.address);
      await expect(advance(ctx, { newSigner: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E1.address, THIEF.address);
      await expect(advance(ctx, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar').withArgs(THIEF.address);
      // A removed phone holds the old key and can make the new key's signature, but no registrar's.
      await expect(advance(ctx, { registrar: OWNER_E0 })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(advance(ctx, { to: OWNER_E0 })).to.be.revertedWithCustomError(ctx.anchor, 'SameOwner');
      // The registrar's signature over the owner's Advance struct is not a RegistrarAdvance.
      const nonce = await nonceOf(ctx);
      const [ownerSig, acceptSig] = await advanceSigs(ctx, { from: OWNER_E0, to: OWNER_E1, meta: META_E1, nonce });
      const wrongType = await sign(ctx, REGISTRAR, 'Advance', { handleId: ID, newOwner: OWNER_E1.address, newMetaAddress: META_E1, nonce, deadline: FAR });
      await expect(ctx.anchor.advance(ID, OWNER_E1.address, META_E1, FAR, ownerSig, acceptSig, wrongType)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
    });

    it('is refused when replayed', async function () {
      const ctx = await loadFixture(claimed);
      const sigs = await advanceSigs(ctx, { from: OWNER_E0, to: OWNER_E1, meta: META_E1, nonce: 1n });
      await ctx.anchor.advance(ID, OWNER_E1.address, META_E1, FAR, ...sigs);
      await expect(ctx.anchor.advance(ID, OWNER_E1.address, META_E1, FAR, ...sigs)).to.be.revertedWithCustomError(ctx.anchor, 'SameOwner');
      // Back to epoch 0 with the old trio: the owner is epoch 1 now and the nonce moved.
      await expect(ctx.anchor.advance(ID, OWNER_E2.address, META_E2, FAR, ...sigs)).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
    });

    it('is accepted on a frozen record, and leaves the freeze in place (ASSUMPTION q15)', async function () {
      const ctx = await loadFixture(claimed);
      await holdBy(ctx);
      const frozenUntil = await frozenUntilOf(ctx);
      await expect(advance(ctx)).to.emit(ctx.anchor, 'Advanced');
      expect(await frozenUntilOf(ctx)).to.equal(frozenUntil);
      expect(await ctx.anchor.isFrozen(ID)).to.equal(true);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(false);
    });
  });

  // ── Freezes ────────────────────────────────────────────────────────────────

  describe('hold, renewal, veto, unfreeze and the freeze', function () {
    it('a veto cancels the pending change and freezes the record for 14 days', async function () {
      const ctx = await loadFixture(claimed);
      await queueTransfer(ctx, { to: THIEF, meta: META_E2 });
      await expect(vetoBy(ctx, 1n)).to.emit(ctx.anchor, 'ChangeVetoed').withArgs(ID, 1n, REGISTRAR.address).and.to.emit(ctx.anchor, 'Frozen');
      const r = await ctx.anchor.recordOf(ID);
      expect(r.pendingKind).to.equal(0n);
      expect(r.frozenUntil).to.equal(BigInt(await time.latest()) + FREEZE);
      expect((await ctx.anchor.resolve(ID)).handleOwner).to.equal(OWNER_E0.address);
      await time.increase(CHANGE_DELAY);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'NoPendingChange');
    });

    it('a veto names the change it cancels, only a registrar may sign it, and it is good once', async function () {
      const ctx = await loadFixture(claimed);
      await expect(vetoBy(ctx, 1n)).to.be.revertedWithCustomError(ctx.anchor, 'NoPendingChange');
      await queueRelease(ctx);
      await expect(vetoBy(ctx, 2n)).to.be.revertedWithCustomError(ctx.anchor, 'WrongChange').withArgs(1n, 2n);
      await expect(vetoBy(ctx, 1n, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      const sig = await sign(ctx, REGISTRAR, 'Veto', { handleId: ID, pendingNonce: 1n, nonce: await nonceOf(ctx), deadline: FAR });
      await expect(ctx.anchor.veto(ID, 1n, FAR, sig)).to.emit(ctx.anchor, 'ChangeVetoed');
      await expect(queueRelease(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen');
      await expect(ctx.anchor.veto(ID, 1n, FAR, sig)).to.be.revertedWithCustomError(ctx.anchor, 'NoPendingChange');
    });

    it('a frozen record refuses every owner change, and applying a change queued before the hold', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      await holdBy(ctx);
      const until = await frozenUntilOf(ctx);
      await expect(queueTransfer(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen').withArgs(until);
      await expect(queueSetMeta(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen');
      await expect(queueRelease(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen');
      await time.increase(CHANGE_DELAY);
      await expect(ctx.anchor.applyChange(ID)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen').withArgs(until);
      // ASSUMPTION(0086 rule 3): the owner's cancel stays open while frozen.
      await expect(cancelBy(ctx, OWNER_E0)).to.emit(ctx.anchor, 'ChangeCancelled');
    });

    it('a freeze lapses after 14 days; a hold refuses a frozen record, and RenewHold renews the freeze it names', async function () {
      const ctx = await loadFixture(claimed);
      await holdBy(ctx);
      const first = await frozenUntilOf(ctx);
      await time.increase(7 * DAY);
      await expect(holdBy(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen');
      await expect(renewBy(ctx, { frozenUntil: first + 1n })).to.be.revertedWithCustomError(ctx.anchor, 'WrongFreeze').withArgs(first, first + 1n);
      await expect(renewBy(ctx, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(renewBy(ctx)).to.emit(ctx.anchor, 'Frozen');
      const renewed = BigInt(await time.latest()) + FREEZE;
      expect(await frozenUntilOf(ctx)).to.equal(renewed);
      await time.increaseTo(renewed - 2n); // the next block is at renewed - 1
      await expect(queueRelease(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'RecordFrozen');
      await time.increaseTo(renewed);
      expect(await ctx.anchor.isFrozen(ID)).to.equal(false);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
      await expect(renewBy(ctx, { frozenUntil: renewed })).to.be.revertedWithCustomError(ctx.anchor, 'NotFrozen');
      await expect(queueRelease(ctx)).to.emit(ctx.anchor, 'ChangeQueued');
    });

    it('refuses a hold replayed, or from a key off the list', async function () {
      const ctx = await loadFixture(claimed);
      const sig = await sign(ctx, REGISTRAR, 'Hold', { handleId: ID, nonce: await nonceOf(ctx), deadline: FAR });
      await ctx.anchor.hold(ID, FAR, sig);
      await ctx.anchor.connect(ctx.safe).liftFreeze(ID);
      await expect(ctx.anchor.hold(ID, FAR, sig)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(holdBy(ctx, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
    });

    it('unfreeze (ASSUMPTION q15) lifts the named freeze with the owner and a registrar, and is refused without either', async function () {
      const ctx = await loadFixture(claimed);
      await expect(unfreezeBy(ctx, { frozenUntil: 1n })).to.be.revertedWithCustomError(ctx.anchor, 'NotFrozen');
      await holdBy(ctx);
      const until = await frozenUntilOf(ctx);
      await expect(unfreezeBy(ctx, { frozenUntil: until - 1n })).to.be.revertedWithCustomError(ctx.anchor, 'WrongFreeze');
      await expect(unfreezeBy(ctx, { owner: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      await expect(unfreezeBy(ctx, { registrar: THIEF })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(unfreezeBy(ctx, { registrar: OWNER_E0 })).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(unfreezeBy(ctx)).to.emit(ctx.anchor, 'Unfrozen').withArgs(ID, REGISTRAR.address);
      expect(await ctx.anchor.isFrozen(ID)).to.equal(false);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
    });

    it('a rotation by advance, then unfreeze: the path question 15 recommends', async function () {
      const ctx = await loadFixture(claimed);
      await holdBy(ctx);
      await advance(ctx, { to: OWNER_E2, meta: META_E2 });
      await expect(unfreezeBy(ctx, { owner: OWNER_E0 })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      await expect(unfreezeBy(ctx, { owner: OWNER_E2 })).to.emit(ctx.anchor, 'Unfrozen');
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
    });

    it('the registrar cannot touch an owned record beyond a freeze', async function () {
      const ctx = await loadFixture(claimed);
      await expect(claim(ctx, { owner: THIEF, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'AlreadyOwned');
      await expect(queueRelease(ctx, { by: REGISTRAR })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner').withArgs(OWNER_E0.address, REGISTRAR.address);
      await expect(queueTransfer(ctx, { from: REGISTRAR, to: THIEF, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      await expect(advance(ctx, { ownerSigner: REGISTRAR, to: THIEF, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'WrongSigner');
      await expect(unfreezeBy(ctx, { frozenUntil: 1n, owner: REGISTRAR })).to.be.revertedWithCustomError(ctx.anchor, 'NotFrozen');
      expect((await ctx.anchor.resolve(ID)).handleOwner).to.equal(OWNER_E0.address);
    });
  });

  // ── The Safe ───────────────────────────────────────────────────────────────

  describe('the Safe: timelock, registrar list, rekey, forceRelease, ownership', function () {
    it('only the Safe may call its functions', async function () {
      const ctx = await loadFixture(claimed);
      const s = ctx.anchor.connect(ctx.stranger);
      for (const call of [
        () => s.removeRegistrar(REGISTRAR.address),
        () => s.liftFreeze(ID),
        () => s.scheduleAddRegistrar(REGISTRAR_2.address),
        () => s.executeAddRegistrar(REGISTRAR_2.address),
        () => s.scheduleRekey(ID, THIEF.address, META_E2),
        () => s.executeRekey(ID, THIEF.address, META_E2),
        () => s.scheduleForceRelease(ID, true),
        () => s.executeForceRelease(ID, true),
        () => s.cancelSafeOp(ethers.ZeroHash),
        () => s.transferOwnership(ctx.stranger.address),
      ]) {
        await expect(call()).to.be.revertedWithCustomError(ctx.anchor, 'NotOwner');
      }
    });

    it('removes a registrar at once', async function () {
      const ctx = await loadFixture(claimed);
      await expect(ctx.anchor.connect(ctx.safe).removeRegistrar(REGISTRAR.address)).to.emit(ctx.anchor, 'RegistrarRemoved').withArgs(REGISTRAR.address);
      expect(await ctx.anchor.isRegistrar(REGISTRAR.address)).to.equal(false);
      await expect(holdBy(ctx)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
      await expect(ctx.anchor.connect(ctx.safe).removeRegistrar(REGISTRAR.address)).to.be.revertedWithCustomError(ctx.anchor, 'RegistrarNotListed');
    });

    it('lifts a freeze at once (a stolen registrar key)', async function () {
      const ctx = await loadFixture(claimed);
      await expect(ctx.anchor.connect(ctx.safe).liftFreeze(ID)).to.be.revertedWithCustomError(ctx.anchor, 'NotFrozen');
      await holdBy(ctx);
      await expect(ctx.anchor.connect(ctx.safe).liftFreeze(ID)).to.emit(ctx.anchor, 'Unfrozen').withArgs(ID, ctx.safe.address);
      expect(await ctx.anchor.isFrozen(ID)).to.equal(false);
    });

    it('adds a registrar only after the 72-hour timelock and within its grace; the Safe may cancel', async function () {
      const ctx = await loadFixture(deploy);
      const safe = ctx.anchor.connect(ctx.safe);
      const opId = await ctx.anchor.addRegistrarOpId(REGISTRAR_2.address);
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotScheduled').withArgs(opId);
      await expect(safe.scheduleAddRegistrar(REGISTRAR.address)).to.be.revertedWithCustomError(ctx.anchor, 'RegistrarAlreadyListed');
      await expect(safe.scheduleAddRegistrar(ethers.ZeroAddress)).to.be.revertedWithCustomError(ctx.anchor, 'ZeroAddress');
      await expect(safe.scheduleAddRegistrar(REGISTRAR_2.address)).to.emit(ctx.anchor, 'SafeOpScheduled');
      const readyAt = BigInt(await time.latest()) + SAFE_DELAY;
      expect(await ctx.anchor.safeOpReadyAt(opId)).to.equal(readyAt);
      await expect(safe.scheduleAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpAlreadyScheduled');
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotReady').withArgs(readyAt);
      await expect(safe.cancelSafeOp(opId)).to.emit(ctx.anchor, 'SafeOpCancelled').withArgs(opId);
      await expect(safe.cancelSafeOp(opId)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotScheduled');
      await time.increase(SAFE_DELAY);
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotScheduled');
      await safe.scheduleAddRegistrar(REGISTRAR_2.address);
      await time.increase(SAFE_DELAY);
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.emit(ctx.anchor, 'RegistrarAdded').withArgs(REGISTRAR_2.address);
      await claim(ctx, { registrar: REGISTRAR_2 });
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotScheduled');
    });

    it('refuses a scheduled operation past its grace, and lets it be scheduled again', async function () {
      const ctx = await loadFixture(deploy);
      const safe = ctx.anchor.connect(ctx.safe);
      await safe.scheduleAddRegistrar(REGISTRAR_2.address);
      const readyAt = BigInt(await time.latest()) + SAFE_DELAY;
      const grace = await ctx.anchor.SAFE_OP_GRACE();
      await time.increaseTo(readyAt + grace + 1n);
      await expect(safe.executeAddRegistrar(REGISTRAR_2.address)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpExpired').withArgs(readyAt + grace);
      await expect(safe.scheduleAddRegistrar(REGISTRAR_2.address)).to.emit(ctx.anchor, 'SafeOpScheduled');
    });

    it('rekeys a frozen record after 72 hours, clearing the freeze and any pending change; the owner cannot stop it (ASSUMPTION q16)', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      await holdBy(ctx);
      const nonceBefore = await nonceOf(ctx);
      const safe = ctx.anchor.connect(ctx.safe);
      await expect(safe.scheduleRekey(ID, OWNER_E2.address, META_E2)).to.emit(ctx.anchor, 'SafeOpScheduled');
      await expect(safe.executeRekey(ID, OWNER_E2.address, META_E2)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotReady');
      // No function takes the record owner's signature over a scheduled rekey.
      await time.increase(SAFE_DELAY);
      await expect(safe.executeRekey(ID, OWNER_E2.address, META_E2))
        .to.emit(ctx.anchor, 'Rekeyed')
        .withArgs(ID, OWNER_E0.address, OWNER_E2.address, 1n, META_E2)
        .and.to.emit(ctx.anchor, 'ChangeCancelled');
      const r = await ctx.anchor.recordOf(ID);
      expect([r.owner, r.serial, r.metaAddress, r.frozenUntil, r.pendingKind, r.nonce]).to.deep.equal([OWNER_E2.address, 1n, META_E2, 0n, 0n, nonceBefore + 1n]);
      expect((await ctx.anchor.resolve(ID)).derivable).to.equal(true);
    });

    it('a rekey voids what was signed for the record before it', async function () {
      const ctx = await loadFixture(claimed);
      const staleHold = await sign(ctx, REGISTRAR, 'Hold', { handleId: ID, nonce: await nonceOf(ctx), deadline: FAR });
      await safeRekey(ctx);
      await expect(ctx.anchor.hold(ID, FAR, staleHold)).to.be.revertedWithCustomError(ctx.anchor, 'NotRegistrar');
    });

    it('rekeys a released record to a new holder with a higher serial, inside the quarantine', async function () {
      const ctx = await loadFixture(claimed);
      await queueRelease(ctx);
      await time.increase(CHANGE_DELAY);
      await ctx.anchor.applyChange(ID);
      await safeRekey(ctx);
      const r = await ctx.anchor.recordOf(ID);
      expect([r.owner, r.serial, r.releasedAt]).to.deep.equal([OWNER_E2.address, 2n, 0n]);
    });

    it('refuses a rekey of a label never claimed, to a zero owner or with a malformed meta-address', async function () {
      const ctx = await loadFixture(deploy);
      const safe = ctx.anchor.connect(ctx.safe);
      await expect(safe.scheduleRekey(ID, OWNER_E2.address, META_E2)).to.be.revertedWithCustomError(ctx.anchor, 'UnknownHandle');
      await claim(ctx);
      await expect(safe.scheduleRekey(ID, ethers.ZeroAddress, META_E2)).to.be.revertedWithCustomError(ctx.anchor, 'ZeroAddress');
      await expect(safe.scheduleRekey(ID, OWNER_E2.address, '0x02')).to.be.revertedWithCustomError(ctx.anchor, 'BadMetaAddress');
    });

    it('forceRelease after the timelock: quarantined, or waived for the rightful holder', async function () {
      const ctx = await loadFixture(claimed);
      const safe = ctx.anchor.connect(ctx.safe);
      await holdBy(ctx);
      await safe.scheduleForceRelease(ID, true);
      await time.increase(SAFE_DELAY);
      await expect(safe.executeForceRelease(ID, false)).to.be.revertedWithCustomError(ctx.anchor, 'SafeOpNotScheduled');
      await expect(safe.executeForceRelease(ID, true)).to.emit(ctx.anchor, 'Released').withArgs(ID, 1n, true);
      expect(await frozenUntilOf(ctx)).to.equal(0n);
      await expect(claim(ctx, { owner: OWNER_E2, meta: META_E2 })).to.be.revertedWithCustomError(ctx.anchor, 'InQuarantine');
      await expect(safe.scheduleForceRelease(ID, false)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwned');

      // A squat (here by the listed registrar) is released with the quarantine waived and claimed at once.
      const bob = handleId('bob');
      await claim(ctx, { id: bob, owner: THIEF, meta: META_E2 });
      await safe.scheduleForceRelease(bob, false);
      await time.increase(SAFE_DELAY);
      await expect(safe.executeForceRelease(bob, false)).to.emit(ctx.anchor, 'Released').withArgs(bob, 1n, false);
      expect(await ctx.anchor.claimableAt(bob)).to.equal(0n);
      await expect(claim(ctx, { id: bob, owner: OWNER_E1, meta: META_E1 })).to.emit(ctx.anchor, 'Claimed').withArgs(bob, OWNER_E1.address, 2n, META_E1, REGISTRAR.address);
    });

    it('transfers ownership in two steps', async function () {
      const ctx = await loadFixture(deploy);
      await expect(ctx.anchor.connect(ctx.safe).transferOwnership(ethers.ZeroAddress)).to.be.revertedWithCustomError(ctx.anchor, 'ZeroAddress');
      await expect(ctx.anchor.connect(ctx.safe).transferOwnership(ctx.newSafe.address))
        .to.emit(ctx.anchor, 'OwnershipTransferStarted')
        .withArgs(ctx.safe.address, ctx.newSafe.address);
      expect(await ctx.anchor.owner()).to.equal(ctx.safe.address);
      await expect(ctx.anchor.connect(ctx.stranger).acceptOwnership()).to.be.revertedWithCustomError(ctx.anchor, 'NotPendingOwner');
      await expect(ctx.anchor.connect(ctx.newSafe).acceptOwnership()).to.emit(ctx.anchor, 'OwnershipTransferred').withArgs(ctx.safe.address, ctx.newSafe.address);
      expect(await ctx.anchor.owner()).to.equal(ctx.newSafe.address);
      expect(await ctx.anchor.pendingOwner()).to.equal(ethers.ZeroAddress);
      await expect(ctx.anchor.connect(ctx.safe).removeRegistrar(REGISTRAR.address)).to.be.revertedWithCustomError(ctx.anchor, 'NotOwner');
    });
  });

  // ── Events ─────────────────────────────────────────────────────────────────

  describe('events', function () {
    it('carry the handleId and never the label', async function () {
      const ctx = await loadFixture(deploy);
      const label = 'zelda-findme';
      const id = handleId(label);
      const receipts = [];
      receipts.push(await (await claim(ctx, { id })).wait());
      receipts.push(await (await queueRelease(ctx, { id })).wait());
      receipts.push(await (await holdBy(ctx, { id })).wait());
      const labelHex = ethers.hexlify(ethers.toUtf8Bytes(label)).slice(2);
      let seen = 0;
      for (const rc of receipts) {
        for (const log of rc!.logs) {
          seen++;
          expect(log.topics[1]).to.equal(id);
          expect(log.data.toLowerCase()).to.not.include(labelHex);
          for (const t of log.topics) expect(t.toLowerCase()).to.not.include(labelHex);
        }
      }
      expect(seen).to.be.greaterThan(2);
    });
  });

  // ── Script helpers ─────────────────────────────────────────────────────────

  describe('safe-exec anchor actions (scripts/lib/handleAnchor.ts)', function () {
    it('lists every anchor action among SAFE_ACTION', function () {
      for (const a of ANCHOR_SAFE_ACTIONS) {
        expect(SAFE_ACTIONS).to.include(a);
        expect(parseSafeAction(a)).to.equal(a);
      }
    });

    it('builds each call from the environment and refuses missing or bad values', function () {
      const env = { REGISTRAR: REGISTRAR.address, HANDLE_LABEL: LABEL, NEW_OWNER: OWNER_E2.address, META_ADDRESS: META_E2 };
      expect(anchorCall('anchor-registrar-schedule', env)).to.deep.include({ fn: 'scheduleAddRegistrar', args: [REGISTRAR.address] });
      expect(anchorCall('anchor-registrar-add', env).fn).to.equal('executeAddRegistrar');
      expect(anchorCall('anchor-registrar-remove', env).fn).to.equal('removeRegistrar');
      expect(anchorCall('anchor-rekey-schedule', env)).to.deep.include({ fn: 'scheduleRekey', args: [ID, OWNER_E2.address, META_E2] });
      expect(anchorCall('anchor-rekey', env).fn).to.equal('executeRekey');
      expect(anchorCall('anchor-force-release-schedule', env)).to.deep.include({ fn: 'scheduleForceRelease', args: [ID, true] });
      expect(anchorCall('anchor-force-release', { ...env, QUARANTINE: '0' })).to.deep.include({ fn: 'executeForceRelease', args: [ID, false] });
      expect(anchorCall('anchor-lift-freeze', { HANDLE_ID: ID })).to.deep.include({ fn: 'liftFreeze', args: [ID] });
      expect(anchorCall('anchor-cancel-op', { SAFE_OP_ID: ID }).fn).to.equal('cancelSafeOp');
      expect(anchorCall('anchor-transfer-ownership', { NEW_SAFE: OWNER_E1.address }).args).to.deep.equal([OWNER_E1.address]);
      expect(anchorCall('anchor-accept-ownership', {}).args).to.deep.equal([]);

      expect(() => anchorCall('anchor-registrar-add', {})).to.throw(/REGISTRAR is required/);
      expect(() => anchorCall('anchor-lift-freeze', {})).to.throw(/HANDLE_LABEL .* or HANDLE_ID/);
      expect(() => anchorCall('anchor-lift-freeze', { HANDLE_LABEL: 'ana', HANDLE_ID: handleId('bob') })).to.throw(/is not the handleId/);
      expect(() => anchorCall('anchor-rekey', { ...env, META_ADDRESS: '0x02' })).to.throw(/META_ADDRESS/);
      expect(() => anchorCall('anchor-force-release', { ...env, QUARANTINE: 'yes' })).to.throw(/QUARANTINE is 1/);
      expect(() => anchorCall('anchor-cancel-op', { SAFE_OP_ID: '0x12' })).to.throw(/SAFE_OP_ID/);
    });
  });
});
