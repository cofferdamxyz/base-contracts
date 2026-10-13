import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import type { Signer } from 'ethers';
import {
  TIER,
  NO_PERMISSION,
  Permission,
  permission,
  permissionHash,
  sessionKey,
  rawPasskey,
  webauthnKey,
  rpIdHash,
  packSig,
  userOp,
} from './helpers/keys';

const ERC1271_MAGIC = '0x1626ba7e';
const ERC1271_FAIL = '0xffffffff';
const SIG_VALIDATION_FAILED = 1n;
const RECOVERY_ID = ethers.MaxUint256;
const PARTNER_ID = ethers.id('offshoresync');
const DAY = 86400n;

describe('CofferdamAccount4337 tiers (decisions 0015, 0016)', () => {
  // The account's EntryPoint is a plain signer, so tests can call
  // validateUserOp and the execution functions directly.
  let entryPoint: Signer;
  let epAddr: string;
  let owner: Signer;
  let attester: ReturnType<typeof ethers.Wallet.createRandom>;
  let partnerBackend: ReturnType<typeof ethers.Wallet.createRandom>;
  let moduleRegistry: any;
  let ceremonyRegistry: any;
  let rawPasskeyModule: any;
  let highModule: any;
  let partnerModule: any;
  let managedModule: any;
  let counter: any;
  let counterAddr: string;
  let usdc: any;
  let INC: string;
  let DEPOSIT: string;

  before(async () => {
    [owner, entryPoint] = await ethers.getSigners();
    epAddr = await entryPoint.getAddress();
    attester = ethers.Wallet.createRandom();
    partnerBackend = ethers.Wallet.createRandom();

    rawPasskeyModule = await (await ethers.getContractFactory('PasskeyAuthority')).deploy();
    highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
    partnerModule = await (await ethers.getContractFactory('PartnerPasskeyAuthority')).deploy();
    managedModule = await (await ethers.getContractFactory('SessionKeyAuthority')).deploy();

    moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(
      await owner.getAddress(),
      [rawPasskeyModule, highModule, partnerModule, managedModule].map((m) => m.target as string),
    );
    ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(
      await owner.getAddress(),
      [attester.address],
    );

    counter = await (await ethers.getContractFactory('MockCounter')).deploy();
    counterAddr = await counter.getAddress();
    usdc = await (await ethers.getContractFactory('USDC')).deploy('USD Coin', 'USDC');
    INC = counter.interface.getFunction('increment')!.selector;
    DEPOSIT = counter.interface.getFunction('deposit')!.selector;
  });

  async function deployAccount(module: any, config: string, perm: Permission = NO_PERMISSION) {
    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account: any = await Account.deploy(epAddr, moduleRegistry, ceremonyRegistry, module, config, perm);
    return { account, addr: await account.getAddress() };
  }

  /** Run validateUserOp from the EntryPoint for `callData` signed by `sign`. */
  function validate(account: any, addr: string, authorityId: bigint | number, callData: string, sign: (h: string) => string) {
    const hash = ethers.hexlify(ethers.randomBytes(32));
    const op = userOp(addr, callData, packSig(authorityId, sign(hash)));
    return account.connect(entryPoint).validateUserOp.staticCall(op, hash, 0);
  }

  function enc(account: any, fn: string, args: unknown[]): string {
    return account.interface.encodeFunctionData(fn, args);
  }

  async function partnerGrant(days = 90n): Promise<Permission> {
    return permission([[counterAddr, INC]], { expiry: BigInt(await time.latest()) + days * DAY });
  }

  async function attest(account: any, action: string, newConfig: string, partnerId: string, window?: [bigint, bigint]) {
    const now = BigInt(await time.latest());
    const [notBefore, expiry] = window ?? [now - 60n, now + 600n];
    const nonce = await account.ceremonyNonce();
    const h = await account.ceremonyHash(action, ethers.keccak256(newConfig), partnerId, nonce, notBefore, expiry);
    return { notBefore, expiry, signature: await attester.signMessage(ethers.getBytes(h)) };
  }

  async function partnerAccount(perm?: Permission) {
    const key = webauthnKey('offshoresync.com');
    const config = key.partnerConfig(PARTNER_ID, partnerBackend.address);
    const { account, addr } = await deployAccount(partnerModule, config, perm ?? (await partnerGrant()));
    return { account, addr, key, config, signAs: (h: string) => key.sign(h) };
  }

  // ── Genesis and the module registry ───────────────────────────────────────

  describe('genesis', () => {
    it('accepts a High passkey with no permission and locks the first-High paths', async () => {
      const { account } = await deployAccount(highModule, webauthnKey().config);
      expect(await account.upgradeLocked()).to.be.true;
      expect(await account.passkeyCount()).to.equal(1);
      await expect(deployAccount(highModule, webauthnKey().config, permission([[counterAddr, INC]])))
        .to.be.revertedWithCustomError(account, 'InvalidPermission');
    });

    it('rejects a module that is not on the registry', async () => {
      const backdoor = await (await ethers.getContractFactory('MockTierModule')).deploy(TIER.High);
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      await expect(deployAccount(backdoor, '0x'))
        .to.be.revertedWithCustomError(Account, 'ModuleNotAllowed').withArgs(await backdoor.getAddress());
    });

    it('rejects the retired LowUntrusted tier even when listed', async () => {
      const legacy = await (await ethers.getContractFactory('MockTierModule')).deploy(TIER.LowUntrusted);
      await moduleRegistry.allowModule(legacy);
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      await expect(deployAccount(legacy, '0x'))
        .to.be.revertedWithCustomError(Account, 'TierNotPermitted').withArgs(TIER.LowUntrusted);
    });

    it('rejects zero registries', async () => {
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      await expect(Account.deploy(epAddr, ethers.ZeroAddress, ceremonyRegistry, highModule, webauthnKey().config, NO_PERMISSION))
        .to.be.revertedWithCustomError(Account, 'ZeroAddress');
    });

    it('validates a Partner grant: listed calls, zero value, expiring, no token moves', async () => {
      const key = webauthnKey('offshoresync.com');
      const config = key.partnerConfig(PARTNER_ID, partnerBackend.address);
      const expiry = BigInt(await time.latest()) + 90n * DAY;
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      const transfer = usdc.interface.getFunction('transfer')!.selector;
      const approve = usdc.interface.getFunction('approve')!.selector;
      const bad: Permission[] = [
        NO_PERMISSION, // nothing listed
        permission([[counterAddr, INC]], { expiry: 0n }), // never expires
        permission([[counterAddr, INC]], { expiry, valueCap: 1n }), // value
        permission([[counterAddr, INC]], { expiry: BigInt(await time.latest()) - 1n }), // expired
        permission([[await usdc.getAddress(), transfer]], { expiry }),
        permission([[await usdc.getAddress(), approve]], { expiry }),
        permission([[ethers.ZeroAddress, INC]], { expiry }),
        { targets: [counterAddr], selectors: [], valueCap: 0n, expiry }, // length mismatch
        permission(Array.from({ length: 17 }, () => [counterAddr, INC] as [string, string]), { expiry }),
      ];
      for (const p of bad) {
        await expect(deployAccount(partnerModule, config, p)).to.be.revertedWithCustomError(Account, 'InvalidPermission');
      }
      const good = permission([[counterAddr, INC]], { expiry });
      const { account } = await deployAccount(partnerModule, config, good);
      expect(await account.upgradeLocked()).to.be.false;
      const stored = await account.getPermission(0);
      expect(stored.targets).to.deep.equal([counterAddr]);
      expect(stored.expiry).to.equal(expiry);
    });

    it('a Managed genesis grant may not carry value, but may be open-ended', async () => {
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      await expect(deployAccount(managedModule, sessionKey().config, permission([[counterAddr, DEPOSIT]], { valueCap: 1n })))
        .to.be.revertedWithCustomError(Account, 'InvalidPermission');
      const { account } = await deployAccount(managedModule, sessionKey().config, permission([[counterAddr, INC]]));
      expect((await account.getPermission(0)).expiry).to.equal(0n);
    });

    it('emits the permission hash', async () => {
      const p = await partnerGrant();
      const { account } = await partnerAccount(p);
      const events = await account.queryFilter(account.filters.PermissionGranted());
      expect(events[0].args.permissionHash).to.equal(permissionHash(p));
    });
  });

  // ── Partner ──────────────────────────────────────────────────────────────

  describe('Partner passkey', () => {
    it('may make the listed calls, until its grant expires', async () => {
      const p = await partnerGrant();
      const { account, addr, signAs } = await partnerAccount(p);
      const inc = counter.interface.encodeFunctionData('increment');
      const validUntil = p.expiry << 160n;
      expect(await validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, inc]), signAs)).to.equal(validUntil);
      expect(await validate(account, addr, 0, enc(account, 'executeBatch', [[counterAddr, counterAddr], [0, 0], [inc, inc]]), signAs))
        .to.equal(validUntil);
    });

    it('may not call anything else', async () => {
      const { account, addr, signAs } = await partnerAccount();
      const inc = counter.interface.encodeFunctionData('increment');
      const dep = counter.interface.encodeFunctionData('deposit');
      const transfer = usdc.interface.encodeFunctionData('transfer', [counterAddr, 1]);
      const cases = [
        enc(account, 'execute', [counterAddr, 0, dep]), // unlisted selector
        enc(account, 'execute', [await usdc.getAddress(), 0, transfer]), // unlisted target, token move
        enc(account, 'execute', [counterAddr, 1, inc]), // value
        enc(account, 'execute', [counterAddr, 0, '0x']), // no selector
        enc(account, 'execute', [addr, 0, enc(account, 'revokeAuthority', [0])]), // the account itself
        enc(account, 'executeBatch', [[counterAddr, counterAddr], [0, 0], [inc, dep]]),
      ];
      for (const callData of cases) {
        await expect(validate(account, addr, 0, callData, signAs)).to.be.revertedWithCustomError(account, 'CallNotPermitted');
      }
      const mgmt = [
        enc(account, 'addAuthority', [highModule.target, webauthnKey().config, NO_PERMISSION]),
        enc(account, 'revokeAuthority', [0]),
        '0x',
      ];
      for (const callData of mgmt) {
        await expect(validate(account, addr, 0, callData, signAs))
          .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(TIER.Partner);
      }
    });

    it('returns SIG_VALIDATION_FAILED for a bad signature', async () => {
      const { account, addr } = await partnerAccount();
      const other = webauthnKey('offshoresync.com');
      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, inc]), (h) => other.sign(h)))
        .to.equal(SIG_VALIDATION_FAILED);
    });

    it('rejects an assertion for a different RP', async () => {
      const { account, addr, key } = await partnerAccount();
      const inc = counter.interface.encodeFunctionData('increment');
      const callData = enc(account, 'execute', [counterAddr, 0, inc]);
      expect(await validate(account, addr, 0, callData, (h) => key.sign(h, { signedRpId: 'evil.example' })))
        .to.equal(SIG_VALIDATION_FAILED);
      expect(await validate(account, addr, 0, callData, (h) => key.sign(h, { uv: false }))).to.equal(SIG_VALIDATION_FAILED);
    });

    it('never produces an ERC-1271 signature', async () => {
      const { account, key } = await partnerAccount();
      const digest = ethers.id('permit');
      const sig = packSig(0, key.sign(await account.replaySafeHash(digest)));
      expect(await account.isValidSignature(digest, sig)).to.equal(ERC1271_FAIL);
    });
  });

  // ── Managed ──────────────────────────────────────────────────────────────

  describe('Managed bridge key', () => {
    it('is scoped by its permission like Partner', async () => {
      const key = sessionKey();
      const { account, addr } = await deployAccount(managedModule, key.config, permission([[counterAddr, INC]]));
      const signAs = (h: string) => key.sign(addr, h);
      const inc = counter.interface.encodeFunctionData('increment');
      const dep = counter.interface.encodeFunctionData('deposit');
      expect(await validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, inc]), signAs)).to.equal(0n);
      await expect(validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, dep]), signAs))
        .to.be.revertedWithCustomError(account, 'CallNotPermitted');
      await expect(validate(account, addr, 0, enc(account, 'revokeAuthority', [0]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(TIER.LowManaged);
    });

    it('may carry value only when High granted it', async () => {
      const high = webauthnKey();
      const { account, addr } = await deployAccount(highModule, high.config);
      const key = sessionKey();
      await account
        .connect(entryPoint)
        .addAuthority(managedModule, key.config, permission([[counterAddr, DEPOSIT]], { valueCap: 100n }));
      const signAs = (h: string) => key.sign(addr, h);
      const dep = counter.interface.encodeFunctionData('deposit');
      expect(await validate(account, addr, 1, enc(account, 'execute', [counterAddr, 100, dep]), signAs)).to.equal(0n);
      await expect(validate(account, addr, 1, enc(account, 'execute', [counterAddr, 101, dep]), signAs))
        .to.be.revertedWithCustomError(account, 'CallNotPermitted');
    });

    it('never produces an ERC-1271 signature', async () => {
      const key = sessionKey();
      const { account, addr } = await deployAccount(managedModule, key.config, permission([[counterAddr, INC]]));
      const digest = ethers.id('permit');
      const sig = packSig(0, key.sign(addr, await account.replaySafeHash(digest)));
      expect(await account.isValidSignature(digest, sig)).to.equal(ERC1271_FAIL);
    });

    it('reports the polis_sso kind', async () => {
      expect(await managedModule.kind()).to.equal(ethers.id('polis_sso'));
      expect(await managedModule.tier()).to.equal(TIER.LowManaged);
    });
  });

  // ── High ─────────────────────────────────────────────────────────────────

  describe('High passkey', () => {
    it('must be a cofferdam.xyz passkey with UV', async () => {
      expect(await highModule.COFFERDAM_RP_ID_HASH()).to.equal(rpIdHash('cofferdam.xyz'));
      const high = webauthnKey();
      const { account, addr } = await deployAccount(highModule, high.config);
      const inc = counter.interface.encodeFunctionData('increment');
      const callData = enc(account, 'execute', [counterAddr, 0, inc]);
      expect(await validate(account, addr, 0, callData, (h) => high.sign(h))).to.equal(0n);
      expect(await validate(account, addr, 0, callData, (h) => high.sign(h, { signedRpId: 'offshoresync.com' })))
        .to.equal(SIG_VALIDATION_FAILED);
      expect(await validate(account, addr, 0, callData, (h) => high.sign(h, { uv: false }))).to.equal(SIG_VALIDATION_FAILED);
    });

    it('may manage authorities, including through a self-call', async () => {
      const high = webauthnKey();
      const { account, addr } = await deployAccount(highModule, high.config);
      const sign = (h: string) => high.sign(h);
      const grant = await partnerGrant();
      const add = enc(account, 'addAuthority', [partnerModule.target, webauthnKey('offshoresync.com').partnerConfig(PARTNER_ID, partnerBackend.address), grant]);
      expect(await validate(account, addr, 0, add, sign)).to.equal(0n);
      expect(await validate(account, addr, 0, enc(account, 'execute', [addr, 0, add]), sign)).to.equal(0n);
      expect(await validate(account, addr, 0, enc(account, 'revokeAuthority', [1]), sign)).to.equal(0n);
    });

    it('may not install an unlisted module', async () => {
      const { account } = await deployAccount(highModule, webauthnKey().config);
      const backdoor = await (await ethers.getContractFactory('MockTierModule')).deploy(TIER.High);
      await expect(account.connect(entryPoint).addAuthority(backdoor, '0x', NO_PERMISSION))
        .to.be.revertedWithCustomError(account, 'ModuleNotAllowed');
    });

    it('caps passkeys at three and never revokes the last one', async () => {
      const { account } = await deployAccount(highModule, webauthnKey().config);
      await expect(account.connect(entryPoint).revokeAuthority(0)).to.be.revertedWithCustomError(account, 'LastHighAuthority');
      await account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION);
      await account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION);
      await expect(account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION))
        .to.be.revertedWithCustomError(account, 'PasskeyCapReached');
      await account.connect(entryPoint).revokeAuthority(0);
      await account.connect(entryPoint).revokeAuthority(1);
      expect(await account.passkeyCount()).to.equal(1);
      await expect(account.connect(entryPoint).revokeAuthority(2)).to.be.revertedWithCustomError(account, 'LastHighAuthority');
      // Revoking an already-inactive passkey is not the last High.
      await account.connect(entryPoint).revokeAuthority(0);
      expect(await account.passkeyCount()).to.equal(1);
    });

    it('signs ERC-1271 over replaySafeHash only, bound to the account', async () => {
      const high = webauthnKey();
      const a = await deployAccount(highModule, high.config);
      const b = await deployAccount(highModule, high.config);
      const digest = ethers.id('permit');
      const { chainId } = await ethers.provider.getNetwork();
      expect(await a.account.replaySafeHash(digest)).to.equal(
        ethers.TypedDataEncoder.hash(
          { name: 'Cofferdam Account', version: '1', chainId, verifyingContract: a.addr },
          { CofferdamAccountMessage: [{ name: 'hash', type: 'bytes32' }] },
          { hash: digest },
        ),
      );
      const sigForA = packSig(0, high.sign(await a.account.replaySafeHash(digest)));
      expect(await a.account.isValidSignature(digest, sigForA)).to.equal(ERC1271_MAGIC);
      expect(await b.account.isValidSignature(digest, sigForA)).to.equal(ERC1271_FAIL);
      expect(await a.account.isValidSignature(digest, packSig(0, high.sign(digest)))).to.equal(ERC1271_FAIL);
      expect(await a.account.isValidSignature(digest, '0x01')).to.equal(ERC1271_FAIL);
    });
  });

  // ── First High: three signatures ─────────────────────────────────────────

  describe('enrollFirstHigh', () => {
    async function firstHighArgs(account: any, signerId: number, high: ReturnType<typeof webauthnKey>, partnerId = PARTNER_ID) {
      const challenge = await account.firstHighChallenge(await account.ceremonyNonce());
      const att = await attest(account, await account.ACTION_ENROLL_FIRST_HIGH(), high.config, partnerId);
      return [signerId, highModule.target, high.config, high.sign(challenge), att];
    }

    it('enrols the first High from a Partner account with all three signatures', async () => {
      const { account, addr, signAs } = await partnerAccount();
      const high = webauthnKey();
      const callData = enc(account, 'enrollFirstHigh', await firstHighArgs(account, 0, high));
      expect(await validate(account, addr, 0, callData, signAs)).to.equal(0n);

      await expect(entryPoint.sendTransaction({ to: addr, data: callData }))
        .to.emit(account, 'FirstHighEnrolled').withArgs(0, 1);
      expect(await account.upgradeLocked()).to.be.true;
      expect(await account.passkeyCount()).to.equal(1);
      expect(await account.ceremonyNonce()).to.equal(1);
      expect((await account.getAuthority(0)).active).to.be.true; // Partner keeps its job calls

      // The path is closed for good, and the new High key can act.
      await expect(validate(account, addr, 0, enc(account, 'enrollFirstHigh', await firstHighArgs(account, 0, webauthnKey())), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 1, enc(account, 'execute', [counterAddr, 0, inc]), (h) => high.sign(h))).to.equal(0n);
    });

    it('works from a Managed account (partner id 0)', async () => {
      const key = sessionKey();
      const { account, addr } = await deployAccount(managedModule, key.config, permission([[counterAddr, INC]]));
      const callData = enc(account, 'enrollFirstHigh', await firstHighArgs(account, 0, webauthnKey(), ethers.ZeroHash));
      expect(await validate(account, addr, 0, callData, (h) => key.sign(addr, h))).to.equal(0n);
      await expect(entryPoint.sendTransaction({ to: addr, data: callData })).to.emit(account, 'FirstHighEnrolled');
    });

    it('is open to an expired Partner grant, so funds are never stranded', async () => {
      const { account, addr, signAs } = await partnerAccount(await partnerGrant(1n));
      await time.increase(2n * DAY);
      const callData = enc(account, 'enrollFirstHigh', await firstHighArgs(account, 0, webauthnKey()));
      expect(await validate(account, addr, 0, callData, signAs)).to.equal(0n);
      await expect(entryPoint.sendTransaction({ to: addr, data: callData })).to.emit(account, 'FirstHighEnrolled');
    });

    it('must name the signing authority', async () => {
      const { account, addr, signAs } = await partnerAccount();
      const callData = enc(account, 'enrollFirstHigh', await firstHighArgs(account, 1, webauthnKey()));
      await expect(validate(account, addr, 0, callData, signAs)).to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('needs the Cofferdam co-sign', async () => {
      const { account, addr } = await partnerAccount();
      const high = webauthnKey();
      const args: any[] = await firstHighArgs(account, 0, high);
      const forged = ethers.Wallet.createRandom();
      const h = await account.ceremonyHash(
        await account.ACTION_ENROLL_FIRST_HIGH(), ethers.keccak256(high.config), PARTNER_ID, 0, args[4].notBefore, args[4].expiry,
      );
      args[4] = { ...args[4], signature: await forged.signMessage(ethers.getBytes(h)) };
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
    });

    it('binds the co-sign to the new key and the partner', async () => {
      const { account, addr } = await partnerAccount();
      const high = webauthnKey();
      const other = webauthnKey();
      // Attested for another key.
      const args: any[] = await firstHighArgs(account, 0, high);
      args[4] = await attest(account, await account.ACTION_ENROLL_FIRST_HIGH(), other.config, PARTNER_ID);
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
      // Attested for another partner.
      args[4] = await attest(account, await account.ACTION_ENROLL_FIRST_HIGH(), high.config, ethers.id('other-partner'));
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
      // Attested for another action.
      args[4] = await attest(account, await account.ACTION_REPLACE_PARTNER(), high.config, PARTNER_ID);
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
    });

    it('needs the new key to be a cofferdam.xyz passkey that signed the challenge', async () => {
      const { account, addr } = await partnerAccount();
      const high = webauthnKey();
      const args: any[] = await firstHighArgs(account, 0, high);
      const challenge = await account.firstHighChallenge(0);
      for (const assertion of [
        high.sign(challenge, { signedRpId: 'offshoresync.com' }), // partner RP
        high.sign(challenge, { uv: false }),
        webauthnKey().sign(challenge), // someone else's key
        high.sign(await account.firstHighChallenge(1)), // stale nonce
      ]) {
        args[3] = assertion;
        await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
          .to.be.revertedWithCustomError(account, 'InvalidNewKeyAssertion');
      }
      // A non-High module is refused.
      args[1] = partnerModule.target;
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', args) }))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('honours the attestation window (the 72h cooldown after a recovery)', async () => {
      const { account, addr } = await partnerAccount();
      const high = webauthnKey();
      const now = BigInt(await time.latest());
      const args: any[] = await firstHighArgs(account, 0, high);
      args[4] = await attest(account, await account.ACTION_ENROLL_FIRST_HIGH(), high.config, PARTNER_ID, [now + 72n * 3600n, now + 73n * 3600n]);
      const callData = enc(account, 'enrollFirstHigh', args);
      await expect(entryPoint.sendTransaction({ to: addr, data: callData })).to.be.revertedWithCustomError(account, 'CeremonyNotActive');
      await time.increase(72n * 3600n);
      await expect(entryPoint.sendTransaction({ to: addr, data: callData })).to.emit(account, 'FirstHighEnrolled');

      const late = await partnerAccount();
      const lateArgs: any[] = await firstHighArgs(late.account, 0, high);
      await time.increase(3600n);
      await expect(entryPoint.sendTransaction({ to: late.addr, data: enc(late.account, 'enrollFirstHigh', lateArgs) }))
        .to.be.revertedWithCustomError(account, 'CeremonyNotActive');
    });

    it('is closed on a High-genesis account', async () => {
      const high = webauthnKey();
      const { account, addr } = await deployAccount(highModule, high.config);
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'enrollFirstHigh', await firstHighArgs(account, 0, webauthnKey())) }))
        .to.be.revertedWithCustomError(account, 'HighAlreadyExists');
    });
  });

  // ── Partner recovery before High ─────────────────────────────────────────

  describe('replacePartnerAuthority (recovery)', () => {
    async function recoveryOp(account: any, oldId: number, newConfig: string, opts: { partner?: any } = {}) {
      const recoveredAt = BigInt(await time.latest());
      const h = await account.partnerRecoveryHash(oldId, ethers.keccak256(newConfig), recoveredAt);
      const recovery = { recoveredAt, signature: await (opts.partner ?? partnerBackend).signMessage(ethers.getBytes(h)) };
      const att = await attest(account, await account.ACTION_REPLACE_PARTNER(), newConfig, PARTNER_ID);
      return enc(account, 'replacePartnerAuthority', [oldId, newConfig, recovery, att]);
    }

    it('re-keys the Partner passkey with partner vouch, new key and Cofferdam co-sign', async () => {
      const p = await partnerGrant();
      const { account, addr } = await partnerAccount(p);
      const newKey = webauthnKey('offshoresync.com');
      const newConfig = newKey.partnerConfig(PARTNER_ID, partnerBackend.address);
      const callData = await recoveryOp(account, 0, newConfig);
      expect(await validate(account, addr, RECOVERY_ID, callData, (h) => newKey.sign(h))).to.equal(0n);

      await expect(entryPoint.sendTransaction({ to: addr, data: callData }))
        .to.emit(account, 'PartnerAuthorityReplaced').withArgs(0, 1);
      expect((await account.getAuthority(0)).active).to.be.false;
      const added = await account.getAuthority(1);
      expect(added.active).to.be.true;
      expect(added.tier).to.equal(TIER.Partner);
      expect(added.config).to.equal(newConfig);
      expect(permissionHash(await account.getPermission(1))).to.equal(permissionHash(p));
      expect(await account.ceremonyNonce()).to.equal(1);

      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 1, enc(account, 'execute', [counterAddr, 0, inc]), (h) => newKey.sign(h)))
        .to.equal(p.expiry << 160n);
      // The same recovery cannot run twice.
      await expect(validate(account, addr, RECOVERY_ID, callData, (h) => newKey.sign(h)))
        .to.be.revertedWithCustomError(account, 'InvalidPartnerRecovery');
    });

    it('needs the partner backend key', async () => {
      const { account, addr } = await partnerAccount();
      const newKey = webauthnKey('offshoresync.com');
      const callData = await recoveryOp(account, 0, newKey.partnerConfig(PARTNER_ID, partnerBackend.address), {
        partner: ethers.Wallet.createRandom(),
      });
      await expect(validate(account, addr, RECOVERY_ID, callData, (h) => newKey.sign(h)))
        .to.be.revertedWithCustomError(account, 'InvalidPartnerRecovery');
    });

    it('may not change the partner, its backend key or its RP', async () => {
      const { account, addr } = await partnerAccount();
      const other = ethers.Wallet.createRandom();
      for (const [key, config] of [
        (() => { const k = webauthnKey('offshoresync.com'); return [k, k.partnerConfig(ethers.id('other'), partnerBackend.address)]; })(),
        (() => { const k = webauthnKey('offshoresync.com'); return [k, k.partnerConfig(PARTNER_ID, other.address)]; })(),
        (() => { const k = webauthnKey('evil.example'); return [k, k.partnerConfig(PARTNER_ID, partnerBackend.address)]; })(),
      ] as Array<[ReturnType<typeof webauthnKey>, string]>) {
        const callData = await recoveryOp(account, 0, config);
        await expect(validate(account, addr, RECOVERY_ID, callData, (h) => key.sign(h)))
          .to.be.revertedWithCustomError(account, 'InvalidPartnerRecovery');
      }
    });

    it('needs the new key to sign the userOp', async () => {
      const { account, addr } = await partnerAccount();
      const newKey = webauthnKey('offshoresync.com');
      const callData = await recoveryOp(account, 0, newKey.partnerConfig(PARTNER_ID, partnerBackend.address));
      expect(await validate(account, addr, RECOVERY_ID, callData, (h) => webauthnKey('offshoresync.com').sign(h)))
        .to.equal(SIG_VALIDATION_FAILED);
    });

    it('needs the Cofferdam co-sign', async () => {
      const { account, addr } = await partnerAccount();
      const newConfig = webauthnKey('offshoresync.com').partnerConfig(PARTNER_ID, partnerBackend.address);
      const recoveredAt = BigInt(await time.latest());
      const h = await account.partnerRecoveryHash(0, ethers.keccak256(newConfig), recoveredAt);
      const recovery = { recoveredAt, signature: await partnerBackend.signMessage(ethers.getBytes(h)) };
      const att = await attest(account, await account.ACTION_REPLACE_PARTNER(), newConfig, ethers.id('other'));
      await expect(entryPoint.sendTransaction({ to: addr, data: enc(account, 'replacePartnerAuthority', [0, newConfig, recovery, att]) }))
        .to.be.revertedWithCustomError(account, 'UntrustedCeremonyAttester');
    });

    it('is only for replacePartnerAuthority, and only before High', async () => {
      const { account, addr } = await partnerAccount();
      const newKey = webauthnKey('offshoresync.com');
      const inc = counter.interface.encodeFunctionData('increment');
      await expect(validate(account, addr, RECOVERY_ID, enc(account, 'execute', [counterAddr, 0, inc]), (h) => newKey.sign(h)))
        .to.be.revertedWithCustomError(account, 'InvalidPartnerRecovery');

      const high = webauthnKey();
      const { account: hAcc, addr: hAddr } = await deployAccount(highModule, high.config);
      await hAcc.connect(entryPoint).addAuthority(partnerModule, newKey.partnerConfig(PARTNER_ID, partnerBackend.address), await partnerGrant());
      const callData = await recoveryOp(hAcc, 1, webauthnKey('offshoresync.com').partnerConfig(PARTNER_ID, partnerBackend.address));
      await expect(validate(hAcc, hAddr, RECOVERY_ID, callData, (h) => newKey.sign(h)))
        .to.be.revertedWithCustomError(hAcc, 'HighAlreadyExists');
    });

    it('a Partner may not call it with its own signature', async () => {
      const { account, addr, signAs } = await partnerAccount();
      const callData = await recoveryOp(account, 0, webauthnKey('offshoresync.com').partnerConfig(PARTNER_ID, partnerBackend.address));
      await expect(validate(account, addr, 0, callData, signAs)).to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });
  });

  // ── Registries ───────────────────────────────────────────────────────────

  describe('CofferdamModuleRegistry', () => {
    it('lets only the owner list and delist modules, with a two-step transfer', async () => {
      const [, , stranger] = await ethers.getSigners();
      const reg = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(await owner.getAddress(), []);
      const m = ethers.Wallet.createRandom().address;
      await expect((reg.connect(stranger) as any).allowModule(m)).to.be.revertedWithCustomError(reg, 'NotOwner');
      await expect(reg.allowModule(m)).to.emit(reg, 'ModuleAllowed').withArgs(m);
      await expect(reg.allowModule(m)).to.be.revertedWithCustomError(reg, 'AlreadyAllowed');
      await expect(reg.disallowModule(m)).to.emit(reg, 'ModuleDisallowed').withArgs(m);
      await reg.transferOwnership(await stranger.getAddress());
      expect(await reg.owner()).to.equal(await owner.getAddress());
      await (reg.connect(stranger) as any).acceptOwnership();
      expect(await reg.owner()).to.equal(await stranger.getAddress());
    });

    it('delisting stops new installs but leaves existing authorities working', async () => {
      const reg = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(await owner.getAddress(), [highModule.target]);
      const Account = await ethers.getContractFactory('CofferdamAccount4337');
      const high = webauthnKey();
      const account: any = await Account.deploy(epAddr, reg, ceremonyRegistry, highModule, high.config, NO_PERMISSION);
      await reg.disallowModule(highModule);
      const addr = await account.getAddress();
      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, inc]), (h) => high.sign(h))).to.equal(0n);
      await expect(account.connect(entryPoint).addAuthority(highModule, webauthnKey().config, NO_PERMISSION))
        .to.be.revertedWithCustomError(account, 'ModuleNotAllowed');
    });
  });

  describe('CofferdamAccountFactory4337', () => {
    it('pins the registries and binds the genesis grant into the address', async () => {
      const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
      const factory: any = await Factory.deploy(epAddr, moduleRegistry, ceremonyRegistry);
      const key = webauthnKey('offshoresync.com');
      const config = key.partnerConfig(PARTNER_ID, partnerBackend.address);
      const p = await partnerGrant();
      const salt = ethers.id('salt');
      const predicted = await factory.getFunction('getAddress')(partnerModule, config, p, salt);
      const wider = { ...p, targets: [counterAddr, counterAddr], selectors: [INC, DEPOSIT] };
      expect(await factory.getFunction('getAddress')(partnerModule, config, wider, salt)).to.not.equal(predicted);

      await expect(factory.deployAccount(partnerModule, config, p, salt)).to.emit(factory, 'AccountDeployed');
      expect(await ethers.provider.getCode(predicted)).to.not.equal('0x');
      await factory.deployAccount(partnerModule, config, p, salt); // idempotent
      const account = await ethers.getContractAt('CofferdamAccount4337', predicted);
      expect(await account.MODULE_REGISTRY()).to.equal(await moduleRegistry.getAddress());
      expect(await account.CEREMONY_ATTESTERS()).to.equal(await ceremonyRegistry.getAddress());
    });
  });

  it('raw P-256 passkeys still work where the registry lists them (test networks)', async () => {
    const pk = rawPasskey();
    const { account, addr } = await deployAccount(rawPasskeyModule, pk.config);
    const inc = counter.interface.encodeFunctionData('increment');
    expect(await validate(account, addr, 0, enc(account, 'execute', [counterAddr, 0, inc]), (h) => pk.sign(h))).to.equal(0n);
  });
});
