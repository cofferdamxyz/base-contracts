import { expect } from 'chai';
import { ethers } from 'hardhat';
import { p256 } from '@noble/curves/p256';
import type { Signer } from 'ethers';

// Tier enum values (contracts/interfaces/IAuthorityModule.sol)
const LOW_UNTRUSTED = 1;
const LOW_MANAGED = 2;

const ERC1271_MAGIC = '0x1626ba7e';
const ERC1271_FAIL = '0xffffffff';

const coder = ethers.AbiCoder.defaultAbiCoder();

/** A server-held session key, signing the way SessionKeyAuthority expects. */
function sessionKey() {
  const wallet = ethers.Wallet.createRandom();
  const key = new ethers.SigningKey(wallet.privateKey);
  return {
    config: coder.encode(['address'], [wallet.address]),
    sign(account: string, digest: string): string {
      const bound = ethers.keccak256(coder.encode(['address', 'bytes32'], [account, digest]));
      const sig = key.sign(ethers.hashMessage(ethers.getBytes(bound)));
      return ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);
    },
  };
}

/** A raw P-256 passkey, signing the way PasskeyAuthority expects. */
function passkey() {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false); // 0x04 || x || y
  return {
    config: coder.encode(['bytes32', 'bytes32'], [pub.slice(1, 33), pub.slice(33, 65)]),
    sign(digest: string): string {
      const sig = p256.sign(ethers.getBytes(digest), priv, { lowS: true }); // P256.verify rejects high s
      return ethers.concat([ethers.toBeHex(sig.r, 32), ethers.toBeHex(sig.s, 32)]);
    },
  };
}

function packSig(authorityId: number, userSig: string): string {
  return ethers.solidityPacked(['uint256', 'bytes'], [authorityId, userSig]);
}

function userOp(sender: string, callData: string, signature: string) {
  return {
    sender,
    nonce: 0n,
    initCode: '0x',
    callData,
    accountGasLimits: ethers.ZeroHash,
    preVerificationGas: 0n,
    gasFees: ethers.ZeroHash,
    paymasterAndData: '0x',
    signature,
  };
}

describe('CofferdamAccount4337 tier gating', () => {
  // The account's EntryPoint is a plain signer, so tests can call
  // validateUserOp and the execution functions directly.
  let entryPoint: Signer;
  let epAddr: string;
  let passkeyModule: any;
  let untrustedModule: any;
  let managedModule: any;
  let counter: any;

  before(async () => {
    [, entryPoint] = await ethers.getSigners();
    epAddr = await entryPoint.getAddress();
    passkeyModule = await (await ethers.getContractFactory('PasskeyAuthority')).deploy();
    const Session = await ethers.getContractFactory('SessionKeyAuthority');
    untrustedModule = await Session.deploy(LOW_UNTRUSTED);
    managedModule = await Session.deploy(LOW_MANAGED);
    counter = await (await ethers.getContractFactory('MockCounter')).deploy();
  });

  async function deployAccount(module: any, config: string) {
    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account: any = await Account.deploy(epAddr, await module.getAddress(), config);
    return { account, addr: await account.getAddress() };
  }

  /** Run validateUserOp from the EntryPoint for `callData` signed by `sign`. */
  function validate(account: any, addr: string, authorityId: number, callData: string, sign: (h: string) => string) {
    const hash = ethers.hexlify(ethers.randomBytes(32));
    const op = userOp(addr, callData, packSig(authorityId, sign(hash)));
    return account.connect(entryPoint).validateUserOp.staticCall(op, hash, 0);
  }

  function enc(account: any, fn: string, args: unknown[]): string {
    return account.interface.encodeFunctionData(fn, args);
  }

  describe('LowUntrusted session key', () => {
    let account: any, addr: string, key: ReturnType<typeof sessionKey>;
    const signAs = (h: string) => key.sign(addr, h);

    beforeEach(async () => {
      key = sessionKey();
      ({ account, addr } = await deployAccount(untrustedModule, key.config));
    });

    it('cannot execute or executeBatch', async () => {
      const inc = counter.interface.encodeFunctionData('increment');
      const target = await counter.getAddress();
      await expect(validate(account, addr, 0, enc(account, 'execute', [target, 0, inc]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(LOW_UNTRUSTED);
      await expect(validate(account, addr, 0, enc(account, 'executeBatch', [[target], [0], [inc]]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('cannot add or revoke authorities', async () => {
      const attacker = passkey();
      await expect(
        validate(account, addr, 0, enc(account, 'addAuthority', [0, await passkeyModule.getAddress(), attacker.config]), signAs),
      ).to.be.revertedWithCustomError(account, 'TierNotPermitted');
      await expect(validate(account, addr, 0, enc(account, 'revokeAuthority', [0, 0]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('cannot reach management functions through a self-call', async () => {
      const pk = passkey();
      const inner = enc(account, 'enrollFirstPasskey', [0, await passkeyModule.getAddress(), pk.config]);
      await expect(validate(account, addr, 0, enc(account, 'execute', [addr, 0, inner]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('cannot enrol a passkey on behalf of a different authority id', async () => {
      const pk = passkey();
      await expect(
        validate(account, addr, 0, enc(account, 'enrollFirstPasskey', [1, await passkeyModule.getAddress(), pk.config]), signAs),
      ).to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('may enrol the first passkey, which fires the ratchet and locks it out', async () => {
      const pk = passkey();
      const callData = enc(account, 'enrollFirstPasskey', [0, await passkeyModule.getAddress(), pk.config]);
      expect(await validate(account, addr, 0, callData, signAs)).to.equal(0n);

      await expect(entryPoint.sendTransaction({ to: addr, data: callData }))
        .to.emit(account, 'RatchetFired')
        .and.to.emit(account, 'FirstPasskeyEnrolled').withArgs(0, 1);
      expect(await account.upgradeLocked()).to.be.true;
      expect((await account.getAuthority(0)).active).to.be.false;

      // The session key is dead for every call, enrolment included.
      await expect(validate(account, addr, 0, callData, signAs))
        .to.be.revertedWithCustomError(account, 'InactiveAuthority');

      // The new passkey can act.
      const inc = counter.interface.encodeFunctionData('increment');
      expect(
        await validate(account, addr, 1, enc(account, 'execute', [await counter.getAddress(), 0, inc]), (h) => pk.sign(h)),
      ).to.equal(0n);
    });

    it('still rejects a bad signature', async () => {
      const other = sessionKey();
      const pk = passkey();
      const callData = enc(account, 'enrollFirstPasskey', [0, await passkeyModule.getAddress(), pk.config]);
      await expect(validate(account, addr, 0, callData, (h) => other.sign(addr, h)))
        .to.be.revertedWithCustomError(account, 'InvalidAuthoritySignature');
    });
  });

  describe('LowManaged session key', () => {
    let account: any, addr: string, key: ReturnType<typeof sessionKey>;
    const signAs = (h: string) => key.sign(addr, h);

    beforeEach(async () => {
      key = sessionKey();
      ({ account, addr } = await deployAccount(managedModule, key.config));
    });

    it('may execute and executeBatch calls to other contracts', async () => {
      const inc = counter.interface.encodeFunctionData('increment');
      const target = await counter.getAddress();
      expect(await validate(account, addr, 0, enc(account, 'execute', [target, 0, inc]), signAs)).to.equal(0n);
      expect(await validate(account, addr, 0, enc(account, 'executeBatch', [[target, target], [0, 0], [inc, inc]]), signAs))
        .to.equal(0n);
    });

    it('may not call the account itself through execute or executeBatch', async () => {
      const inc = counter.interface.encodeFunctionData('increment');
      const revoke = enc(account, 'revokeAuthority', [0, 0]);
      await expect(validate(account, addr, 0, enc(account, 'execute', [addr, 0, revoke]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(LOW_MANAGED);
      await expect(
        validate(account, addr, 0, enc(account, 'executeBatch', [[await counter.getAddress(), addr], [0, 0], [inc, revoke]]), signAs),
      ).to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('may add a passkey, which fires the ratchet', async () => {
      // Add a LowUntrusted authority first (as a High signer would) so the
      // ratchet has something to deactivate.
      const legacy = sessionKey();
      await account.connect(entryPoint).addAuthority(0, await untrustedModule.getAddress(), legacy.config);
      expect(await account.upgradeLocked()).to.be.false;

      const pk = passkey();
      const callData = enc(account, 'addAuthority', [0, await passkeyModule.getAddress(), pk.config]);
      expect(await validate(account, addr, 0, callData, signAs)).to.equal(0n);
      await expect(entryPoint.sendTransaction({ to: addr, data: callData })).to.emit(account, 'RatchetFired');

      expect(await account.upgradeLocked()).to.be.true;
      expect((await account.getAuthority(1)).active).to.be.false; // LowUntrusted, ratcheted
      expect((await account.getAuthority(0)).active).to.be.true; // LowManaged survives (OR semantics)
    });

    it('may not add any authority once a passkey exists', async () => {
      await account.connect(entryPoint).addAuthority(0, await passkeyModule.getAddress(), passkey().config);
      expect(await account.upgradeLocked()).to.be.true;
      const callData = enc(account, 'addAuthority', [0, await passkeyModule.getAddress(), passkey().config]);
      await expect(validate(account, addr, 0, callData, signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted').withArgs(LOW_MANAGED);
      // It can still execute company-bound ops (OR semantics).
      const inc = counter.interface.encodeFunctionData('increment');
      expect(await validate(account, addr, 0, enc(account, 'execute', [await counter.getAddress(), 0, inc]), signAs))
        .to.equal(0n);
    });

    it('may not add a low-tier authority or revoke one', async () => {
      const other = sessionKey();
      for (const mod of [untrustedModule, managedModule]) {
        await expect(validate(account, addr, 0, enc(account, 'addAuthority', [0, await mod.getAddress(), other.config]), signAs))
          .to.be.revertedWithCustomError(account, 'TierNotPermitted');
      }
      await expect(validate(account, addr, 0, enc(account, 'revokeAuthority', [0, 0]), signAs))
        .to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });

    it('may not call enrollFirstPasskey or arbitrary selectors', async () => {
      const pk = passkey();
      await expect(
        validate(account, addr, 0, enc(account, 'enrollFirstPasskey', [0, await passkeyModule.getAddress(), pk.config]), signAs),
      ).to.be.revertedWithCustomError(account, 'TierNotPermitted');
      await expect(validate(account, addr, 0, '0x', signAs)).to.be.revertedWithCustomError(account, 'TierNotPermitted');
    });
  });

  describe('High passkey', () => {
    it('may manage authorities, including through a self-call', async () => {
      const pk = passkey();
      const { account, addr } = await deployAccount(passkeyModule, pk.config);
      const sign = (h: string) => pk.sign(h);
      const revoke = enc(account, 'revokeAuthority', [0, 0]);
      expect(await validate(account, addr, 0, revoke, sign)).to.equal(0n);
      expect(await validate(account, addr, 0, enc(account, 'execute', [addr, 0, revoke]), sign)).to.equal(0n);
      const backup = passkey();
      expect(
        await validate(account, addr, 0, enc(account, 'addAuthority', [0, await passkeyModule.getAddress(), backup.config]), sign),
      ).to.equal(0n);
    });
  });

  describe('ratchet', () => {
    it('refuses a LowUntrusted authority once locked', async () => {
      const pk = passkey();
      const { account } = await deployAccount(passkeyModule, pk.config);
      await expect(account.connect(entryPoint).addAuthority(0, await untrustedModule.getAddress(), sessionKey().config))
        .to.be.revertedWithCustomError(account, 'UpgradeLocked');
      // LowManaged is not ratchet-locked.
      await account.connect(entryPoint).addAuthority(0, await managedModule.getAddress(), sessionKey().config);
      expect((await account.getAuthority(1)).active).to.be.true;
    });

    it('fires when a passkey is added through addAuthority', async () => {
      const { account } = await deployAccount(untrustedModule, sessionKey().config);
      await expect(account.connect(entryPoint).addAuthority(0, await passkeyModule.getAddress(), passkey().config))
        .to.emit(account, 'RatchetFired')
        .and.to.emit(account, 'AuthorityRevoked').withArgs(0);
      expect(await account.upgradeLocked()).to.be.true;
      expect((await account.getAuthority(0)).active).to.be.false;
      await expect(account.connect(entryPoint).enrollFirstPasskey(0, await passkeyModule.getAddress(), passkey().config))
        .to.be.revertedWithCustomError(account, 'PasskeyAlreadyExists');
    });

    it('stays locked after every passkey is revoked', async () => {
      const { account } = await deployAccount(passkeyModule, passkey().config);
      await account.connect(entryPoint).revokeAuthority(0, 0);
      expect(await account.passkeyCount()).to.equal(0);
      await expect(account.connect(entryPoint).enrollFirstPasskey(0, await passkeyModule.getAddress(), passkey().config))
        .to.be.revertedWithCustomError(account, 'PasskeyAlreadyExists');
      await expect(account.connect(entryPoint).addAuthority(0, await untrustedModule.getAddress(), sessionKey().config))
        .to.be.revertedWithCustomError(account, 'UpgradeLocked');
    });
  });

  describe('ERC-1271', () => {
    const digest = ethers.id('permit');

    it('replaySafeHash is the EIP-712 hash under the account domain', async () => {
      const { account, addr } = await deployAccount(passkeyModule, passkey().config);
      const { chainId } = await ethers.provider.getNetwork();
      const expected = ethers.TypedDataEncoder.hash(
        { name: 'Cofferdam Account', version: '1', chainId, verifyingContract: addr },
        { CofferdamAccountMessage: [{ name: 'hash', type: 'bytes32' }] },
        { hash: digest },
      );
      expect(await account.replaySafeHash(digest)).to.equal(expected);
    });

    it('a passkey signature for one account is not valid on another', async () => {
      const pk = passkey();
      const a = await deployAccount(passkeyModule, pk.config);
      const b = await deployAccount(passkeyModule, pk.config);
      const sigForA = packSig(0, pk.sign(await a.account.replaySafeHash(digest)));
      expect(await a.account.isValidSignature(digest, sigForA)).to.equal(ERC1271_MAGIC);
      expect(await b.account.isValidSignature(digest, sigForA)).to.equal(ERC1271_FAIL);

      // A signature over the bare digest is valid nowhere.
      const raw = packSig(0, pk.sign(digest));
      expect(await a.account.isValidSignature(digest, raw)).to.equal(ERC1271_FAIL);
      expect(await b.account.isValidSignature(digest, raw)).to.equal(ERC1271_FAIL);
    });

    it('accepts LowManaged signatures', async () => {
      const key = sessionKey();
      const { account, addr } = await deployAccount(managedModule, key.config);
      const sig = packSig(0, key.sign(addr, await account.replaySafeHash(digest)));
      expect(await account.isValidSignature(digest, sig)).to.equal(ERC1271_MAGIC);
    });

    it('rejects LowUntrusted signatures', async () => {
      const key = sessionKey();
      const { account, addr } = await deployAccount(untrustedModule, key.config);
      const safe = packSig(0, key.sign(addr, await account.replaySafeHash(digest)));
      const raw = packSig(0, key.sign(addr, digest));
      expect(await account.isValidSignature(digest, safe)).to.equal(ERC1271_FAIL);
      expect(await account.isValidSignature(digest, raw)).to.equal(ERC1271_FAIL);
    });
  });
});
