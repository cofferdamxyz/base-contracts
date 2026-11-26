import { expect } from 'chai';
import { ethers } from 'hardhat';
import { NO_PERMISSION, userOp, webauthnKey } from './helpers/keys';
import { accountCodeFingerprint } from '../scripts/lib/paymaster';

// CofferdamRelayPaymaster, the production generation's paymaster (the
// founder's ruling P9, 2026-11-26): decision 0071's two checks (the relayer as
// tx.origin, the sender running the factory's account code) plus the owner
// from the constructor, two-step ownership, the pause and the per-op cap.
// The EntryPoint is MockEntryPoint, which forwards to the paymaster from the
// transaction's own sender, so a test controls tx.origin.
// test/fork/relay-paymaster-fork.test.ts runs it under the real EntryPoint v0.7.

const CAP = ethers.parseEther('0.001');

describe('CofferdamRelayPaymaster', function () {
  async function deploy() {
    const [deployer, safe, relayer, attacker, recipient, nextSafe] = await ethers.getSigners();
    const entryPoint = await (await ethers.getContractFactory('MockEntryPoint')).deploy();
    const epAddr = await entryPoint.getAddress();

    const highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
    const moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(deployer.address, [
      await highModule.getAddress(),
    ]);
    const ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(deployer.address, []);
    const nullifierRegistry = await ceremonyRegistry.getAddress();
    const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
    const factory = await Factory.deploy(epAddr, moduleRegistry, ceremonyRegistry, nullifierRegistry, 0n, 600n);

    const highAddr = await highModule.getAddress();
    const accountArgs = (salt: string) => [highAddr, webauthnKey().config, NO_PERMISSION, ethers.id(salt)] as const;
    async function account(salt: string, f: any = factory) {
      const args = accountArgs(salt);
      const addr = await f.getFunction('getAddress')(...args);
      await f.deployAccount(...args);
      return addr as string;
    }

    const fp = await accountCodeFingerprint(await factory.getAddress(), await highModule.getAddress());
    const Paymaster = await ethers.getContractFactory('CofferdamRelayPaymaster');
    // Deployed by `deployer` (the Ledger), owned by `safe` from the first block.
    const paymaster = await Paymaster.connect(deployer).deploy(epAddr, safe.address, relayer.address, CAP, fp.codeHash, fp.codeSize, fp.maskOffsets);
    const deposit = ethers.parseEther('1');
    await deployer.sendTransaction({ to: await paymaster.getAddress(), value: deposit });
    const asSafe = paymaster.connect(safe) as typeof paymaster;
    return {
      deployer, safe, relayer, attacker, recipient, nextSafe, entryPoint, epAddr, paymaster, asSafe, Paymaster, deposit, factory, Factory,
      account, accountArgs, fp, moduleRegistry, ceremonyRegistry, nullifierRegistry, highModule,
    };
  }

  const op = (sender: string) => userOp(sender, '0x', '0x');
  const validate = (entryPoint: any, signer: any, paymaster: any, sender: string, maxCost = CAP) =>
    (entryPoint.connect(signer) as any).validatePaymasterWithMaxCost(paymaster, op(sender), maxCost);

  describe('deployment', function () {
    it('is owned by the constructor owner (the Safe), not the deployer, with the relayer and the cap set', async function () {
      const { deployer, safe, relayer, paymaster, entryPoint, deposit } = await deploy();
      expect(await paymaster.owner()).to.equal(safe.address);
      expect(await paymaster.owner()).to.not.equal(deployer.address);
      expect(await paymaster.pendingOwner()).to.equal(ethers.ZeroAddress);
      expect(await paymaster.relayer()).to.equal(relayer.address);
      expect(await paymaster.maxCostPerOp()).to.equal(CAP);
      expect(await paymaster.paused()).to.equal(false);
      expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(deposit);
    });

    it('emits the relayer and the cap it starts with', async function () {
      const { safe, relayer, epAddr, fp, Paymaster } = await deploy();
      const p = await Paymaster.deploy(epAddr, safe.address, relayer.address, CAP, fp.codeHash, fp.codeSize, fp.maskOffsets);
      const tx = p.deploymentTransaction()!;
      await expect(tx).to.emit(p, 'RelayerChanged').withArgs(ethers.ZeroAddress, relayer.address);
      await expect(tx).to.emit(p, 'MaxCostPerOpChanged').withArgs(0n, CAP);
    });

    it('refuses a zero owner, entry point or relayer, the owner as relayer, a zero cap and a bad fingerprint', async function () {
      const { safe, relayer, epAddr, fp, Paymaster } = await deploy();
      const d = (o: Partial<{ ep: string; owner: string; relayer: string; cap: bigint; hash: string; size: number; offsets: number[] }>) =>
        Paymaster.deploy(
          o.ep ?? epAddr,
          o.owner ?? safe.address,
          o.relayer ?? relayer.address,
          o.cap ?? CAP,
          o.hash ?? fp.codeHash,
          o.size ?? fp.codeSize,
          o.offsets ?? fp.maskOffsets,
        );
      await expect(d({ owner: ethers.ZeroAddress })).to.be.revertedWithCustomError(Paymaster, 'OwnableInvalidOwner');
      await expect(d({ ep: ethers.ZeroAddress })).to.be.revertedWithCustomError(Paymaster, 'ZeroAddress');
      await expect(d({ relayer: ethers.ZeroAddress })).to.be.revertedWithCustomError(Paymaster, 'ZeroAddress');
      await expect(d({ relayer: safe.address })).to.be.revertedWithCustomError(Paymaster, 'RelayerIsOwner');
      await expect(d({ cap: 0n })).to.be.revertedWithCustomError(Paymaster, 'ZeroMaxCost');
      await expect(d({ hash: ethers.ZeroHash })).to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
      await expect(d({ size: 31 })).to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
      await expect(d({ offsets: [fp.codeSize - 31] })).to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
      await expect(d({ offsets: Array(17).fill(0) })).to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
    });
  });

  describe('sponsorship', function () {
    it('sponsors a factory account when the relayer submits, within the cap, with no postOp', async function () {
      const { relayer, entryPoint, paymaster, account } = await deploy();
      for (const sender of [await account('a'), await account('b')]) {
        const [context, validationData] = await validate(entryPoint, relayer, paymaster, sender);
        expect(validationData).to.equal(0n);
        expect(context).to.equal('0x');
        expect(await paymaster.isCofferdamAccount(sender)).to.equal(true);
      }
    });

    it('sponsors a first op whose initCode deploys the sender (the EntryPoint deploys before it asks)', async function () {
      const { relayer, entryPoint, paymaster, factory, accountArgs } = await deploy();
      const args = accountArgs('first');
      const sender: string = await factory.getFunction('getAddress')(...args);
      expect(await ethers.provider.getCode(sender)).to.equal('0x');
      const initCode = ethers.concat([await factory.getAddress(), factory.interface.encodeFunctionData('deployAccount', [...args])]);
      const first = { ...op(sender), initCode };
      const [context, validationData] = await (entryPoint.connect(relayer) as any).createSenderThenValidate.staticCall(paymaster, first, CAP);
      expect(validationData).to.equal(0n);
      expect(context).to.equal('0x');
      // An attacker's relayer-less first op is refused even though its sender gets deployed.
      const [, , , attacker] = await ethers.getSigners();
      await expect((entryPoint.connect(attacker) as any).createSenderThenValidate(paymaster, first, CAP))
        .to.be.revertedWithCustomError(paymaster, 'NotRelayer')
        .withArgs(attacker.address);
    });

    it('refuses any other tx.origin, the owner and the deployer included', async function () {
      const { deployer, safe, attacker, entryPoint, paymaster, account } = await deploy();
      const a = await account('a');
      for (const s of [attacker, safe, deployer]) {
        await expect(validate(entryPoint, s, paymaster, a)).to.be.revertedWithCustomError(paymaster, 'NotRelayer').withArgs(s.address);
      }
    });

    it('refuses senders that are not accounts of this factory', async function () {
      const { relayer, attacker, entryPoint, paymaster, Factory, account, epAddr, moduleRegistry, ceremonyRegistry, nullifierRegistry } =
        await deploy();
      const counter = await (await ethers.getContractFactory('MockCounter')).deploy();
      // Same account code, other factory settings: a different immutable outside the mask.
      const other = await Factory.deploy(epAddr, moduleRegistry, ceremonyRegistry, nullifierRegistry, 0n, 601n);
      const foreign = await account('a', other);
      for (const sender of [attacker.address, await counter.getAddress(), foreign]) {
        expect(await paymaster.isCofferdamAccount(sender)).to.equal(false);
        await expect(validate(entryPoint, relayer, paymaster, sender))
          .to.be.revertedWithCustomError(paymaster, 'NotCofferdamAccount')
          .withArgs(sender);
      }
    });

    it('answers only the EntryPoint', async function () {
      const { relayer, paymaster, account } = await deploy();
      const a = await account('a');
      await expect((paymaster.connect(relayer) as any).validatePaymasterUserOp(op(a), ethers.ZeroHash, 0n)).to.be.revertedWithCustomError(
        paymaster,
        'NotEntryPoint',
      );
      await expect((paymaster.connect(relayer) as any).postOp(0, '0x', 0n, 0n)).to.be.revertedWithCustomError(paymaster, 'NotEntryPoint');
    });
  });

  describe('the per-op cap', function () {
    it('sponsors maxCost up to the cap and refuses one wei above it', async function () {
      const { relayer, entryPoint, paymaster, account } = await deploy();
      const a = await account('a');
      const [, ok] = await validate(entryPoint, relayer, paymaster, a, CAP);
      expect(ok).to.equal(0n);
      await expect(validate(entryPoint, relayer, paymaster, a, CAP + 1n))
        .to.be.revertedWithCustomError(paymaster, 'MaxCostExceeded')
        .withArgs(CAP + 1n, CAP);
    });

    it('lets only the owner change the cap, never to zero', async function () {
      const { relayer, attacker, entryPoint, paymaster, asSafe, account } = await deploy();
      const a = await account('a');
      const higher = CAP * 2n;
      await expect(asSafe.setMaxCostPerOp(higher)).to.emit(paymaster, 'MaxCostPerOpChanged').withArgs(CAP, higher);
      expect(await paymaster.maxCostPerOp()).to.equal(higher);
      const [, ok] = await validate(entryPoint, relayer, paymaster, a, higher);
      expect(ok).to.equal(0n);
      await expect(asSafe.setMaxCostPerOp(0n)).to.be.revertedWithCustomError(paymaster, 'ZeroMaxCost');
      await expect((paymaster.connect(attacker) as any).setMaxCostPerOp(1n))
        .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
        .withArgs(attacker.address);
      await expect((paymaster.connect(relayer) as any).setMaxCostPerOp(1n)).to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount');
    });
  });

  describe('the pause', function () {
    it('refuses every op while paused, and sponsors again once resumed', async function () {
      const { relayer, entryPoint, paymaster, asSafe, account } = await deploy();
      const a = await account('a');
      await expect(asSafe.setPaused(true)).to.emit(paymaster, 'PausedSet').withArgs(true);
      expect(await paymaster.paused()).to.equal(true);
      await expect(validate(entryPoint, relayer, paymaster, a)).to.be.revertedWithCustomError(paymaster, 'SponsorshipPaused');
      await expect(asSafe.setPaused(false)).to.emit(paymaster, 'PausedSet').withArgs(false);
      const [, ok] = await validate(entryPoint, relayer, paymaster, a);
      expect(ok).to.equal(0n);
    });

    it('is the owner’s only, the relayer and the deployer included', async function () {
      const { deployer, relayer, attacker, paymaster } = await deploy();
      for (const s of [attacker, relayer, deployer]) {
        await expect((paymaster.connect(s) as any).setPaused(true))
          .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
          .withArgs(s.address);
      }
    });
  });

  describe('relayer rotation', function () {
    it('moves sponsorship to the new relayer, with an event', async function () {
      const { relayer, recipient, entryPoint, paymaster, asSafe, account } = await deploy();
      const a = await account('a');
      await expect(asSafe.setRelayer(recipient.address)).to.emit(paymaster, 'RelayerChanged').withArgs(relayer.address, recipient.address);
      expect(await paymaster.relayer()).to.equal(recipient.address);
      await expect(validate(entryPoint, relayer, paymaster, a)).to.be.revertedWithCustomError(paymaster, 'NotRelayer').withArgs(relayer.address);
      const [, ok] = await validate(entryPoint, recipient, paymaster, a);
      expect(ok).to.equal(0n);
    });

    it('refuses zero, the owner, and anyone but the owner (the relayer cannot rotate itself)', async function () {
      const { safe, relayer, attacker, paymaster, asSafe } = await deploy();
      await expect(asSafe.setRelayer(ethers.ZeroAddress)).to.be.revertedWithCustomError(paymaster, 'ZeroAddress');
      await expect(asSafe.setRelayer(safe.address)).to.be.revertedWithCustomError(paymaster, 'RelayerIsOwner');
      for (const s of [attacker, relayer]) {
        await expect((paymaster.connect(s) as any).setRelayer(s.address))
          .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
          .withArgs(s.address);
      }
    });
  });

  describe('ownership', function () {
    it('moves in two steps: nominated by the owner, then accepted by the nominee', async function () {
      const { safe, nextSafe, attacker, paymaster, asSafe } = await deploy();
      await expect((paymaster.connect(attacker) as any).transferOwnership(attacker.address))
        .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
        .withArgs(attacker.address);
      await expect(asSafe.transferOwnership(nextSafe.address))
        .to.emit(paymaster, 'OwnershipTransferStarted')
        .withArgs(safe.address, nextSafe.address);
      // Nothing moves until the nominee accepts: the old Safe still governs.
      expect(await paymaster.owner()).to.equal(safe.address);
      expect(await paymaster.pendingOwner()).to.equal(nextSafe.address);
      await expect(asSafe.setPaused(true)).to.not.be.reverted;
      await expect((paymaster.connect(attacker) as any).acceptOwnership())
        .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
        .withArgs(attacker.address);
      await expect((paymaster.connect(nextSafe) as any).acceptOwnership())
        .to.emit(paymaster, 'OwnershipTransferred')
        .withArgs(safe.address, nextSafe.address);
      expect(await paymaster.owner()).to.equal(nextSafe.address);
      expect(await paymaster.pendingOwner()).to.equal(ethers.ZeroAddress);
      await expect(asSafe.setPaused(false)).to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount').withArgs(safe.address);
      await expect((paymaster.connect(nextSafe) as any).setPaused(false)).to.emit(paymaster, 'PausedSet').withArgs(false);
    });

    it('lets the owner withdraw a nomination by nominating zero', async function () {
      const { nextSafe, paymaster, asSafe } = await deploy();
      await asSafe.transferOwnership(nextSafe.address);
      await asSafe.transferOwnership(ethers.ZeroAddress);
      expect(await paymaster.pendingOwner()).to.equal(ethers.ZeroAddress);
      await expect((paymaster.connect(nextSafe) as any).acceptOwnership()).to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount');
    });

    it('cannot be renounced', async function () {
      const { attacker, paymaster, asSafe, safe } = await deploy();
      await expect(asSafe.renounceOwnership()).to.be.revertedWithCustomError(paymaster, 'RenounceDisabled');
      await expect((paymaster.connect(attacker) as any).renounceOwnership()).to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount');
      expect(await paymaster.owner()).to.equal(safe.address);
    });
  });

  describe('the deposit', function () {
    it('lets the owner withdraw it to any non-zero address', async function () {
      const { recipient, entryPoint, paymaster, asSafe, deposit } = await deploy();
      await expect(asSafe.withdrawTo(recipient.address, deposit)).to.changeEtherBalance(recipient, deposit);
      expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(0n);
      await expect(asSafe.withdrawTo(ethers.ZeroAddress, 0n)).to.be.revertedWithCustomError(paymaster, 'ZeroAddress');
    });

    it('refuses a withdrawal by anyone but the owner, the relayer and the deployer included', async function () {
      const { deployer, relayer, attacker, entryPoint, paymaster, deposit } = await deploy();
      for (const s of [attacker, relayer, deployer]) {
        await expect((paymaster.connect(s) as any).withdrawTo(s.address, deposit))
          .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
          .withArgs(s.address);
      }
      expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(deposit);
    });

    it('takes a top-up from anyone, credited to its EntryPoint deposit', async function () {
      const { attacker, entryPoint, paymaster, deposit } = await deploy();
      await attacker.sendTransaction({ to: await paymaster.getAddress(), value: 5n });
      expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(deposit + 5n);
    });
  });
});
