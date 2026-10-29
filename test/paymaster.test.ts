import { expect } from 'chai';
import { ethers } from 'hardhat';
import { NO_PERMISSION, userOp, webauthnKey } from './helpers/keys';
import { accountCodeFingerprint } from '../scripts/lib/paymaster';

describe('CofferdamPaymaster', function () {
  async function deploy() {
    const [owner, relayer, attacker, recipient] = await ethers.getSigners();
    const entryPoint = await (await ethers.getContractFactory('MockEntryPoint')).deploy();
    const epAddr = await entryPoint.getAddress();

    const highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
    const moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(owner.address, [
      await highModule.getAddress(),
    ]);
    const ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(owner.address, []);
    // The account only needs a non-zero nullifier registry to be built.
    const nullifierRegistry = await ceremonyRegistry.getAddress();
    const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
    const factory = await Factory.deploy(epAddr, moduleRegistry, ceremonyRegistry, nullifierRegistry, 0n, 600n);

    async function account(salt: string, f: any = factory) {
      const key = webauthnKey();
      const args = [highModule, key.config, NO_PERMISSION, ethers.id(salt)] as const;
      const addr = await f.getFunction('getAddress')(...args);
      await f.deployAccount(...args);
      return addr;
    }

    const fp = await accountCodeFingerprint(await factory.getAddress(), await highModule.getAddress());
    const paymaster = await (await ethers.getContractFactory('CofferdamPaymaster')).deploy(
      epAddr,
      relayer.address,
      fp.codeHash,
      fp.codeSize,
      fp.maskOffsets,
    );
    const deposit = ethers.parseEther('1');
    await owner.sendTransaction({ to: await paymaster.getAddress(), value: deposit });
    return { owner, relayer, attacker, recipient, entryPoint, paymaster, deposit, factory, Factory, account, fp, epAddr, moduleRegistry, ceremonyRegistry, nullifierRegistry, highModule };
  }

  const op = (sender: string) => userOp(sender, '0x', '0x');

  it('sets the deployer as owner', async function () {
    const { owner, paymaster } = await deploy();
    expect(await paymaster.owner()).to.equal(owner.address);
  });

  it('lets the owner withdraw the EntryPoint deposit', async function () {
    const { recipient, entryPoint, paymaster, deposit } = await deploy();
    await expect(paymaster.withdrawTo(recipient.address, deposit)).to.changeEtherBalance(recipient, deposit);
    expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(0n);
  });

  it('rejects withdrawals from anyone but the owner', async function () {
    const { attacker, entryPoint, paymaster, deposit } = await deploy();
    await expect((paymaster.connect(attacker) as any).withdrawTo(attacker.address, deposit))
      .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
      .withArgs(attacker.address);
    expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(deposit);
  });

  describe('sponsorship', function () {
    it('masks only the two per-account words (address and domain separator)', async function () {
      const { fp } = await deploy();
      expect(fp.maskOffsets.length).to.equal(2);
    });

    it('sponsors a factory account when the relayer submits', async function () {
      const { relayer, entryPoint, paymaster, account } = await deploy();
      const a = await account('a');
      const b = await account('b');
      for (const sender of [a, b]) {
        const [context, validationData] = await (entryPoint.connect(relayer) as any).validatePaymaster(paymaster, op(sender));
        expect(validationData).to.equal(0n);
        expect(context).to.equal('0x'); // no postOp
        expect(await paymaster.isCofferdamAccount(sender)).to.equal(true);
      }
      // The masked hash stays a small part of validation gas.
      const gas = await paymaster.isCofferdamAccount.estimateGas(a);
      expect(gas - 21_000n).to.be.lessThan(25_000n);
    });

    it('refuses any other tx.origin, even for a Cofferdam account', async function () {
      const { attacker, entryPoint, paymaster, account } = await deploy();
      const a = await account('a');
      await expect((entryPoint.connect(attacker) as any).validatePaymaster(paymaster, op(a)))
        .to.be.revertedWithCustomError(paymaster, 'NotRelayer')
        .withArgs(attacker.address);
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
        await expect((entryPoint.connect(relayer) as any).validatePaymaster(paymaster, op(sender)))
          .to.be.revertedWithCustomError(paymaster, 'NotCofferdamAccount')
          .withArgs(sender);
      }
    });

    it('answers only the EntryPoint', async function () {
      const { relayer, paymaster, account } = await deploy();
      const a = await account('a');
      await expect((paymaster.connect(relayer) as any).validatePaymasterUserOp(op(a), ethers.ZeroHash, 0n))
        .to.be.revertedWithCustomError(paymaster, 'NotEntryPoint');
      await expect((paymaster.connect(relayer) as any).postOp(0, '0x', 0n, 0n))
        .to.be.revertedWithCustomError(paymaster, 'NotEntryPoint');
    });
  });

  describe('relayer rotation', function () {
    it('lets the owner move sponsorship to a new relayer', async function () {
      const { relayer, attacker, recipient, entryPoint, paymaster, account } = await deploy();
      const a = await account('a');
      await expect(paymaster.setRelayer(recipient.address))
        .to.emit(paymaster, 'RelayerChanged')
        .withArgs(relayer.address, recipient.address);
      await expect((entryPoint.connect(relayer) as any).validatePaymaster(paymaster, op(a)))
        .to.be.revertedWithCustomError(paymaster, 'NotRelayer');
      const [, validationData] = await (entryPoint.connect(recipient) as any).validatePaymaster(paymaster, op(a));
      expect(validationData).to.equal(0n);
      await expect((paymaster.connect(attacker) as any).setRelayer(attacker.address))
        .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount');
      await expect(paymaster.setRelayer(ethers.ZeroAddress)).to.be.revertedWithCustomError(paymaster, 'ZeroAddress');
    });
  });

  describe('constructor', function () {
    it('refuses a zero relayer, a zero hash and offsets past the code', async function () {
      const { entryPoint, fp } = await deploy();
      const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
      const ep = await entryPoint.getAddress();
      const [, relayer] = await ethers.getSigners();
      await expect(Paymaster.deploy(ep, ethers.ZeroAddress, fp.codeHash, fp.codeSize, fp.maskOffsets))
        .to.be.revertedWithCustomError(Paymaster, 'ZeroAddress');
      await expect(Paymaster.deploy(ep, relayer.address, ethers.ZeroHash, fp.codeSize, fp.maskOffsets))
        .to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
      await expect(Paymaster.deploy(ep, relayer.address, fp.codeHash, fp.codeSize, [fp.codeSize - 31]))
        .to.be.revertedWithCustomError(Paymaster, 'InvalidAccountCode');
    });
  });
});
