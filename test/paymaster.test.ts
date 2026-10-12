import { expect } from 'chai';
import { ethers } from 'hardhat';

describe('CofferdamPaymaster', function () {
  async function deploy() {
    const [owner, attacker, recipient] = await ethers.getSigners();
    const entryPoint = await (await ethers.getContractFactory('MockEntryPoint')).deploy();
    const paymaster = await (await ethers.getContractFactory('CofferdamPaymaster')).deploy(
      await entryPoint.getAddress(),
    );
    const deposit = ethers.parseEther('1');
    await owner.sendTransaction({ to: await paymaster.getAddress(), value: deposit });
    return { owner, attacker, recipient, entryPoint, paymaster, deposit };
  }

  it('sets the deployer as owner', async function () {
    const { owner, paymaster } = await deploy();
    expect(await paymaster.owner()).to.equal(owner.address);
  });

  it('lets the owner withdraw the EntryPoint deposit', async function () {
    const { recipient, entryPoint, paymaster, deposit } = await deploy();
    await expect(paymaster.withdrawTo(recipient.address, deposit)).to.changeEtherBalance(
      recipient,
      deposit,
    );
    expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(0n);
  });

  it('rejects withdrawals from anyone but the owner', async function () {
    const { attacker, entryPoint, paymaster, deposit } = await deploy();
    await expect((paymaster.connect(attacker) as any).withdrawTo(attacker.address, deposit))
      .to.be.revertedWithCustomError(paymaster, 'OwnableUnauthorizedAccount')
      .withArgs(attacker.address);
    expect(await entryPoint.balanceOf(await paymaster.getAddress())).to.equal(deposit);
  });
});
