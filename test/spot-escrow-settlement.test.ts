import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

/**
 * Settlement paths of CofferdamSpotEscrow: every exit must leave the escrow
 * empty and pay only the funder or the predetermined worker (2026-10-15 fixes:
 * no kill fee without an awarded worker; no dispute before an award).
 */

const USDC_ARTIFACT = 'contracts/test/MockUSDC.sol:USDC';

const CHECK_IN_TIMEOUT = 3600;
const CHECK_OUT_TIMEOUT = 86_400;
const DISPUTE_WINDOW = 172_800;
const KILL_FEE_BPS = 1000;

async function deployFixture() {
  const [deployer, funder, recruiter, witness, worker, arbiter, stranger] = await ethers.getSigners();
  const Usdc = await ethers.getContractFactory(USDC_ARTIFACT);
  const usdc = (await Usdc.deploy('USD Coin', 'USDC')) as any;
  await usdc.waitForDeployment();
  const amount = ethers.parseUnits('5000', 6);
  await (await usdc.mint(funder.address, amount * 10n)).wait();
  return { deployer, funder, recruiter, witness, worker, arbiter, stranger, usdc, amount };
}

async function fundedEscrow(ctx: Awaited<ReturnType<typeof deployFixture>>) {
  const policy = {
    funder: ctx.funder.address,
    recruiter: ctx.recruiter.address,
    workerNullifier: ethers.ZeroHash,
    checkInTimeout: CHECK_IN_TIMEOUT,
    checkOutTimeout: CHECK_OUT_TIMEOUT,
    witness: ctx.witness.address,
    arbiter: ctx.arbiter.address,
    killFeeBps: KILL_FEE_BPS,
    amount: ctx.amount,
    termsHash: ethers.ZeroHash,
    jobStartTime: 0,
    disputeWindow: DISPUTE_WINDOW,
  };
  const Escrow = await ethers.getContractFactory('CofferdamSpotEscrow');
  const escrow = (await Escrow.deploy(await ctx.usdc.getAddress(), policy)) as any;
  await escrow.waitForDeployment();
  await (await ctx.usdc.connect(ctx.funder).approve(await escrow.getAddress(), ctx.amount)).wait();
  await (await escrow.connect(ctx.funder).fund(ctx.amount)).wait();
  return escrow;
}

const balance = (usdc: any, who: { address: string } | string) =>
  usdc.balanceOf(typeof who === 'string' ? who : who.address) as Promise<bigint>;

describe('CofferdamSpotEscrow — refund', () => {
  it('returns the full amount when nobody was awarded, leaving nothing in the escrow', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedEscrow(ctx);
    const before = await balance(ctx.usdc, ctx.funder);

    await expect(escrow.connect(ctx.funder).refund()).to.not.emit(escrow, 'KillFeePaid');

    expect((await balance(ctx.usdc, ctx.funder)) - before).to.equal(ctx.amount);
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
    expect(await escrow.state()).to.equal(7n); // EscrowState.Refunded
  });

  it('pays the awarded worker the kill fee and the funder the rest', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedEscrow(ctx);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    const before = await balance(ctx.usdc, ctx.funder);
    const killFee = (ctx.amount * BigInt(KILL_FEE_BPS)) / 10_000n;

    await expect(escrow.connect(ctx.funder).refund())
      .to.emit(escrow, 'KillFeePaid')
      .withArgs(ctx.worker.address, killFee, ctx.funder.address);

    expect(await balance(ctx.usdc, ctx.worker)).to.equal(killFee);
    expect((await balance(ctx.usdc, ctx.funder)) - before).to.equal(ctx.amount - killFee);
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
  });
});

describe('CofferdamSpotEscrow — disputes', () => {
  it('cannot be raised before a worker is awarded', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedEscrow(ctx);
    const reason = ethers.id('conditions');
    await expect(escrow.connect(ctx.funder).raiseDispute(reason)).to.be.revertedWith('No worker awarded');
    await expect(escrow.connect(ctx.witness).raiseDispute(reason)).to.be.revertedWith('No worker awarded');
    // The funder keeps the ordinary exits.
    await (await escrow.connect(ctx.funder).refund()).wait();
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
  });

  it('lets the arbiter split between the awarded worker and the funder, emptying the escrow', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedEscrow(ctx);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witness).raiseDispute(ethers.id('left early'))).wait();
    const before = await balance(ctx.usdc, ctx.funder);
    const half = ctx.amount / 2n;

    await expect(escrow.connect(ctx.arbiter).resolveDispute(half))
      .to.emit(escrow, 'DisputeResolved')
      .withArgs(ctx.worker.address, half, ctx.funder.address, ctx.amount - half, ctx.arbiter.address);

    expect(await balance(ctx.usdc, ctx.worker)).to.equal(half);
    expect((await balance(ctx.usdc, ctx.funder)) - before).to.equal(ctx.amount - half);
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
  });

  it('pays the awarded worker in full when the arbiter stays silent past the window', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedEscrow(ctx);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.funder).raiseDispute(ethers.id('no show claim'))).wait();

    await expect(escrow.connect(ctx.stranger).claimAfterDisputeTimeout()).to.be.revertedWith('Dispute window still open');
    await time.increase(DISPUTE_WINDOW + 1);
    await (await escrow.connect(ctx.stranger).claimAfterDisputeTimeout()).wait();

    expect(await balance(ctx.usdc, ctx.worker)).to.equal(ctx.amount);
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
  });
});
