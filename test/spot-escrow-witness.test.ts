import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

const USDC_ARTIFACT = 'contracts/test/MockUSDC.sol:USDC';

const CHECK_IN_TIMEOUT = 3600;
const CHECK_OUT_TIMEOUT = 86_400;
const DISPUTE_WINDOW = 172_800;
const KILL_FEE_BPS = 1000;

async function deployFixture() {
  const [deployer, funder, recruiter, witnessA, witnessB, worker, arbiter] =
    await ethers.getSigners();

  const Usdc = await ethers.getContractFactory(USDC_ARTIFACT);
  const usdc = (await Usdc.deploy('USD Coin', 'USDC')) as any;
  await usdc.waitForDeployment();

  const amount = ethers.parseUnits('5000', 6);
  await (await usdc.mint(funder.address, amount * 10n)).wait();

  return { deployer, funder, recruiter, witnessA, witnessB, worker, arbiter, usdc, amount };
}

async function deployEscrow(
  ctx: Awaited<ReturnType<typeof deployFixture>>,
  overrides: Partial<Record<string, unknown>> = {}
) {
  const policy = {
    funder: ctx.funder.address,
    recruiter: ctx.recruiter.address,
    workerNullifier: ethers.id('worker-nullifier-1'),
    checkInTimeout: CHECK_IN_TIMEOUT,
    checkOutTimeout: CHECK_OUT_TIMEOUT,
    witness: ctx.witnessA.address,
    arbiter: ctx.arbiter.address,
    killFeeBps: KILL_FEE_BPS,
    amount: ctx.amount,
    termsHash: ethers.ZeroHash,
    jobStartTime: 0,
    disputeWindow: DISPUTE_WINDOW,
    ...overrides,
  };

  const Escrow = await ethers.getContractFactory('CofferdamSpotEscrow');
  const escrow = (await Escrow.deploy(await ctx.usdc.getAddress(), policy)) as any;
  await escrow.waitForDeployment();
  return escrow;
}

async function fundEscrow(ctx: Awaited<ReturnType<typeof deployFixture>>, escrow: any) {
  await (await ctx.usdc.connect(ctx.funder).approve(await escrow.getAddress(), ctx.amount)).wait();
  await (await escrow.connect(ctx.funder).fund(ctx.amount)).wait();
}

describe('CofferdamSpotEscrow — witness integrity', () => {
  it('must not allow the awarded worker to be installed as the witness', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);

    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();

    // `worker` is still address(0) until check-in; the awarded worker lives in
    // `awardedWorker`. Guarding only against `worker` lets the recruiter install
    // the worker as their own witness, who then self-attests and drains the escrow.
    await expect(
      escrow.connect(ctx.recruiter).setWitness(ctx.worker.address)
    ).to.be.revertedWith('Witness cannot be worker');
  });

  it('the worker must never be able to self-attest and drain the escrow', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();

    // If the guard above is missing, this whole sequence succeeds and the
    // witness trust model is bypassed end to end.
    const installed = await escrow
      .connect(ctx.recruiter)
      .setWitness(ctx.worker.address)
      .then(() => true)
      .catch(() => false);

    expect(installed, 'worker was installed as witness').to.be.false;

    const balanceBefore = await ctx.usdc.balanceOf(ctx.worker.address);
    const selfCheckedIn = await escrow
      .connect(ctx.worker)
      .checkIn(ctx.worker.address)
      .then(() => true)
      .catch(() => false);
    expect(selfCheckedIn, 'worker self-checked-in').to.be.false;

    expect(await ctx.usdc.balanceOf(ctx.worker.address)).to.equal(balanceBefore);
  });

  it('must not allow the arbiter to become the witness', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);

    await expect(
      escrow.connect(ctx.recruiter).setWitness(ctx.arbiter.address)
    ).to.be.revertedWith('Witness cannot be arbiter');
  });
});

describe('CofferdamSpotEscrow — arbiter neutrality at construction', () => {
  it('rejects an escrow whose arbiter is the funder', async () => {
    const ctx = await deployFixture();
    await expect(
      deployEscrow(ctx, { arbiter: ctx.funder.address })
    ).to.be.revertedWith('Arbiter cannot be funder');
  });

  it('rejects an escrow whose arbiter is the recruiter', async () => {
    const ctx = await deployFixture();
    await expect(
      deployEscrow(ctx, { arbiter: ctx.recruiter.address })
    ).to.be.revertedWith('Arbiter cannot be recruiter');
  });

  it('rejects an escrow whose arbiter is the witness', async () => {
    const ctx = await deployFixture();
    await expect(
      deployEscrow(ctx, { arbiter: ctx.witnessA.address })
    ).to.be.revertedWith('Arbiter cannot be witness');
  });

  it('accepts a contract address as the arbiter (protocol arbitration pool)', async () => {
    const ctx = await deployFixture();
    // policy.arbiter must be able to point at a contract, not just an operator
    // EOA — that is what keeps a future juror-pool arbitrator a drop-in.
    const poolAddress = await ctx.usdc.getAddress();
    const escrow = await deployEscrow(ctx, { arbiter: poolAddress });
    expect((await escrow.policy()).arbiter).to.equal(poolAddress);
  });

  it('accepts the consumer self-witnessed shape (funder == recruiter == witness)', async () => {
    const ctx = await deployFixture();
    // Cofferdam's own Spot use case: one hirer holds every company-side role
    // and Cofferdam is the only neutral party available.
    const escrow = await deployEscrow(ctx, {
      recruiter: ctx.funder.address,
      witness: ctx.funder.address,
      arbiter: ctx.arbiter.address,
    });
    const policy = await escrow.policy();
    expect(policy.funder).to.equal(ctx.funder.address);
    expect(policy.witness).to.equal(ctx.funder.address);
    expect(policy.arbiter).to.equal(ctx.arbiter.address);
  });
});

describe('CofferdamSpotEscrow — mid-job witness rotation', () => {
  it('allows the recruiter to rotate the witness while the job is Active', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkIn(ctx.worker.address)).wait();

    await expect(escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address))
      .to.emit(escrow, 'WitnessReplaced')
      .withArgs(ctx.witnessA.address, ctx.witnessB.address, ctx.recruiter.address);

    expect(await escrow.witnessHistoryCount()).to.equal(2);
  });

  it('lets the replacement witness check out a worker checked in by the previous witness', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkIn(ctx.worker.address)).wait();

    await (await escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address)).wait();

    // The outgoing witness loses authority immediately.
    await expect(escrow.connect(ctx.witnessA).checkOut()).to.be.revertedWith('Only witness');

    await (await escrow.connect(ctx.witnessB).checkOut()).wait();
    expect(await ctx.usdc.balanceOf(ctx.worker.address)).to.equal(ctx.amount);
  });

  it('does not disturb the checkout timeout when the witness rotates', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkIn(ctx.worker.address)).wait();

    const checkedInAt = await escrow.checkedInAt();
    await time.increase(CHECK_OUT_TIMEOUT / 2);
    await (await escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address)).wait();

    // Rotation must not reset the worker's Rule D protection.
    expect(await escrow.checkedInAt()).to.equal(checkedInAt);

    await time.increase(CHECK_OUT_TIMEOUT / 2 + 1);
    await (await escrow.connect(ctx.worker).claimAfterCheckoutTimeout()).wait();
    expect(await ctx.usdc.balanceOf(ctx.worker.address)).to.equal(ctx.amount);
  });
});

describe('CofferdamSpotEscrow — selfWitnessed (consumer hirer-as-witness)', () => {
  // Consumer shape: one hirer funds, drafts and attests. hirerB is a stand-in
  // (partner, neighbour, building manager) covering while the hirer is away.
  async function deployConsumer(ctx: Awaited<ReturnType<typeof deployFixture>>) {
    return deployEscrow(ctx, {
      recruiter: ctx.funder.address,
      witness: ctx.funder.address,
    });
  }

  it('flags a consumer escrow as selfWitnessed and a B2B escrow as not', async () => {
    const ctx = await deployFixture();
    expect(await (await deployConsumer(ctx)).selfWitnessed()).to.be.true;
    expect(await (await deployEscrow(ctx)).selfWitnessed()).to.be.false;
  });

  it('lets the hirer hand witness duty to a stand-in and then take it back', async () => {
    const ctx = await deployFixture();
    const escrow = await deployConsumer(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.funder).awardWorker(ctx.worker.address)).wait();

    // Hirer is away — hand off to the stand-in.
    await (await escrow.connect(ctx.funder).setWitness(ctx.witnessB.address)).wait();
    await (await escrow.connect(ctx.witnessB).checkIn(ctx.worker.address)).wait();

    // Hirer returns mid-job and resumes their own witness duty.
    await expect(escrow.connect(ctx.funder).setWitness(ctx.funder.address))
      .to.emit(escrow, 'WitnessReplaced')
      .withArgs(ctx.witnessB.address, ctx.funder.address, ctx.funder.address);

    await (await escrow.connect(ctx.funder).checkOut()).wait();
    expect(await ctx.usdc.balanceOf(ctx.worker.address)).to.equal(ctx.amount);
  });

  it('still forbids a B2B funder from taking over attestation mid-job', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);

    // Finance holds the money and must never also certify the work.
    await expect(
      escrow.connect(ctx.recruiter).setWitness(ctx.funder.address)
    ).to.be.revertedWith('Witness cannot be funder');
  });

  it('does not let a self-witnessed hirer become their own worker', async () => {
    const ctx = await deployFixture();
    const escrow = await deployConsumer(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.funder).awardWorker(ctx.worker.address)).wait();

    // The selfWitnessed relaxation must not widen the drain hole.
    await expect(
      escrow.connect(ctx.funder).setWitness(ctx.worker.address)
    ).to.be.revertedWith('Witness cannot be worker');
  });
});

describe('CofferdamSpotEscrow — setWitness state gating', () => {
  it('rejects a witness change after the escrow has been released', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkIn(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkOut()).wait();

    // Appending to witnessHistory after settlement falsifies the audit trail.
    await expect(
      escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address)
    ).to.be.revertedWith('Wrong state');

    expect(await escrow.witnessHistoryCount()).to.equal(1);
  });

  it('rejects a witness change while a dispute is being adjudicated', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);
    await fundEscrow(ctx, escrow);
    await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witnessA).checkIn(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.worker).raiseDispute(ethers.id('underpaid'))).wait();

    // raiseDispute() counts policy.witness as a party, so swapping mid-dispute
    // silently changes who has standing.
    await expect(
      escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address)
    ).to.be.revertedWith('Wrong state');
  });

  it('still allows a witness change before funding', async () => {
    const ctx = await deployFixture();
    const escrow = await deployEscrow(ctx);

    await expect(escrow.connect(ctx.recruiter).setWitness(ctx.witnessB.address))
      .to.emit(escrow, 'WitnessReplaced')
      .withArgs(ctx.witnessA.address, ctx.witnessB.address, ctx.recruiter.address);
  });
});
