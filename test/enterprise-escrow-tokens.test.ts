import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

/**
 * Flexible-currency escrows (workspace decision 0100, question 7, ruled
 * 2026-11-26): each escrow's token is fixed at creation and immutable, and the
 * EscrowFactory creates escrows only in tokens on its owner's allowlist.
 * Amounts are in the token's base units, so the same escrow runs USDC (6
 * decimals), mainnet BRS (6) and Pods' pBRL on Base Sepolia (18).
 *
 * Deploys enterprise contracts, so CI skips it (`enterprise-*`); run on the Mac.
 */

const USDC_ARTIFACT = 'contracts/test/MockUSDC.sol:USDC';
const TOKEN_ARTIFACT = 'contracts/test/MockToken.sol:MockToken';
const FEE_TOKEN_ARTIFACT = 'contracts/test/MockToken.sol:MockFeeToken';

const CHECK_IN_TIMEOUT = 3600;
const CHECK_OUT_TIMEOUT = 86_400;
const DISPUTE_WINDOW = 172_800;
const KILL_FEE_BPS = 1000;
const DAY = 86_400;

async function deployFixture() {
  const [owner, funder, recruiter, witness, worker, arbiter, stranger] = await ethers.getSigners();
  const usdc = (await (await ethers.getContractFactory(USDC_ARTIFACT)).deploy('USD Coin', 'USDC')) as any;
  const pbrl = (await (await ethers.getContractFactory(TOKEN_ARTIFACT)).deploy('pods BRL Testnet', 'pBRL', 18)) as any;
  const other = (await (await ethers.getContractFactory(TOKEN_ARTIFACT)).deploy('Not Allowed', 'NOPE', 6)) as any;
  const Factory = await ethers.getContractFactory('EscrowFactory');
  const factory = (await Factory.deploy([await usdc.getAddress(), await pbrl.getAddress()])) as any;
  await factory.waitForDeployment();
  await (await usdc.mint(funder.address, ethers.parseUnits('1000000', 6))).wait();
  await (await pbrl.mint(funder.address, ethers.parseUnits('1000000', 18))).wait();
  await (await other.mint(funder.address, ethers.parseUnits('1000000', 6))).wait();
  return { owner, funder, recruiter, witness, worker, arbiter, stranger, usdc, pbrl, other, factory };
}

type Ctx = Awaited<ReturnType<typeof deployFixture>>;

function spotPolicy(ctx: Ctx, amount: bigint, overrides: Record<string, unknown> = {}) {
  return {
    funder: ctx.funder.address,
    recruiter: ctx.recruiter.address,
    workerNullifier: ethers.ZeroHash,
    checkInTimeout: CHECK_IN_TIMEOUT,
    checkOutTimeout: CHECK_OUT_TIMEOUT,
    witness: ctx.witness.address,
    arbiter: ctx.arbiter.address,
    killFeeBps: KILL_FEE_BPS,
    amount,
    termsHash: ethers.ZeroHash,
    jobStartTime: 0,
    disputeWindow: DISPUTE_WINDOW,
    ...overrides,
  };
}

let saltCounter = 0;
async function createSpot(ctx: Ctx, token: any, amount: bigint, overrides: Record<string, unknown> = {}) {
  const policy = spotPolicy(ctx, amount, overrides);
  const salt = ethers.id(`spot-${saltCounter++}`);
  const tokenAddr = await token.getAddress();
  const predicted = await ctx.factory.predictSpotEscrowAddress(tokenAddr, policy, salt);
  await expect(ctx.factory.createSpotEscrow(tokenAddr, policy, salt))
    .to.emit(ctx.factory, 'SpotEscrowCreated')
    .withArgs(predicted, policy.funder, policy.recruiter, tokenAddr, policy.workerNullifier, policy.witness);
  return (await ethers.getContractAt('CofferdamSpotEscrow', predicted)) as any;
}

async function fundAndAward(ctx: Ctx, token: any, escrow: any, amount: bigint) {
  await (await token.connect(ctx.funder).approve(await escrow.getAddress(), amount)).wait();
  await (await escrow.connect(ctx.funder).fund(amount)).wait();
  await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
}

const bal = (token: any, who: string) => token.balanceOf(who) as Promise<bigint>;

describe('EscrowFactory — token allowlist', () => {
  it('allows the constructor tokens and emits each one with its decimals', async () => {
    const ctx = await deployFixture();
    const usdcAddr = await ctx.usdc.getAddress();
    const pbrlAddr = await ctx.pbrl.getAddress();
    expect(await ctx.factory.allowedTokens(usdcAddr)).to.equal(true);
    expect(await ctx.factory.allowedTokens(pbrlAddr)).to.equal(true);
    expect(await ctx.factory.allowedTokens(await ctx.other.getAddress())).to.equal(false);
    const receipt = await ctx.factory.deploymentTransaction()!.wait();
    const allowed = receipt!.logs
      .map((l: any) => { try { return ctx.factory.interface.parseLog(l); } catch { return null; } })
      .filter((p: any) => p?.name === 'TokenAllowed')
      .map((p: any) => [p.args.token, Number(p.args.decimals)]);
    expect(allowed).to.deep.equal([[usdcAddr, 6], [pbrlAddr, 18]]);
  });

  it('refuses a spot or payroll escrow in a token not on the allowlist', async () => {
    const ctx = await deployFixture();
    const otherAddr = await ctx.other.getAddress();
    await expect(
      ctx.factory.createSpotEscrow(otherAddr, spotPolicy(ctx, 1_000_000n), ethers.id('x')),
    ).to.be.revertedWith('Token not allowed');
    const now = await time.latest();
    const payroll = {
      worker: ctx.worker.address, workerRole: ethers.id('Deckhand'), managerRole: ethers.ZeroHash,
      payPeriodStart: now, payPeriodEnd: now + 30 * DAY, releaseDelay: DAY, disputeWindow: 3 * DAY,
      managerApproval: false,
    };
    await expect(
      ctx.factory.createPayrollEscrow(otherAddr, ctx.funder.address, ethers.id('root'), payroll, ethers.id('p')),
    ).to.be.revertedWith('Token not allowed');
    await expect(
      ctx.factory.createSpotEscrow(ethers.ZeroAddress, spotPolicy(ctx, 1_000_000n), ethers.id('x')),
    ).to.be.revertedWith('Token not allowed');
  });

  it('lets only the owner change the allowlist, and only to ERC-20 contracts', async () => {
    const ctx = await deployFixture();
    const otherAddr = await ctx.other.getAddress();
    await expect(ctx.factory.connect(ctx.stranger).allowToken(otherAddr)).to.be.revertedWith('Only owner');
    await expect(ctx.factory.connect(ctx.stranger).disallowToken(await ctx.usdc.getAddress())).to.be.revertedWith('Only owner');
    await expect(ctx.factory.allowToken(ctx.stranger.address)).to.be.revertedWith('Token has no code');
    await expect(ctx.factory.allowToken(await ctx.usdc.getAddress())).to.be.revertedWith('Token already allowed');
    await expect(ctx.factory.disallowToken(otherAddr)).to.be.revertedWith('Token not allowed');
    // A contract without decimals() is no token.
    await expect(ctx.factory.allowToken(await ctx.factory.getAddress())).to.be.reverted;

    await expect(ctx.factory.allowToken(otherAddr))
      .to.emit(ctx.factory, 'TokenAllowed').withArgs(otherAddr, 6, ctx.owner.address);
    await createSpot(ctx, ctx.other, 1_000_000n);
  });

  it('follows ownership: the new owner changes the allowlist, the old one cannot', async () => {
    const ctx = await deployFixture();
    await expect(ctx.factory.transferOwnership(ctx.stranger.address))
      .to.emit(ctx.factory, 'OwnershipTransferred').withArgs(ctx.owner.address, ctx.stranger.address);
    await expect(ctx.factory.allowToken(await ctx.other.getAddress())).to.be.revertedWith('Only owner');
    await ctx.factory.connect(ctx.stranger).allowToken(await ctx.other.getAddress());
  });

  it('disallowing a token stops new escrows in it; an escrow already created still settles', async () => {
    const ctx = await deployFixture();
    const amount = ethers.parseUnits('200', 18);
    const escrow = await createSpot(ctx, ctx.pbrl, amount);
    await expect(ctx.factory.disallowToken(await ctx.pbrl.getAddress()))
      .to.emit(ctx.factory, 'TokenDisallowed').withArgs(await ctx.pbrl.getAddress(), ctx.owner.address);
    await expect(
      ctx.factory.createSpotEscrow(await ctx.pbrl.getAddress(), spotPolicy(ctx, amount), ethers.id('after')),
    ).to.be.revertedWith('Token not allowed');

    await fundAndAward(ctx, ctx.pbrl, escrow, amount);
    await (await escrow.connect(ctx.witness).checkIn(ctx.worker.address)).wait();
    await (await escrow.connect(ctx.witness).checkOut()).wait();
    expect(await bal(ctx.pbrl, ctx.worker.address)).to.equal(amount);
  });

  it('only authorized callers create escrows, whatever the token', async () => {
    const ctx = await deployFixture();
    await expect(
      ctx.factory.connect(ctx.stranger).createSpotEscrow(await ctx.usdc.getAddress(), spotPolicy(ctx, 1n), ethers.id('s')),
    ).to.be.revertedWith('Not authorized');
  });
});

for (const [label, key, decimals, whole] of [
  ['USDC, 6 decimals', 'usdc', 6, '5000'],
  ['pBRL, 18 decimals', 'pbrl', 18, '200'],
] as const) {
  describe(`CofferdamSpotEscrow from the factory — ${label}`, () => {
    const amountOf = () => ethers.parseUnits(whole, decimals);

    it('holds the token it was created in, and the check-out pays the worker the whole amount', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      expect(await escrow.token()).to.equal(await token.getAddress());
      await fundAndAward(ctx, token, escrow, amount);
      expect(await bal(token, await escrow.getAddress())).to.equal(amount);
      await (await escrow.connect(ctx.witness).checkIn(ctx.worker.address)).wait();
      await expect(escrow.connect(ctx.witness).checkOut())
        .to.emit(escrow, 'EscrowReleased').withArgs(0, await token.getAddress(), amount, ctx.worker.address);
      expect(await bal(token, ctx.worker.address)).to.equal(amount);
      expect(await bal(token, await escrow.getAddress())).to.equal(0n);
    });

    it('pays the kill fee in the token at the agreed basis points, the rest to the funder', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      await fundAndAward(ctx, token, escrow, amount);
      const before = await bal(token, ctx.funder.address);
      await (await escrow.connect(ctx.funder).refund()).wait();
      const killFee = (amount * BigInt(KILL_FEE_BPS)) / 10_000n;
      expect(killFee).to.equal(ethers.parseUnits(whole, decimals) / 10n);
      expect(await bal(token, ctx.worker.address)).to.equal(killFee);
      expect((await bal(token, ctx.funder.address)) - before).to.equal(amount - killFee);
      expect(await bal(token, await escrow.getAddress())).to.equal(0n);
    });

    it('splits a dispute in the token, leaving nothing behind', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      await fundAndAward(ctx, token, escrow, amount);
      await (await escrow.connect(ctx.witness).checkIn(ctx.worker.address)).wait();
      await (await escrow.connect(ctx.worker).raiseDispute(ethers.id('hours'))).wait();
      const third = amount / 3n;
      const before = await bal(token, ctx.funder.address);
      await (await escrow.connect(ctx.arbiter).resolveDispute(third)).wait();
      expect(await bal(token, ctx.worker.address)).to.equal(third);
      expect((await bal(token, ctx.funder.address)) - before).to.equal(amount - third);
      expect(await bal(token, await escrow.getAddress())).to.equal(0n);
    });

    it('names the token in every event that moves an amount (the founder, 2026-11-26)', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const tokenAddr = await token.getAddress();
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      await (await token.connect(ctx.funder).approve(await escrow.getAddress(), amount)).wait();
      await expect(escrow.connect(ctx.funder).fund(amount))
        .to.emit(escrow, 'EscrowFunded').withArgs(0, tokenAddr, amount, ctx.funder.address);
      await (await escrow.connect(ctx.recruiter).awardWorker(ctx.worker.address)).wait();
      const killFee = (amount * BigInt(KILL_FEE_BPS)) / 10_000n;
      await expect(escrow.connect(ctx.funder).refund())
        .to.emit(escrow, 'KillFeePaid').withArgs(ctx.worker.address, tokenAddr, killFee, ctx.funder.address)
        .and.to.emit(escrow, 'EscrowRefunded').withArgs(0, tokenAddr, amount - killFee, ctx.funder.address);

      const disputed = await createSpot(ctx, token, amount);
      await fundAndAward(ctx, token, disputed, amount);
      await (await disputed.connect(ctx.worker).raiseDispute(ethers.id('late'))).wait();
      await expect(disputed.connect(ctx.arbiter).resolveDispute(amount / 2n))
        .to.emit(disputed, 'DisputeResolved')
        .withArgs(ctx.worker.address, tokenAddr, amount / 2n, ctx.funder.address, amount - amount / 2n, ctx.arbiter.address);
    });

    it('refuses an amount other than the agreed one, in base units', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      await (await token.connect(ctx.funder).approve(await escrow.getAddress(), amount + 1n)).wait();
      await expect(escrow.connect(ctx.funder).fund(amount + 1n)).to.be.revertedWith('Amount != agreed');
    });

    it('lets the worker claim after the check-out timeout, in the token', async () => {
      const ctx = await deployFixture();
      const token = ctx[key];
      const amount = amountOf();
      const escrow = await createSpot(ctx, token, amount);
      await fundAndAward(ctx, token, escrow, amount);
      await (await escrow.connect(ctx.witness).checkIn(ctx.worker.address)).wait();
      await time.increase(CHECK_OUT_TIMEOUT + 1);
      await (await escrow.connect(ctx.stranger).claimAfterCheckoutTimeout()).wait();
      expect(await bal(token, ctx.worker.address)).to.equal(amount);
    });
  });
}

describe('CofferdamPayrollEscrow from the factory — 18 decimals', () => {
  it('holds pBRL and pays the named worker the period at release', async () => {
    const ctx = await deployFixture();
    const amount = ethers.parseUnits('3500.25', 18);
    const now = await time.latest();
    const role = ethers.id('Deckhand');
    const abi = ethers.AbiCoder.defaultAbiCoder();
    // A one-leaf org tree: the root is the worker's own leaf, the proof empty.
    const root = ethers.keccak256(abi.encode(['address', 'bytes32'], [ctx.worker.address, role]));
    const policy = {
      worker: ctx.worker.address, workerRole: role, managerRole: ethers.ZeroHash,
      payPeriodStart: now, payPeriodEnd: now + 30 * DAY, releaseDelay: DAY, disputeWindow: 3 * DAY,
      managerApproval: false,
    };
    const pbrlAddr = await ctx.pbrl.getAddress();
    const tx = await ctx.factory.createPayrollEscrow(pbrlAddr, ctx.funder.address, root, policy, ethers.id('p'));
    const receipt = await tx.wait();
    const created = receipt!.logs
      .map((l: any) => { try { return ctx.factory.interface.parseLog(l); } catch { return null; } })
      .find((p: any) => p?.name === 'PayrollEscrowCreated');
    expect(created!.args.token).to.equal(pbrlAddr);
    const escrow = (await ethers.getContractAt('CofferdamPayrollEscrow', created!.args.escrow)) as any;
    expect(await escrow.token()).to.equal(pbrlAddr);

    await (await ctx.pbrl.connect(ctx.funder).approve(await escrow.getAddress(), amount)).wait();
    await expect(escrow.connect(ctx.funder).fund(amount))
      .to.emit(escrow, 'EscrowFunded').withArgs(0, pbrlAddr, amount, ctx.funder.address);
    await time.increase(31 * DAY + 1);
    await expect(escrow.connect(ctx.stranger).claim([]))
      .to.emit(escrow, 'EscrowReleased').withArgs(0, pbrlAddr, amount, ctx.worker.address);
    expect(await bal(ctx.pbrl, ctx.worker.address)).to.equal(amount);
  });
});

describe('Escrows refuse a token that takes a fee on transfer', () => {
  it('a spot escrow made outside the factory in a fee token cannot be funded', async () => {
    const ctx = await deployFixture();
    const fee = (await (await ethers.getContractFactory(FEE_TOKEN_ARTIFACT)).deploy()) as any;
    await (await fee.mint(ctx.funder.address, 1_000_000n)).wait();
    const Escrow = await ethers.getContractFactory('CofferdamSpotEscrow');
    const escrow = (await Escrow.deploy(await fee.getAddress(), spotPolicy(ctx, 0n))) as any;
    await (await fee.connect(ctx.funder).approve(await escrow.getAddress(), 1_000_000n)).wait();
    await expect(escrow.connect(ctx.funder).fund(1_000_000n)).to.be.revertedWith('Token took a fee');
  });

  it('the escrows refuse the zero token', async () => {
    const ctx = await deployFixture();
    const Escrow = await ethers.getContractFactory('CofferdamSpotEscrow');
    await expect(Escrow.deploy(ethers.ZeroAddress, spotPolicy(ctx, 0n))).to.be.revertedWith('Token required');
  });
});

describe('Code hashes per token (decision 0016 grants)', () => {
  it('a spot escrow\'s runtime code hash is fixed per token and selfWitnessed flag', async () => {
    const ctx = await deployFixture();
    const hash = async (escrow: any) => ethers.keccak256(await ethers.provider.getCode(await escrow.getAddress()));
    const usdcA = await createSpot(ctx, ctx.usdc, 1_000_000n);
    const usdcB = await createSpot(ctx, ctx.usdc, 7_000_000n, { checkInTimeout: 99 });
    const pbrlA = await createSpot(ctx, ctx.pbrl, ethers.parseUnits('1', 18));
    const usdcSelf = await createSpot(ctx, ctx.usdc, 1_000_000n, { witness: ctx.funder.address });
    // Same token and flag: one hash, whatever the policy (a grant names it once).
    expect(await hash(usdcA)).to.equal(await hash(usdcB));
    // Another token or the consumer shape: another hash (a grant must list each).
    expect(await hash(pbrlA)).to.not.equal(await hash(usdcA));
    expect(await hash(usdcSelf)).to.not.equal(await hash(usdcA));
  });

  it('the predicted address depends on the token', async () => {
    const ctx = await deployFixture();
    const policy = spotPolicy(ctx, 1n);
    const salt = ethers.id('same');
    expect(await ctx.factory.predictSpotEscrowAddress(await ctx.usdc.getAddress(), policy, salt))
      .to.not.equal(await ctx.factory.predictSpotEscrowAddress(await ctx.pbrl.getAddress(), policy, salt));
  });
});
