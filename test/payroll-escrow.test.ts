import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

/**
 * CofferdamPayrollEscrow access control (2026-10-15): the policy names the
 * worker, a manager approves with the proof of their own org-tree leaf, the
 * claim pays the named worker only, disputes come from the funder or the
 * worker, and only the funder refunds.
 */

const USDC_ARTIFACT = 'contracts/test/MockUSDC.sol:USDC';
const DAY = 86_400;

const abi = ethers.AbiCoder.defaultAbiCoder();
const leafOf = (account: string, role: string) => ethers.keccak256(abi.encode(['address', 'bytes32'], [account, role]));
const pair = (a: string, b: string) => ethers.keccak256(ethers.solidityPacked(['bytes32', 'bytes32'], a < b ? [a, b] : [b, a]));

/** The org tree as enterprise-cli/lib/merkle.ts builds it: sorted pairs, odd layers duplicate the last node. */
function buildTree(leaves: string[]) {
  const layers: string[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) next.push(pair(current[i], current[i + 1] ?? current[i]));
    layers.push(next);
    current = next;
  }
  return { root: current[0], layers };
}
function proofFor(tree: ReturnType<typeof buildTree>, leaf: string): string[] {
  let index = tree.layers[0].indexOf(leaf);
  if (index < 0) throw new Error('leaf not in tree');
  const proof: string[] = [];
  for (let i = 0; i < tree.layers.length - 1; i++) {
    const layer = tree.layers[i];
    const sibling = index % 2 === 0 ? index + 1 : index - 1;
    proof.push(sibling < layer.length ? layer[sibling] : layer[index]);
    index = Math.floor(index / 2);
  }
  return proof;
}

const DECKHAND = ethers.id('Deckhand');
const MANAGER = ethers.id('Manager');
const FINANCE = ethers.id('Finance');

async function deployFixture() {
  const [deployer, funder, worker, manager, peer, stranger] = await ethers.getSigners();
  const Usdc = await ethers.getContractFactory(USDC_ARTIFACT);
  const usdc = (await Usdc.deploy('USD Coin', 'USDC')) as any;
  await usdc.waitForDeployment();
  const amount = ethers.parseUnits('4200', 6);
  await (await usdc.mint(funder.address, amount * 10n)).wait();

  const leaves = {
    worker: leafOf(worker.address, DECKHAND),
    manager: leafOf(manager.address, MANAGER),
    peer: leafOf(peer.address, DECKHAND), // another employee with the worker's role
    funder: leafOf(funder.address, FINANCE),
  };
  const tree = buildTree([leaves.worker, leaves.manager, leaves.peer, leaves.funder]);
  const proof = (who: keyof typeof leaves) => proofFor(tree, leaves[who]);
  const now = await time.latest();
  return { deployer, funder, worker, manager, peer, stranger, usdc, amount, tree, proof, now };
}

type Ctx = Awaited<ReturnType<typeof deployFixture>>;

function policyOf(ctx: Ctx, overrides: Record<string, unknown> = {}) {
  return {
    worker: ctx.worker.address,
    workerRole: DECKHAND,
    managerRole: MANAGER,
    payPeriodStart: ctx.now,
    payPeriodEnd: ctx.now + 30 * DAY,
    releaseDelay: DAY,
    disputeWindow: 3 * DAY,
    managerApproval: true,
    ...overrides,
  };
}

async function deployPayroll(ctx: Ctx, overrides: Record<string, unknown> = {}, root = ctx.tree.root) {
  const Escrow = await ethers.getContractFactory('CofferdamPayrollEscrow');
  const escrow = (await Escrow.deploy(await ctx.usdc.getAddress(), ctx.funder.address, root, policyOf(ctx, overrides))) as any;
  await escrow.waitForDeployment();
  return escrow;
}

async function fundedPayroll(ctx: Ctx, overrides: Record<string, unknown> = {}) {
  const escrow = await deployPayroll(ctx, overrides);
  await (await ctx.usdc.connect(ctx.funder).approve(await escrow.getAddress(), ctx.amount)).wait();
  await (await escrow.connect(ctx.funder).fund(ctx.amount)).wait();
  return escrow;
}

const RELEASE = 31 * DAY + 1; // past payPeriodEnd + releaseDelay
const balance = (usdc: any, address: string) => usdc.balanceOf(address) as Promise<bigint>;

describe('CofferdamPayrollEscrow — policy and funding', () => {
  it('refuses a policy without a worker, a worker who is the funder, or approval without a manager role', async () => {
    const ctx = await deployFixture();
    await expect(deployPayroll(ctx, { worker: ethers.ZeroAddress })).to.be.revertedWith('Worker cannot be zero');
    await expect(deployPayroll(ctx, { worker: ctx.funder.address })).to.be.revertedWith('Worker cannot be funder');
    await expect(deployPayroll(ctx, { managerRole: ethers.ZeroHash })).to.be.revertedWith('Manager role required');
    await expect(deployPayroll(ctx, {}, ethers.ZeroHash)).to.be.revertedWith('Org root required');
  });

  it('is funded by the funder only', async () => {
    const ctx = await deployFixture();
    const escrow = await deployPayroll(ctx);
    await expect(escrow.connect(ctx.stranger).fund(ctx.amount)).to.be.revertedWith('Only funder');
    await (await ctx.usdc.connect(ctx.funder).approve(await escrow.getAddress(), ctx.amount)).wait();
    await (await escrow.connect(ctx.funder).fund(ctx.amount)).wait();
    expect(await escrow.state()).to.equal(1n); // Funded
  });
});

describe('CofferdamPayrollEscrow — manager approval', () => {
  it('needs the proof of a manager leaf from the approver, and never the worker', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx);
    await expect(escrow.connect(ctx.stranger).managerApprove([])).to.be.revertedWith('Not a manager in org tree');
    await expect(escrow.connect(ctx.peer).managerApprove(ctx.proof('peer'))).to.be.revertedWith('Not a manager in org tree');
    await expect(escrow.connect(ctx.worker).managerApprove(ctx.proof('worker'))).to.be.revertedWith('Worker cannot approve own pay');
    // A manager presenting someone else's proof fails too: the leaf is built from msg.sender.
    await expect(escrow.connect(ctx.manager).managerApprove(ctx.proof('worker'))).to.be.revertedWith('Not a manager in org tree');

    await (await escrow.connect(ctx.manager).managerApprove(ctx.proof('manager'))).wait();
    expect(await escrow.state()).to.equal(3n); // Pending
    expect(await escrow.approvedBy()).to.equal(ctx.manager.address);
  });

  it('is refused when the policy requires no approval', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx, { managerApproval: false, managerRole: ethers.ZeroHash });
    await expect(escrow.connect(ctx.manager).managerApprove(ctx.proof('manager'))).to.be.revertedWith('No manager approval in policy');
  });
});

describe('CofferdamPayrollEscrow — claim', () => {
  it('pays the worker named in the policy, after approval and the release delay, and nobody else', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx);
    await expect(escrow.connect(ctx.worker).claim(ctx.proof('worker'))).to.be.revertedWith('Manager approval required');
    await (await escrow.connect(ctx.manager).managerApprove(ctx.proof('manager'))).wait();
    await expect(escrow.connect(ctx.worker).claim(ctx.proof('worker'))).to.be.revertedWith('Release not yet');

    await time.increase(RELEASE);
    // Another employee with the same role cannot redirect the pay: the leaf is the named worker's.
    await expect(escrow.connect(ctx.peer).claim(ctx.proof('peer'))).to.be.revertedWith('Not in org tree');
    // Anyone may trigger the release; it still pays the named worker.
    await (await escrow.connect(ctx.stranger).claim(ctx.proof('worker'))).wait();
    expect(await balance(ctx.usdc, ctx.worker.address)).to.equal(ctx.amount);
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
    expect(await escrow.state()).to.equal(4n); // Released
  });

  it('releases straight from Funded when the policy needs no approval', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx, { managerApproval: false, managerRole: ethers.ZeroHash });
    await time.increase(RELEASE);
    await (await escrow.connect(ctx.worker).claim(ctx.proof('worker'))).wait();
    expect(await balance(ctx.usdc, ctx.worker.address)).to.equal(ctx.amount);
  });

  it('keeps the funds when the named worker is not in the org tree, so the funder can dispute and refund', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx, { worker: ctx.stranger.address });
    await (await escrow.connect(ctx.manager).managerApprove(ctx.proof('manager'))).wait();
    await time.increase(RELEASE);
    await expect(escrow.connect(ctx.stranger).claim(ctx.proof('worker'))).to.be.revertedWith('Not in org tree');
    await (await escrow.connect(ctx.funder).dispute(ethers.id('not an employee'))).wait();
    await (await escrow.connect(ctx.funder).refund()).wait();
    expect(await balance(ctx.usdc, await escrow.getAddress())).to.equal(0n);
  });
});

describe('CofferdamPayrollEscrow — dispute and refund', () => {
  it('lets only the funder or the worker dispute, inside the window', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx);
    await expect(escrow.connect(ctx.stranger).dispute(ethers.id('x'))).to.be.revertedWith('Not a party');
    await expect(escrow.connect(ctx.manager).dispute(ethers.id('x'))).to.be.revertedWith('Not a party');
    await (await escrow.connect(ctx.worker).dispute(ethers.id('short pay'))).wait();
    expect(await escrow.state()).to.equal(5n); // Disputed

    const late = await fundedPayroll(ctx);
    await time.increase(RELEASE + 3 * DAY);
    await expect(late.connect(ctx.funder).dispute(ethers.id('too late'))).to.be.revertedWith('Dispute window passed');
  });

  it('refunds a disputed period to the funder, on the funder\'s call only', async () => {
    const ctx = await deployFixture();
    const escrow = await fundedPayroll(ctx);
    await (await escrow.connect(ctx.manager).managerApprove(ctx.proof('manager'))).wait();
    await (await escrow.connect(ctx.funder).dispute(ethers.id('period voided'))).wait();
    await expect(escrow.connect(ctx.stranger).refund()).to.be.revertedWith('Only funder');
    await expect(escrow.connect(ctx.worker).refund()).to.be.revertedWith('Only funder');
    const before = await balance(ctx.usdc, ctx.funder.address);
    await (await escrow.connect(ctx.funder).refund()).wait();
    expect((await balance(ctx.usdc, ctx.funder.address)) - before).to.equal(ctx.amount);
    expect(await escrow.state()).to.equal(7n); // Refunded
  });
});
