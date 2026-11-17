import { expect } from 'chai';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { Wallet } from 'ethers';
import { ethers, network } from 'hardhat';
import type { CofferdamHandleAnchor } from '../../typechain-types';

import { SAFE_V141 } from '../../scripts/lib/devKeyException';
import { HANDLE_ANCHOR_MAINNET, handleAnchorDomain, handleId, typesFor } from '../../scripts/lib/handleAnchor';
import { runAnchorSafeAction } from '../../scripts/lib/handleAnchorExec';

// CofferdamHandleAnchor (workspace decision 0086, rule 3) on a fork of Base
// mainnet that keeps chain id 8453: the constructor's pin of 0086's delays,
// the anchor owned by a real Safe v1.4.1 from its first block and driven
// through safe-exec.ts's anchor-* actions, and the gas of a claim and a read.
//
//   BASE_FORK=1 npx hardhat test test/fork/handle-anchor-fork.test.ts
//
// Nothing here reaches Base mainnet: the in-process network forks it locally.
// Every test skips unless the network is chain 8453.

const M = HANDLE_ANCHOR_MAINNET;
const key = (seed: string) => new Wallet(ethers.id(`cofferdam-handle-anchor-fork:${seed}`));
const compressed = (seed: string) => ethers.SigningKey.computePublicKey(key(seed).signingKey.publicKey, true);
const metaOf = (seed: string) => ethers.concat([compressed(`${seed}:spend`), compressed(`${seed}:view`)]);
const REGISTRAR = key('registrar');
const REGISTRAR_2 = key('registrar-2');
const OWNER = key('owner');
const OWNER_2 = key('owner-2');
const FAR = 2n ** 48n;

/** The promise rejects with a message matching `re`. */
async function rejects(p: Promise<unknown>, re: RegExp): Promise<void> {
  let message = '';
  try {
    await p;
  } catch (e) {
    message = (e as Error).message;
  }
  expect(message, 'expected a refusal').to.match(re);
}

const FACTORY_ABI = ['function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)'];
const SETUP_ABI = [
  'function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
];

describe('CofferdamHandleAnchor on a fork of Base mainnet (chain 8453)', function () {
  this.timeout(600_000);

  before(async function () {
    if ((await ethers.provider.getNetwork()).chainId !== 8453n) this.skip();
    await network.provider.send('hardhat_mine', ['0x1']);
  });

  async function createSafe(salt: string): Promise<string> {
    const [deployer] = await ethers.getSigners();
    const singleton = new ethers.Interface(SETUP_ABI);
    const init = singleton.encodeFunctionData('setup', [[deployer.address], 1, ethers.ZeroAddress, '0x', SAFE_V141.fallbackHandler, ethers.ZeroAddress, 0, ethers.ZeroAddress]);
    const factory = new ethers.Contract(SAFE_V141.proxyFactory, FACTORY_ABI, deployer);
    const saltNonce = BigInt(ethers.id(`cofferdam-handle-anchor-fork:${salt}`));
    const predicted: string = await factory.createProxyWithNonce.staticCall(SAFE_V141.singletonL2, init, saltNonce);
    await (await factory.createProxyWithNonce(SAFE_V141.singletonL2, init, saltNonce)).wait();
    return predicted;
  }

  it("refuses any delay but 0086's on chain 8453, and deploys with them", async function () {
    const [deployer] = await ethers.getSigners();
    const Anchor = await ethers.getContractFactory('CofferdamHandleAnchor');
    const ok = [M.changeDelay, M.freezeDuration, M.quarantine, M.safeDelay] as const;
    for (let i = 0; i < 4; i++) {
      const bad = [...ok] as bigint[];
      bad[i] = i === 2 ? M.quarantine + 1n : bad[i] - 1n;
      await expect(Anchor.deploy(deployer.address, bad[0], bad[1], bad[2], bad[3], [])).to.be.revertedWithCustomError(Anchor, 'MainnetDelayMismatch');
    }
    // Sepolia's short values are refused here.
    await expect(Anchor.deploy(deployer.address, 60, 120, 600, 0, [])).to.be.revertedWithCustomError(Anchor, 'MainnetDelayMismatch');
    const a = await Anchor.deploy(deployer.address, ...ok, []);
    expect(await a.CHANGE_DELAY()).to.equal(M.changeDelay);
    expect(await a.FREEZE_DURATION()).to.equal(M.freezeDuration);
    expect(await a.QUARANTINE()).to.equal(M.quarantine);
    expect(await a.SAFE_DELAY()).to.equal(M.safeDelay);
  });

  it('runs under a Safe v1.4.1 from its first block: every anchor-* action, and the gas of claim and read', async function () {
    const [deployer, relayer] = await ethers.getSigners();
    const safeAddress = await createSafe('one');
    const Anchor = await ethers.getContractFactory('CofferdamHandleAnchor');
    const anchor = (await Anchor.deploy(safeAddress, M.changeDelay, M.freezeDuration, M.quarantine, M.safeDelay, [REGISTRAR.address])) as unknown as CofferdamHandleAnchor;
    const deployReceipt = await anchor.deploymentTransaction()!.wait();
    const anchorAddress = await anchor.getAddress();
    expect(await anchor.owner()).to.equal(safeAddress);
    const domain = handleAnchorDomain(8453n, anchorAddress);
    const log = (line: string) => console.log(`      ${line}`);
    const run = (action: Parameters<typeof runAnchorSafeAction>[0]['action'], env: NodeJS.ProcessEnv, s = safeAddress) =>
      runAnchorSafeAction({ action, env, provider: ethers.provider, signer: deployer, safeAddress: s, anchorAddress, errorInterface: Anchor.interface, log });

    // Gas: a claim (first claim of a label, 66-byte meta-address) and the reads a payer makes.
    const id = handleId('ana');
    const meta = metaOf('owner');
    const rSig = await REGISTRAR.signTypedData(domain, typesFor('RegistrarClaim'), { handleId: id, owner: OWNER.address, serial: 1n, nonce: 0n, deadline: FAR });
    const oSig = await OWNER.signTypedData(domain, typesFor('OwnerClaim'), { handleId: id, metaAddress: meta, serial: 1n });
    const claimReceipt = await (await anchor.connect(relayer).claim(id, OWNER.address, meta, FAR, rSig, oSig)).wait();
    const resolveGas = await ethers.provider.estimateGas({ to: anchorAddress, data: anchor.interface.encodeFunctionData('resolve', [id]) });
    const metaGas = await ethers.provider.estimateGas({ to: anchorAddress, data: anchor.interface.encodeFunctionData('stealthMetaAddressOf', [id]) });
    const holdSig = await REGISTRAR.signTypedData(domain, typesFor('Hold'), { handleId: id, nonce: 1n, deadline: FAR });
    const holdReceipt = await (await anchor.connect(relayer).hold(id, FAR, holdSig)).wait();
    const block = await ethers.provider.getBlock('latest');
    log(`gas: deploy ${deployReceipt!.gasUsed}, claim ${claimReceipt!.gasUsed}, hold ${holdReceipt!.gasUsed}; ` +
      `resolve() ${resolveGas} and stealthMetaAddressOf() ${metaGas} as eth_call (21000 intrinsic included); base fee ${block!.baseFeePerGas} wei`);
    expect(claimReceipt!.gasUsed).to.be.lessThan(200_000n);

    // The Safe lifts the freeze at once.
    await run('anchor-lift-freeze', { HANDLE_LABEL: 'ana' });
    expect(await anchor.isFrozen(id)).to.equal(false);

    // A registrar added through the timelock.
    await run('anchor-registrar-schedule', { REGISTRAR: REGISTRAR_2.address });
    await rejects(run('anchor-registrar-add', { REGISTRAR: REGISTRAR_2.address }), /SafeOpNotReady/);
    await time.increase(M.safeDelay);
    await run('anchor-registrar-add', { REGISTRAR: REGISTRAR_2.address });
    expect(await anchor.isRegistrar(REGISTRAR_2.address)).to.equal(true);

    // A rekey to new keys after the timelock.
    const meta2 = metaOf('owner-2');
    await run('anchor-rekey-schedule', { HANDLE_ID: id, NEW_OWNER: OWNER_2.address, META_ADDRESS: meta2 });
    await time.increase(M.safeDelay);
    await run('anchor-rekey', { HANDLE_ID: id, NEW_OWNER: OWNER_2.address, META_ADDRESS: meta2 });
    expect((await anchor.resolve(id)).handleOwner).to.equal(OWNER_2.address);

    // A scheduled forceRelease withdrawn, then one carried out.
    await run('anchor-force-release-schedule', { HANDLE_ID: id, QUARANTINE: '1' });
    const opId = await anchor.forceReleaseOpId(id, true);
    await run('anchor-cancel-op', { SAFE_OP_ID: opId });
    await rejects(run('anchor-force-release', { HANDLE_ID: id }), /not scheduled/);
    await run('anchor-force-release-schedule', { HANDLE_ID: id, QUARANTINE: '0' });
    await time.increase(M.safeDelay);
    await run('anchor-force-release', { HANDLE_ID: id, QUARANTINE: '0' });
    expect(await anchor.claimableAt(id)).to.equal(0n);

    // A registrar removed at once.
    await run('anchor-registrar-remove', { REGISTRAR: REGISTRAR.address });
    expect(await anchor.isRegistrar(REGISTRAR.address)).to.equal(false);

    // Ownership handed to a second Safe in two steps, behind the timelock.
    const safe2 = await createSafe('two');
    await run('anchor-transfer-ownership', { NEW_SAFE: safe2 });
    await rejects(run('anchor-accept-ownership', {}), /pending owner/);
    await rejects(run('anchor-accept-ownership', {}, safe2), /SafeOpNotReady/);
    await time.increase(M.safeDelay);
    await run('anchor-accept-ownership', {}, safe2);
    expect(await anchor.owner()).to.equal(safe2);
    await rejects(run('anchor-registrar-remove', { REGISTRAR: REGISTRAR_2.address }), /not the Safe/);
  });
});
