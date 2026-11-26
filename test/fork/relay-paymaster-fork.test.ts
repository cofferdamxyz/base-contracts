import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ethers, network } from 'hardhat';
import type { Signer } from 'ethers';

import { SAFE_V141 } from '../../scripts/lib/devKeyException';
import { HANDLE_ANCHOR_MAINNET } from '../../scripts/lib/handleAnchor';
import { accountCodeFingerprint } from '../../scripts/lib/paymaster';
import { productionOwnerRefusal } from '../../scripts/lib/productionSafe';
import { readSafeFacts } from '../../scripts/lib/safeFacts';
import {
  BatchFile,
  ProposeAction,
  SAFE_TX_TYPES,
  SafeProposal,
  actionTarget,
  buildSafeCall,
  packSafeSignatures,
  runReadback,
  safeCallTx,
  safeProposeRefusal,
  safeTxDomain,
  safeTxHash,
  safeTxHashParts,
  txBuilderChecksum,
  txBuilderFile,
} from '../../scripts/lib/safeProposal';
import { NO_PERMISSION, packSig, webauthnKey } from '../helpers/keys';

// The production generation's paymaster and the company Safe's 2-of-3 flow,
// on a fork of Base mainnet that keeps chain id 8453 (the real EntryPoint v0.7
// and Safe v1.4.1):
//
//   - a 2-of-3 Safe made from three of Hardhat's local accounts through Safe's
//     canonical factory, passing the deploy scripts' company Safe check;
//   - CofferdamRelayPaymaster owned by it from its first block, sponsoring
//     through EntryPoint.handleOps a first op whose initCode deploys a
//     Cofferdam account, only from the relayer, within the cap, never paused;
//   - safe-propose.ts's library building each owner action, its Transaction
//     Builder file read back from disk, the safeTxHash checked against the
//     Safe's own getTransactionHash, two owners' EIP-712 signatures sorted by
//     owner, execTransaction, and safe-readback.ts's check of the effect.
//
//   BASE_FORK=1 npx hardhat test test/fork/relay-paymaster-fork.test.ts   (yarn test:fork:safe)
//
// Nothing reaches Base mainnet: the in-process network forks it locally. No
// key is written anywhere; the signers are Hardhat's local accounts.

const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
const DAY = 86_400n;
const CAP = ethers.parseEther('0.01');

const FACTORY_ABI = ['function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)'];
const SAFE_ABI = [
  'function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)',
  'function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32)',
  'function nonce() view returns (uint256)',
];
const EP_ABI = [
  'function handleOps((address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature)[] ops, address beneficiary)',
  'function getUserOpHash((address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature) op) view returns (bytes32)',
  'function balanceOf(address) view returns (uint256)',
  'error FailedOp(uint256 opIndex, string reason)',
  'error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)',
];

/** The promise rejects with a message matching `re`. */
async function rejects(p: Promise<unknown>, re: RegExp): Promise<void> {
  let message = '';
  try {
    await p;
  } catch (e) {
    message = (e as Error).message || 'rejected';
  }
  expect(message, 'expected a refusal').to.match(re);
}

const pack128 = (hi: bigint, lo: bigint) => ethers.toBeHex((hi << 128n) | lo, 32);

describe('CofferdamRelayPaymaster and the 2-of-3 Safe on a fork of Base mainnet (chain 8453)', function () {
  this.timeout(600_000);

  before(async function () {
    if ((await ethers.provider.getNetwork()).chainId !== 8453n) this.skip();
    await network.provider.send('hardhat_mine', ['0x1']);
  });

  async function createSafe(owners: string[], threshold: number, salt: string): Promise<string> {
    const [deployer] = await ethers.getSigners();
    const init = new ethers.Interface(SAFE_ABI).encodeFunctionData('setup', [
      owners, threshold, ethers.ZeroAddress, '0x', SAFE_V141.fallbackHandler, ethers.ZeroAddress, 0, ethers.ZeroAddress,
    ]);
    const factory = new ethers.Contract(SAFE_V141.proxyFactory, FACTORY_ABI, deployer);
    const saltNonce = BigInt(ethers.id(`cofferdam-relay-paymaster-fork:${salt}`));
    const predicted: string = await factory.createProxyWithNonce.staticCall(SAFE_V141.singletonL2, init, saltNonce);
    await (await factory.createProxyWithNonce(SAFE_V141.singletonL2, init, saltNonce)).wait();
    return predicted;
  }

  async function setup() {
    const signers = await ethers.getSigners();
    const [deployer, ownerA, ownerB, ownerC, relayer, attacker, newRelayer, ownerD, ownerE, ownerF] = signers;
    const owners = [ownerA, ownerB, ownerC];
    const salt = ethers.hexlify(ethers.randomBytes(8));
    const safe = await createSafe(owners.map((o) => o.address), 2, `one:${salt}`);

    // The account layer the paymaster serves, owned by the Safe, on the real EntryPoint.
    const highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
    const moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(safe, [await highModule.getAddress()]);
    const ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(safe, []);
    const registry = await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
      safe, ethers.id('kind'), ethers.id('scope'), 3n * DAY, 3n * DAY, [], true, [],
    );
    const factory = await (await ethers.getContractFactory('CofferdamAccountFactory4337')).deploy(
      ENTRYPOINT_V07, moduleRegistry, ceremonyRegistry, registry, 3n * DAY, 3n * DAY,
    );
    const anchor = await (await ethers.getContractFactory('CofferdamHandleAnchor')).deploy(
      safe, HANDLE_ANCHOR_MAINNET.changeDelay, HANDLE_ANCHOR_MAINNET.freezeDuration, HANDLE_ANCHOR_MAINNET.quarantine, HANDLE_ANCHOR_MAINNET.safeDelay,
      [attacker.address],
    );
    const fp = await accountCodeFingerprint(await factory.getAddress(), await highModule.getAddress());
    const paymaster = await (await ethers.getContractFactory('CofferdamRelayPaymaster')).deploy(
      ENTRYPOINT_V07, safe, relayer.address, CAP, fp.codeHash, fp.codeSize, fp.maskOffsets,
    );
    await deployer.sendTransaction({ to: await paymaster.getAddress(), value: ethers.parseEther('0.1') });
    const recorded = {
      CofferdamSafe: { address: safe },
      CofferdamRelayPaymaster: { address: await paymaster.getAddress() },
      CofferdamIdentityRegistry: { address: await registry.getAddress() },
      CofferdamHandleAnchor: { address: await anchor.getAddress() },
    };
    const entryPoint = new ethers.Contract(ENTRYPOINT_V07, EP_ABI, deployer);
    return {
      deployer, owners, relayer, attacker, newRelayer, spares: [ownerD, ownerE, ownerF], safe, highModule, factory, paymaster, registry, anchor,
      recorded, entryPoint,
    };
  }

  type Ctx = Awaited<ReturnType<typeof setup>>;

  /**
   * safe-propose.ts's path, then the owners' part: build the call, pre-flight
   * it from the Safe, write the Transaction Builder file and read it back from
   * disk, hash, sign with `signers` (EIP-712), pack sorted by owner, execute
   * from `executor`, and run safe-readback.ts's checks on the execution.
   */
  async function proposeAndExecute(c: Ctx, action: ProposeAction, env: NodeJS.ProcessEnv, o: { signers?: Signer[]; safe?: string } = {}) {
    const chainId = 8453n;
    const safe = o.safe ?? c.safe;
    const facts = (await readSafeFacts(ethers.provider, safe))!;
    expect(safeProposeRefusal(safe, facts)).to.equal(null);
    const target = c.recorded[actionTarget(action).key as keyof Ctx['recorded']].address;
    const built = await buildSafeCall({ action, env, provider: ethers.provider, chainId, safe, safeFacts: facts, target, recorded: c.recorded });
    await ethers.provider.call({ from: safe, to: built.to, data: built.data, value: built.value }); // the pre-flight
    const nonce: bigint = await new ethers.Contract(safe, SAFE_ABI, ethers.provider).nonce();

    // The Transaction Builder file, through disk, as the Safe app imports it.
    const file = txBuilderFile({ chainId, safe, createdAt: 1, name: action, description: built.describe, tx: { to: built.to, value: built.value.toString(), data: built.data } });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cofferdam-safe-'));
    const p = path.join(dir, 'batch.json');
    fs.writeFileSync(p, JSON.stringify(file));
    const imported = JSON.parse(fs.readFileSync(p, 'utf8')) as BatchFile;
    fs.rmSync(dir, { recursive: true });
    expect(imported.meta.checksum).to.equal(txBuilderChecksum(imported));
    expect(imported.chainId).to.equal('8453');
    expect(imported.transactions).to.have.length(1);
    const t = imported.transactions[0];
    const tx = safeCallTx(t.to, BigInt(t.value), t.data, nonce);

    const hash = safeTxHash(chainId, safe, tx);
    const sc = new ethers.Contract(safe, SAFE_ABI, c.deployer);
    expect(await sc.getTransactionHash(tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce)).to.equal(hash);
    const parts = safeTxHashParts(chainId, safe, tx);
    expect(ethers.keccak256(ethers.concat(['0x1901', parts.domainHash, parts.messageHash]))).to.equal(hash);

    const signers = o.signers ?? [c.owners[2], c.owners[0]]; // out of order: packing sorts them
    const sigs = await Promise.all(
      signers.map(async (s) => ({ owner: await s.getAddress(), signature: await s.signTypedData(safeTxDomain(chainId, safe), SAFE_TX_TYPES, tx) })),
    );
    const signatures = packSafeSignatures(hash, sigs);
    // Anyone may execute once two owners signed; here an outsider does.
    const exec = await (sc.connect(c.attacker) as any).execTransaction(tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signatures);
    const receipt = await exec.wait();
    const proposal: SafeProposal = {
      kind: 'cofferdam-safe-proposal-v1', action, describe: built.describe, chainId: '8453', safe, nonce: nonce.toString(), safeTxHash: hash,
      domainHash: parts.domainHash, messageHash: parts.messageHash, tx: { to: tx.to, value: tx.value.toString(), data: tx.data, operation: 0 }, checks: built.checks,
    };
    await runReadback(ethers.provider, proposal, receipt.hash);
    return { proposal, receipt, tx, hash, signatures };
  }

  /** A first op from the relayer: initCode deploys a new account, which increments a counter, paid by the paymaster. */
  async function firstOp(c: Ctx, o: { maxFeePerGas?: bigint; verificationGas?: bigint } = {}) {
    const key = webauthnKey();
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const high = await c.highModule.getAddress();
    const sender: string = await c.factory.getFunction('getAddress')(high, key.config, NO_PERMISSION, salt);
    const initCode = ethers.concat([await c.factory.getAddress(), c.factory.interface.encodeFunctionData('deployAccount', [high, key.config, NO_PERMISSION, salt])]);
    const counter = await (await ethers.getContractFactory('MockCounter')).deploy();
    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const callData = Account.interface.encodeFunctionData('execute', [await counter.getAddress(), 0n, counter.interface.encodeFunctionData('increment')]);
    const maxFee = o.maxFeePerGas ?? ethers.parseUnits('0.1', 'gwei');
    const op = {
      sender,
      nonce: 0n,
      initCode,
      callData,
      accountGasLimits: pack128(o.verificationGas ?? 6_000_000n, 300_000n),
      preVerificationGas: 60_000n,
      gasFees: pack128(maxFee, maxFee),
      paymasterAndData: ethers.concat([await c.paymaster.getAddress(), ethers.toBeHex(150_000n, 16), ethers.toBeHex(0n, 16)]),
      signature: '0x',
    };
    const userOpHash: string = await c.entryPoint.getUserOpHash(op);
    op.signature = packSig(0, key.sign(userOpHash));
    const maxCost = (6_000_000n + 300_000n + 150_000n + 60_000n) * maxFee;
    return { op, sender, counter, maxCost };
  }

  /** The EntryPoint's refusal, decoded down to the paymaster's own error. */
  async function refusal(c: Ctx, from: Signer, op: unknown): Promise<string> {
    try {
      await (c.entryPoint.connect(from) as any).handleOps.staticCall([op], await from.getAddress(), { gasLimit: 10_000_000n });
    } catch (e) {
      const data = (e as { data?: string }).data;
      const parsed = data ? c.entryPoint.interface.parseError(data) : null;
      if (!parsed) throw e;
      if (parsed.name === 'FailedOpWithRevert') {
        const inner = c.paymaster.interface.parseError(parsed.args.inner);
        return `${parsed.args.reason}: ${inner ? inner.name : parsed.args.inner}`;
      }
      return String(parsed.args.reason);
    }
    return 'accepted';
  }

  it("creates a 2-of-3 Safe from three local accounts that passes the deploy scripts' company Safe check", async function () {
    const c = await setup();
    const facts = await readSafeFacts(ethers.provider, c.safe);
    expect(facts!.threshold).to.equal(2n);
    expect(facts!.owners.map((a) => a.toLowerCase()).sort()).to.deep.equal(c.owners.map((o) => o.address.toLowerCase()).sort());
    expect(facts!.modules).to.deep.equal([]);
    expect(productionOwnerRefusal(c.safe, facts)).to.equal(null);
    // As the deploy scripts call it: the deployer among the owners, the recorded Safe.
    expect(productionOwnerRefusal(c.safe, facts, { deployer: c.owners[1].address, recordedSafe: c.safe })).to.equal(null);
    expect(productionOwnerRefusal(c.safe, facts, { deployer: c.deployer.address })).to.match(/does not list the deployer/);
    const single = await createSafe([c.owners[0].address], 1, `single:${ethers.hexlify(ethers.randomBytes(4))}`);
    expect(productionOwnerRefusal(single, await readSafeFacts(ethers.provider, single))).to.match(/has 1 owners/);
    expect(safeProposeRefusal(single, await readSafeFacts(ethers.provider, single))).to.match(/threshold 1/);
    expect(await c.paymaster.owner()).to.equal(c.safe);
  });

  it('sponsors, through the real EntryPoint, a first op with initCode from the relayer only, within the cap', async function () {
    const c = await setup();
    const { op, sender, counter, maxCost } = await firstOp(c);
    expect(maxCost).to.be.lessThanOrEqual(CAP);
    const pm = await c.paymaster.getAddress();

    // Anyone else submitting the same op: the paymaster refuses (AA33).
    expect(await refusal(c, c.attacker, op)).to.equal('AA33 reverted: NotRelayer');
    expect(await refusal(c, c.owners[0], op)).to.equal('AA33 reverted: NotRelayer');

    const before: bigint = await c.entryPoint.balanceOf(pm);
    const receipt = await (await (c.entryPoint.connect(c.relayer) as any).handleOps([op], c.relayer.address, { gasLimit: 10_000_000n })).wait();
    expect(receipt.status).to.equal(1);
    expect(await ethers.provider.getCode(sender)).to.not.equal('0x');
    expect(await c.paymaster.isCofferdamAccount(sender)).to.equal(true);
    expect(await counter.value()).to.equal(1n);
    const spent = before - (await c.entryPoint.balanceOf(pm));
    expect(spent).to.be.greaterThan(0n);
    expect(spent).to.be.lessThanOrEqual(maxCost);
    console.log(`      first op (initCode + execute): handleOps gas ${receipt.gasUsed}, deposit spent ${ethers.formatEther(spent)} ETH of maxCost ${ethers.formatEther(maxCost)}`);

    // Above the cap: refused, even from the relayer.
    const big = await firstOp(c, { maxFeePerGas: ethers.parseUnits('2', 'gwei') });
    expect(big.maxCost).to.be.greaterThan(CAP);
    expect(await refusal(c, c.relayer, big.op)).to.equal('AA33 reverted: MaxCostExceeded');
  });

  it('runs every paymaster owner action as a 2-of-3 proposal: rotation, pause, cap, deposit, withdrawal, ownership', async function () {
    const c = await setup();
    const pm = await c.paymaster.getAddress();

    // One owner's signature is not enough.
    const lone = await buildSafeCall({
      action: 'paymaster-pause', env: {}, provider: ethers.provider, chainId: 8453n, safe: c.safe,
      safeFacts: (await readSafeFacts(ethers.provider, c.safe))!, target: pm, recorded: c.recorded,
    });
    const nonce0: bigint = await new ethers.Contract(c.safe, SAFE_ABI, ethers.provider).nonce();
    const loneTx = safeCallTx(lone.to, lone.value, lone.data, nonce0);
    const loneHash = safeTxHash(8453n, c.safe, loneTx);
    const one = packSafeSignatures(loneHash, [{ owner: c.owners[1].address, signature: await c.owners[1].signTypedData(safeTxDomain(8453n, c.safe), SAFE_TX_TYPES, loneTx) }]);
    const sc = new ethers.Contract(c.safe, SAFE_ABI, c.attacker);
    await expect(sc.execTransaction(loneTx.to, 0, loneTx.data, 0, 0, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, one)).to.be.reverted;
    // A non-owner's signature in place of the second owner's is refused too.
    const outsider = await c.attacker.signTypedData(safeTxDomain(8453n, c.safe), SAFE_TX_TYPES, loneTx);
    const mixed = packSafeSignatures(loneHash, [
      { owner: c.owners[1].address, signature: await c.owners[1].signTypedData(safeTxDomain(8453n, c.safe), SAFE_TX_TYPES, loneTx) },
      { owner: c.attacker.address, signature: outsider },
    ]);
    await expect(sc.execTransaction(loneTx.to, 0, loneTx.data, 0, 0, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, mixed)).to.be.reverted;
    expect(await c.paymaster.paused()).to.equal(false);

    // Rotation: the old relayer is refused, the new one sponsored.
    await proposeAndExecute(c, 'paymaster-set-relayer', { RELAYER_ADDRESS: c.newRelayer.address });
    expect(await c.paymaster.relayer()).to.equal(c.newRelayer.address);
    const a = await firstOp(c);
    expect(await refusal(c, c.relayer, a.op)).to.equal('AA33 reverted: NotRelayer');
    expect(await refusal(c, c.newRelayer, a.op)).to.equal('accepted');
    // A Safe owner is never the relayer.
    await rejects(proposeAndExecute(c, 'paymaster-set-relayer', { RELAYER_ADDRESS: c.owners[1].address }), /an owner of the Safe/);

    // Pause and resume.
    await proposeAndExecute(c, 'paymaster-pause', {});
    expect(await refusal(c, c.newRelayer, a.op)).to.equal('AA33 reverted: SponsorshipPaused');
    await proposeAndExecute(c, 'paymaster-unpause', {}, { signers: [c.owners[1], c.owners[2]] });
    expect(await refusal(c, c.newRelayer, a.op)).to.equal('accepted');

    // The cap, lowered below the op's maxCost.
    await proposeAndExecute(c, 'paymaster-set-max-cost', { PAYMASTER_MAX_COST_WEI: (a.maxCost - 1n).toString() });
    expect(await refusal(c, c.newRelayer, a.op)).to.equal('AA33 reverted: MaxCostExceeded');
    await rejects(proposeAndExecute(c, 'paymaster-set-max-cost', { PAYMASTER_MAX_COST_WEI: (10n ** 16n + 1n).toString() }), /likely typo/);

    // A deposit from the Safe's balance, then a withdrawal to the Safe.
    await c.deployer.sendTransaction({ to: c.safe, value: ethers.parseEther('0.05') });
    const before: bigint = await c.entryPoint.balanceOf(pm);
    await proposeAndExecute(c, 'paymaster-deposit', { AMOUNT_WEI: ethers.parseEther('0.02').toString() });
    expect(await c.entryPoint.balanceOf(pm)).to.equal(before + ethers.parseEther('0.02'));
    const safeBalance = await ethers.provider.getBalance(c.safe);
    await proposeAndExecute(c, 'paymaster-withdraw', { AMOUNT_WEI: ethers.parseEther('0.03').toString() });
    expect(await ethers.provider.getBalance(c.safe)).to.equal(safeBalance + ethers.parseEther('0.03'));
    expect(await c.entryPoint.balanceOf(pm)).to.equal(before - ethers.parseEther('0.01'));
    await rejects(proposeAndExecute(c, 'paymaster-withdraw', { AMOUNT_WEI: ethers.parseEther('1').toString() }), /more than the deposit/);

    // The nominee is checked before the owners sign: never an EOA, a 1-of-1 Safe or this Safe.
    await rejects(proposeAndExecute(c, 'paymaster-transfer-ownership', { NEW_SAFE: c.attacker.address }), /NEW_SAFE: .*not a Safe/);
    const lone1 = await createSafe([c.spares[0].address], 1, `lone:${ethers.hexlify(ethers.randomBytes(4))}`);
    await rejects(proposeAndExecute(c, 'paymaster-transfer-ownership', { NEW_SAFE: lone1 }), /NEW_SAFE: .*has 1 owners/);
    await rejects(proposeAndExecute(c, 'paymaster-transfer-ownership', { NEW_SAFE: c.safe }), /NEW_SAFE is this Safe/);

    // Ownership to a second 2-of-3 Safe, in two steps.
    const next = await createSafe(c.spares.map((s) => s.address), 2, `next:${ethers.hexlify(ethers.randomBytes(4))}`);
    await proposeAndExecute(c, 'paymaster-transfer-ownership', { NEW_SAFE: next });
    expect(await c.paymaster.owner()).to.equal(c.safe);
    expect(await c.paymaster.pendingOwner()).to.equal(next);
    await proposeAndExecute(c, 'paymaster-accept-ownership', {}, { safe: next, signers: [c.spares[0], c.spares[2]] });
    expect(await c.paymaster.owner()).to.equal(next);
    expect(await c.paymaster.pendingOwner()).to.equal(ethers.ZeroAddress);
    await rejects(proposeAndExecute(c, 'paymaster-pause', {}), /owned by .*not the Safe/);
  });

  it("proposes the identity registry's and the handle anchor's actions through the same path", async function () {
    const c = await setup();
    await proposeAndExecute(c, 'pause', {});
    expect(await c.registry.paused()).to.equal(true);
    await proposeAndExecute(c, 'unpause', {});
    expect(await c.registry.paused()).to.equal(false);
    await proposeAndExecute(c, 'set-test-account', { ACCOUNT: c.attacker.address });
    expect(await c.registry.isTestAccount(c.attacker.address)).to.equal(true);
    // The anchor's immediate removal of a registrar.
    expect(await c.anchor.isRegistrar(c.attacker.address)).to.equal(true);
    await proposeAndExecute(c, 'anchor-registrar-remove', { REGISTRAR: c.attacker.address });
    expect(await c.anchor.isRegistrar(c.attacker.address)).to.equal(false);
    // A timelocked add is scheduled, and its execution refused until ready.
    await proposeAndExecute(c, 'anchor-registrar-schedule', { REGISTRAR: c.newRelayer.address });
    await rejects(proposeAndExecute(c, 'anchor-registrar-add', { REGISTRAR: c.newRelayer.address }), /revert/i);
  });

  it("read-back refuses an execution that is not the proposal's, and an effect that does not hold", async function () {
    const c = await setup();
    const { proposal, receipt } = await proposeAndExecute(c, 'paymaster-pause', {});
    // Another transaction: no ExecutionSuccess for this hash.
    const other = await (await c.deployer.sendTransaction({ to: c.deployer.address, value: 0 })).wait();
    await rejects(runReadback(ethers.provider, proposal, other!.hash), /not this proposal's execution/);
    // A proposal whose hash differs from the executed one.
    await rejects(runReadback(ethers.provider, { ...proposal, safeTxHash: ethers.ZeroHash }, receipt.hash), /the record was altered/);
    // A record edited to another nonce (or call) no longer matches its own hash.
    await rejects(runReadback(ethers.provider, { ...proposal, nonce: '7' }, receipt.hash), /the record was altered/);
    // The same execution, read against a check that does not hold.
    const wrong = { ...proposal, checks: proposal.checks.map((ch) => (ch.kind === 'call' ? { ...ch, value: 'false' } : ch)) };
    await rejects(runReadback(ethers.provider, wrong, receipt.hash), /paused: read true, expected false/);
  });
});
