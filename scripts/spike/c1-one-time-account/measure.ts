// SPIKE (C1, 2026-11-17): gas of a one-time receive account on a LOCAL fork of
// Base mainnet, two ways, for ruling A of the handle and income plan:
//   (a) a minimal ERC-4337 v0.7 account from a CREATE2 factory (0083 rule 4);
//   (b) a scheme 1 stealth EOA delegating to code under EIP-7702.
// Each is measured for its deploy or delegation, the first USDC receive, the
// first sweep and a later sweep, plus the ERC-5564 announcement.
//
// It talks to a local anvil only and refuses anything else (it checks the
// node answers anvil_nodeInfo). Start the fork first, for example:
//   base-anvil --base --fork-url https://mainnet.base.org --fork-block-number <n> \
//     --port 8611 --timeout 600000 --retries 10
// then, after `yarn compile`:
//   C1_RPC=http://127.0.0.1:8611 npx ts-node scripts/spike/c1-one-time-account/measure.ts
// Every key here is a fresh random test key on the fork; nothing is signed for
// a live network. Results go to stdout and to results.json beside this file.

import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';

const RPC = process.env.C1_RPC || 'http://127.0.0.1:8611';
const ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564';
const GAS_PRICE_ORACLE = '0x420000000000000000000000000000000000000F';
const CHAINLINK_ETH_USD = '0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70';
/** FiatTokenV2_2 keeps balances (with the blacklist bit) in mapping slot 9. */
const USDC_BALANCE_SLOT = 9n;
/** Base's usual tip (eth_maxPriorityFeePerGas on mainnet.base.org, 2026-11-17): 0.001 gwei. */
const TIP = BigInt(process.env.C1_TIP_WEI || '1000000');

const ART = path.join(__dirname, '..', '..', '..', 'artifacts', 'contracts', 'spike', 'c1-one-time-account', 'SpikeOneTimeAccount.sol');
const artifact = (name: string) => JSON.parse(fs.readFileSync(path.join(ART, `${name}.json`), 'utf8')) as { abi: ethers.InterfaceAbi; bytecode: string };

const EP_ABI = [
  'function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)[] ops, address beneficiary)',
  'function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) op) view returns (bytes32)',
  'function getNonce(address sender, uint192 key) view returns (uint256)',
];
const ERC20_ABI = ['function transfer(address to, uint256 amount) returns (bool)', 'function balanceOf(address) view returns (uint256)'];
const ANNOUNCER_ABI = ['function announce(uint256 schemeId, address stealthAddress, bytes ephemeralPubKey, bytes metadata)'];
const ORACLE_ABI = ['function getL1Fee(bytes) view returns (uint256)'];
const FEED_ABI = ['function latestRoundData() view returns (uint80, int256 answer, uint256, uint256 updatedAt, uint80)'];

type Row = { case: string; form: string; gasUsed: bigint; l2FeeWei: bigint; l1FeeWei: bigint; totalWei: bigint; txBytes: number; note: string };

/** The fork reads state it lacks from the public RPC, which can time out: retry a read a few times. */
async function retry<T>(read: () => Promise<T>, attempts = 6): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await read();
    } catch (e) {
      if (i >= attempts) throw e;
      console.log(`  (fork read failed, retry ${i}: ${(e as Error).message.slice(0, 80)})`);
      await new Promise((r) => setTimeout(r, 5_000 * i));
    }
  }
}

/** A fresh random test key as a plain Wallet. */
const fresh = () => new ethers.Wallet(ethers.Wallet.createRandom().privateKey);

const pack128 = (hi: bigint, lo: bigint) => ethers.toBeHex((hi << 128n) | lo, 32);

async function main() {
  const fetchReq = new ethers.FetchRequest(RPC);
  fetchReq.timeout = 600_000;
  const provider = new ethers.JsonRpcProvider(fetchReq, undefined, { staticNetwork: true, batchMaxCount: 1 });
  try {
    await provider.send('anvil_nodeInfo', []);
  } catch {
    throw new Error(`${RPC} is not an anvil node: this spike runs on a local fork only`);
  }
  const net = await provider.getNetwork();
  if (net.chainId !== 8453n) throw new Error(`Expected a fork of Base mainnet (8453), got ${net.chainId}`);
  // The fork's own block, not anvil's later ones (whose base fee anvil computes itself).
  const info = await provider.send('anvil_nodeInfo', []);
  const forkNumber = Number(process.env.C1_FORK_BLOCK || info?.forkConfig?.forkBlockNumber);
  const forkBlock = await retry(async () => {
    const b = await provider.getBlock(forkNumber);
    if (!b) throw new Error(`no block ${forkNumber}`);
    return b;
  });
  const baseFee = forkBlock.baseFeePerGas!;
  console.log(`Fork of Base at block ${forkBlock.number}, base fee ${baseFee} wei, tip ${TIP} wei`);

  const fund = async (a: string, eth = '10') => provider.send('anvil_setBalance', [a, ethers.toBeHex(ethers.parseEther(eth))]);
  const actor = async () => {
    const w = fresh().connect(provider);
    await fund(w.address);
    return w;
  };
  // Each actor sends through ethers' NonceManager: anvil's pending count can lag a mined receipt.
  const deployer = await actor();
  const bundlerWallet = await actor();
  const relayerWallet = await actor();
  const payerWallet = await actor();
  const bundler = new ethers.NonceManager(bundlerWallet);
  const relayer = new ethers.NonceManager(relayerWallet);
  const payer = new ethers.NonceManager(payerWallet);

  const setUsdc = async (who: string, amount: bigint) => {
    const slot = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [who, USDC_BALANCE_SLOT]));
    await provider.send('anvil_setStorageAt', [USDC, slot, ethers.toBeHex(amount, 32)]);
  };
  const usdc = new ethers.Contract(USDC, ERC20_ABI, provider);
  await setUsdc(payerWallet.address, 1_000_000n * 10n ** 6n);
  if ((await usdc.balanceOf(payerWallet.address)) !== 1_000_000n * 10n ** 6n) throw new Error('USDC balance slot guess is wrong');
  // The sweep goes to an address that already holds USDC (the user's main account, or an exchange).
  const dest = ethers.Wallet.createRandom().address;
  await setUsdc(dest, 1n * 10n ** 6n);

  const deploy = async (name: string, ...args: unknown[]) => {
    const a = artifact(name);
    const c = await new ethers.ContractFactory(a.abi, a.bytecode, deployer).deploy(...args);
    await c.waitForDeployment();
    return c as ethers.Contract;
  };
  const factory = await deploy('SpikeOneTimeAccountFactory', ENTRY_POINT);
  const fullFactory = await deploy('SpikeOneTimeAccountFullFactory', ENTRY_POINT);
  const delegate = await deploy('Spike7702Delegate', ENTRY_POINT);
  const paymaster = await deploy('SpikeSponsorAllPaymaster', ENTRY_POINT);
  await (await (paymaster.connect(deployer) as ethers.Contract).deposit({ value: ethers.parseEther('5') })).wait();
  const entryPoint = new ethers.Contract(ENTRY_POINT, EP_ABI, bundler);
  const accountIface = new ethers.Interface(artifact('SpikeOneTimeAccount').abi);
  const delegateIface = new ethers.Interface(artifact('Spike7702Delegate').abi);
  const oracle = new ethers.Contract(GAS_PRICE_ORACLE, ORACLE_ABI, provider);

  const rows: Row[] = [];
  async function record(caseName: string, form: string, txHash: string, note = '') {
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt || receipt.status !== 1) throw new Error(`${caseName}: transaction ${txHash} failed`);
    let raw: string;
    try {
      raw = await provider.send('eth_getRawTransactionByHash', [txHash]);
    } catch {
      raw = ethers.Transaction.from((await provider.getTransaction(txHash))!).serialized;
    }
    // GasPriceOracle.getL1Fee takes the UNSIGNED RLP transaction and adds 68
    // bytes for the signature itself (Fjord), so the signature is stripped.
    const unsigned = ethers.Transaction.from(raw).unsignedSerialized;
    const l1FeeWei: bigint = await retry(() => oracle.getL1Fee(unsigned));
    const l2FeeWei = receipt.gasUsed * (baseFee + TIP);
    rows.push({ case: caseName, form, gasUsed: receipt.gasUsed, l2FeeWei, l1FeeWei, totalWei: l2FeeWei + l1FeeWei, txBytes: ethers.dataLength(raw), note });
    console.log(`${form} | ${caseName}: gas ${receipt.gasUsed}, ${ethers.dataLength(raw)} tx bytes`);
    return receipt;
  }

  const transferData = (to: string, amount: bigint) => new ethers.Interface(ERC20_ABI).encodeFunctionData('transfer', [to, amount]);
  const receive = async (to: string, form: string, caseName = 'first USDC receive (payer pays)') => {
    const tx = await (usdc.connect(payer) as ethers.Contract).transfer(to, 100n * 10n ** 6n);
    await tx.wait();
    return record(caseName, form, tx.hash, 'a plain USDC transfer from an EOA to a fresh address; the same for both forms');
  };

  /** A sponsored user operation through EntryPoint v0.7, sent by the bundler (optionally as a type-4 transaction). */
  async function userOp(o: { sender: string; signer: ethers.Wallet; initCode?: string; callData: string; authorization?: ethers.Authorization }) {
    const op = {
      sender: o.sender,
      nonce: await entryPoint.getNonce(o.sender, 0),
      initCode: o.initCode ?? '0x',
      callData: o.callData,
      accountGasLimits: pack128(400_000n, 200_000n),
      preVerificationGas: 60_000n,
      gasFees: pack128(TIP, baseFee * 4n + TIP),
      paymasterAndData: ethers.concat([await paymaster.getAddress(), ethers.toBeHex(100_000n, 16), ethers.toBeHex(0n, 16)]),
      signature: '0x',
    };
    const hash: string = await entryPoint.getUserOpHash(op);
    op.signature = o.signer.signingKey.sign(hash).serialized;
    const data = entryPoint.interface.encodeFunctionData('handleOps', [[op], bundlerWallet.address]);
    const tx = await bundler.sendTransaction({
      to: ENTRY_POINT,
      data,
      gasLimit: 1_500_000n,
      ...(o.authorization ? { type: 4, authorizationList: [o.authorization] } : {}),
    });
    await tx.wait();
    return tx.hash;
  }

  const sweepCall = (from: string) => async () => transferData(dest, await usdc.balanceOf(from));

  // ── Form (a): ERC-4337 v0.7 account from a CREATE2 factory ───────────────

  {
    const s = fresh();
    const tx = await (factory.connect(relayer) as ethers.Contract).createAccount(s.address);
    await tx.wait();
    await record('deploy alone (ERC-1167 clone with the signer as immutable argument)', '(a) 4337', tx.hash, 'factory.createAccount from an EOA');
    const s2 = fresh();
    const tx2 = await (fullFactory.connect(relayer) as ethers.Contract).createAccount(s2.address);
    await tx2.wait();
    await record('deploy alone (full bytecode, for comparison)', '(a) 4337', tx2.hash, 'not the recommended shape');
  }
  {
    const s = fresh();
    const account: string = await factory.getFunction('getAddress')(s.address);
    await receive(account, '(a) 4337');
    const initCode = ethers.concat([await factory.getAddress(), factory.interface.encodeFunctionData('createAccount', [s.address])]);
    const call = accountIface.encodeFunctionData('execute', [USDC, 0, await sweepCall(account)()]);
    await record('first sweep, deploy included (initCode), sponsored', '(a) 4337', await userOp({ sender: account, signer: s, initCode, callData: call }));
    await receive(account, '(a) 4337', 'second USDC receive (account deployed, balance back from 0)');
    const call2 = accountIface.encodeFunctionData('execute', [USDC, 0, await sweepCall(account)()]);
    await record('later sweep, sponsored', '(a) 4337', await userOp({ sender: account, signer: s, callData: call2 }));
  }

  // ── Form (b): EIP-7702 delegation from a scheme 1 stealth EOA ────────────

  const authFor = async (s: ethers.Wallet) =>
    s.authorize({ address: await delegate.getAddress(), nonce: await provider.getTransactionCount(s.address), chainId: 8453n });

  {
    const s = fresh().connect(provider);
    const tx = await relayer.sendTransaction({ type: 4, to: s.address, data: '0x', authorizationList: [await authFor(s)], gasLimit: 200_000n });
    await tx.wait();
    await record('delegate alone (type-4 tx, empty call)', '(b) 7702', tx.hash, 'sent by a relayer; the stealth EOA holds no ETH');
    const code = await provider.getCode(s.address);
    if (!code.toLowerCase().startsWith('0xef0100')) throw new Error(`7702 delegation not applied: code ${code}`);
  }
  {
    // Relayed direct call, signed by the stealth key.
    const s = fresh().connect(provider);
    await receive(s.address, '(b) 7702');
    const sweepSigned = async (withAuth: boolean, caseName: string) => {
      const data = await sweepCall(s.address)();
      const deadline = BigInt(forkBlock.timestamp) + 10n ** 9n;
      const nonce = withAuth ? 0n : BigInt(await new ethers.Contract(s.address, delegateIface, provider).directNonce());
      const h = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['uint256', 'address', 'uint256', 'address', 'uint256', 'bytes32', 'uint256'],
          [8453n, s.address, nonce, USDC, 0n, ethers.keccak256(data), deadline],
        ),
      );
      const sig = s.signingKey.sign(h).serialized;
      const call = delegateIface.encodeFunctionData('executeSigned', [USDC, 0n, data, deadline, sig]);
      const tx = await relayer.sendTransaction({
        to: s.address,
        data: call,
        gasLimit: 300_000n,
        ...(withAuth ? { type: 4, authorizationList: [await authFor(s)] } : {}),
      });
      await tx.wait();
      await record(caseName, '(b) 7702', tx.hash, 'relayer EOA pays; no EntryPoint, no paymaster');
    };
    await sweepSigned(true, 'first sweep, delegation included, relayed direct call');
    await receive(s.address, '(b) 7702', 'second USDC receive (balance back from 0)');
    await sweepSigned(false, 'later sweep, relayed direct call');
  }
  {
    // Through EntryPoint v0.7: the bundler's type-4 transaction carries the authorization.
    const s = fresh().connect(provider);
    await receive(s.address, '(b) 7702');
    const call = delegateIface.encodeFunctionData('execute', [USDC, 0, await sweepCall(s.address)()]);
    await record(
      'first sweep, delegation included (bundler type-4), sponsored',
      '(b) 7702',
      await userOp({ sender: s.address, signer: s, callData: call, authorization: await authFor(s) }),
    );
    await receive(s.address, '(b) 7702', 'second USDC receive (balance back from 0)');
    const call2 = delegateIface.encodeFunctionData('execute', [USDC, 0, await sweepCall(s.address)()]);
    await record('later sweep, sponsored', '(b) 7702', await userOp({ sender: s.address, signer: s, callData: call2 }));
  }

  // ── The ERC-5564 announcement (either form) ──────────────────────────────

  {
    const announcer = new ethers.Contract(ANNOUNCER, ANNOUNCER_ABI, relayer);
    const ephemeral = ethers.SigningKey.computePublicKey(ethers.Wallet.createRandom().signingKey.publicKey, true);
    const stealth = ethers.Wallet.createRandom().address;
    // ERC-5564 metadata for a token transfer: view tag, selector, token, amount (57 bytes).
    const metadata = ethers.concat(['0x7a', ethers.dataSlice(ethers.id('transfer(address,uint256)'), 0, 4), USDC, ethers.toBeHex(100n * 10n ** 6n, 32)]);
    const tx = await announcer.announce(1, stealth, ephemeral, metadata);
    await tx.wait();
    await record('ERC-5564 announce (scheme 1, 33-byte ephemeral key, 57-byte metadata)', 'either', tx.hash, 'a standalone tx; inside a payer batch it costs about 21,000 less');
  }

  // ── Price and output ─────────────────────────────────────────────────────

  let ethUsd: number | null = null;
  try {
    const [, answer] = await new ethers.Contract(CHAINLINK_ETH_USD, FEED_ABI, provider).latestRoundData();
    ethUsd = Number(answer) / 1e8;
  } catch {
    ethUsd = null;
  }
  const fmtEth = (w: bigint) => `${ethers.formatEther(w)}`;
  const usd = (w: bigint) => (ethUsd === null ? 'n/a' : `$${((Number(w) / 1e18) * ethUsd).toFixed(5)}`);
  console.log(`\nETH/USD ${ethUsd ?? 'unknown'} (Chainlink on the fork)`);
  console.log('| form | case | gas | L2 fee (ETH) | L1 fee (ETH) | total (ETH) | total (USD) |');
  console.log('|---|---|---:|---:|---:|---:|---:|');
  for (const r of rows) console.log(`| ${r.form} | ${r.case} | ${r.gasUsed} | ${fmtEth(r.l2FeeWei)} | ${fmtEth(r.l1FeeWei)} | ${fmtEth(r.totalWei)} | ${usd(r.totalWei)} |`);

  const out = {
    note: 'SPIKE C1: one-time receive account gas on a local fork of Base mainnet. Not a design.',
    forkBlock: forkBlock.number,
    baseFeeWei: baseFee.toString(),
    tipWei: TIP.toString(),
    ethUsd,
    rows: rows.map((r) => ({ ...r, gasUsed: r.gasUsed.toString(), l2FeeWei: r.l2FeeWei.toString(), l1FeeWei: r.l1FeeWei.toString(), totalWei: r.totalWei.toString() })),
  };
  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(out, null, 2) + '\n');
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
