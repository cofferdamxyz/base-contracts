import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { artifacts, ethers } from 'hardhat';
import { Wallet } from 'ethers';
import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import type { CofferdamHandleAnchor } from '../typechain-types';

import { DEV_KEY_EXCEPTION, SAFE_V141, type SafeFacts } from '../scripts/lib/devKeyException';
import { HANDLE_ANCHOR_MAINNET } from '../scripts/lib/handleAnchor';
import {
  BASE_SEPOLIA_CHAIN_ID,
  HANDLE_ANCHOR_SEPOLIA_DEFAULTS,
  chainRefusal,
  deployHandleAnchor,
  mainnetDelaysRefusal,
  planeEnvLines,
  recordHandleAnchor,
  registrarFrom,
  registrarRefusal,
  safeRefusal,
  sepoliaDelaysFrom,
} from '../scripts/lib/handleAnchorDeploy';
import { constructorArgsHex, selectRecorded, verifyPlan } from '../scripts/lib/verify';

// scripts/deploy-handle-anchor.ts (workspace decision 0086, rule 3; runbook
// docs/runbooks/handles-build.md step 2) driven through its library on the
// in-process network: the deploy and its read-back, the deployments entries
// and the plane's env lines, and every refusal, Base mainnet first. The Safe's
// facts are injected here (no Safe v1.4.1 exists on the in-process network);
// the anvil fork of Base Sepolia runs the script against a real one.

const DAY = 24n * 3600n;
const SAFE = Wallet.createRandom().address;
const SAFE_SIGNER = Wallet.createRandom().address;
const REGISTRAR = new Wallet(ethers.id('cofferdam-handle-anchor-deploy-test:registrar')).address;
const RELAYER = Wallet.createRandom().address;
const safeFacts = (owners: string[], singleton: string = SAFE_V141.singletonL2): SafeFacts => ({ singleton, owners, threshold: 1n });

describe('deploy-handle-anchor (scripts/lib/handleAnchorDeploy.ts)', function () {
  let deployer: HardhatEthersSigner;

  before(async function () {
    [deployer] = await ethers.getSigners();
  });

  async function run(env: NodeJS.ProcessEnv, o: Partial<Parameters<typeof deployHandleAnchor>[0]> = {}) {
    return deployHandleAnchor({
      factory: await ethers.getContractFactory('CofferdamHandleAnchor', deployer),
      deployer,
      provider: ethers.provider,
      localDevNode: true,
      env,
      safe: SAFE,
      readSafe: async (a) => (a.toLowerCase() === SAFE.toLowerCase() ? safeFacts([deployer.address, SAFE_SIGNER]) : null),
      relayers: [RELAYER],
      ...o,
    });
  }

  it("deploys with Sepolia's short delays, owned by the Safe, the plane's registrar listed and the deployer holding no role", async function () {
    const lines: string[] = [];
    const d = (await run({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { log: (l) => lines.push(l) }))!;
    const anchor = (await ethers.getContractAt('CofferdamHandleAnchor', d.address)) as unknown as CofferdamHandleAnchor;

    expect(await anchor.CHANGE_DELAY()).to.equal(600n);
    expect(await anchor.FREEZE_DURATION()).to.equal(1800n);
    expect(await anchor.QUARANTINE()).to.equal(DAY);
    expect(await anchor.SAFE_DELAY()).to.equal(600n);
    expect(d.delays).to.deep.equal(HANDLE_ANCHOR_SEPOLIA_DEFAULTS);

    expect(await anchor.owner()).to.equal(SAFE);
    expect(await anchor.pendingOwner()).to.equal(ethers.ZeroAddress);
    expect(await anchor.isRegistrar(REGISTRAR)).to.equal(true);
    expect(await anchor.isRegistrar(deployer.address)).to.equal(false);
    expect(await anchor.owner()).to.not.equal(deployer.address);
    // The constructor lists exactly one registrar.
    const added = await anchor.queryFilter(anchor.filters.RegistrarAdded(), d.blockNumber, d.blockNumber);
    expect(added.map((e) => e.args.registrar)).to.deep.equal([REGISTRAR]);
    // The deployer cannot act as the owner.
    await expect(anchor.connect(deployer).removeRegistrar(REGISTRAR)).to.be.revertedWithCustomError(anchor, 'NotOwner');

    const receipt = await ethers.provider.getTransactionReceipt(d.txHash);
    expect(receipt?.contractAddress).to.equal(d.address);
    expect(receipt?.blockNumber).to.equal(d.blockNumber);
    expect(d.deployer).to.equal(deployer.address);
    expect(lines.join('\n')).to.match(/the deployer signs for the Safe/);
    expect(planeEnvLines(d)).to.deep.equal([`HANDLE_ANCHOR_ADDRESS=${d.address}`, `HANDLE_ANCHOR_FROM_BLOCK=${d.blockNumber}`]);

    // The deployments entries, merged into a file that keeps its other entries, and verify.ts's plan of them.
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-deploy-')), 'baseSepolia.json');
    fs.writeFileSync(file, JSON.stringify({ EntryPoint: { address: '0x0000000071727De22E5E9d8BAf0edAc6f37da032' }, MockUSDC: { address: RELAYER } }, null, 2) + '\n');
    recordHandleAnchor(file, d);
    const written = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(written.CofferdamHandleAnchor).to.deep.equal({ address: d.address, txHash: d.txHash, blockNumber: d.blockNumber, deployer: deployer.address });
    expect(written.CofferdamHandleAnchorSafe).to.deep.equal({ address: SAFE });
    expect(written.MockUSDC.address).to.equal(RELAYER);
    expect(() => verifyPlan(written)).to.throw(/MockUSDC/);
    const plan = verifyPlan(selectRecorded(written, 'CofferdamHandleAnchor,CofferdamHandleAnchorSafe'));
    expect(plan.ours).to.deep.equal([{ key: 'CofferdamHandleAnchor', contract: 'CofferdamHandleAnchor', address: d.address, txHash: d.txHash }]);
    expect(plan.notOurs).to.deep.equal([{ key: 'CofferdamHandleAnchorSafe', address: SAFE }]);
    expect(() => selectRecorded(written, 'CofferdamHandleAnchor,Nothing')).to.throw(/Nothing/);

    // What verify.ts submits: the recorded creation transaction starts with the compiled bytecode, and its arguments decode.
    const tx = await ethers.provider.getTransaction(d.txHash);
    expect(tx?.from).to.equal(deployer.address);
    const artifact = await artifacts.readArtifact('CofferdamHandleAnchor');
    const iface = new ethers.Interface(artifact.abi);
    const args = ethers.AbiCoder.defaultAbiCoder().decode(iface.deploy.inputs, constructorArgsHex(tx!.data, artifact.bytecode)).toArray(true);
    expect(args).to.deep.equal([SAFE, 600n, 1800n, DAY, 600n, [REGISTRAR]]);
  });

  it('takes the delays from the environment, within the contract bounds', async function () {
    const env = {
      HANDLE_REGISTRAR_ADDRESS: REGISTRAR,
      HANDLE_CHANGE_DELAY_SECONDS: '60',
      HANDLE_FREEZE_SECONDS: '120',
      HANDLE_QUARANTINE_SECONDS: '0',
      HANDLE_SAFE_DELAY_SECONDS: '0',
    };
    const d = (await run(env))!;
    const anchor = (await ethers.getContractAt('CofferdamHandleAnchor', d.address)) as unknown as CofferdamHandleAnchor;
    expect([await anchor.CHANGE_DELAY(), await anchor.FREEZE_DURATION(), await anchor.QUARANTINE(), await anchor.SAFE_DELAY()]).to.deep.equal([60n, 120n, 0n, 0n]);

    expect(() => sepoliaDelaysFrom({ HANDLE_FREEZE_SECONDS: '0' })).to.throw(/never 0/);
    expect(() => sepoliaDelaysFrom({ HANDLE_CHANGE_DELAY_SECONDS: String(30n * DAY + 1n) })).to.throw(/30 days/);
    expect(() => sepoliaDelaysFrom({ HANDLE_SAFE_DELAY_SECONDS: String(30n * DAY + 1n) })).to.throw(/30 days/);
    expect(() => sepoliaDelaysFrom({ HANDLE_QUARANTINE_SECONDS: String(730n * DAY + 1n) })).to.throw(/730 days/);
    expect(sepoliaDelaysFrom({ HANDLE_QUARANTINE_SECONDS: String(730n * DAY) }).quarantine).to.equal(730n * DAY);
    expect(() => sepoliaDelaysFrom({ HANDLE_CHANGE_DELAY_SECONDS: '10m' })).to.throw(/whole number/);
    expect(() => sepoliaDelaysFrom({ HANDLE_CHANGE_DELAY_SECONDS: '-1' })).to.throw(/whole number/);
  });

  it('refuses Base mainnet outright, a fork of it included, and any chain that is neither Sepolia nor a local node', async function () {
    expect(chainRefusal(8453n, false)).to.match(/never deploys to Base mainnet/);
    expect(chainRefusal(8453n, true)).to.match(/never deploys to Base mainnet/);
    expect(chainRefusal(BASE_SEPOLIA_CHAIN_ID, false)).to.equal(null);
    expect(chainRefusal(BASE_SEPOLIA_CHAIN_ID, true)).to.equal(null);
    expect(chainRefusal(31337n, true)).to.equal(null);
    expect(chainRefusal(1n, false)).to.match(/neither Base Sepolia/);

    // The library reads the chain id from the node: a provider reporting 8453 sends nothing.
    const mainnetProvider = new Proxy(ethers.provider, {
      get(target, prop, receiver) {
        if (prop === 'getNetwork') return async () => ({ chainId: 8453n, name: 'base' });
        return Reflect.get(target, prop, receiver);
      },
    });
    const nonce = await ethers.provider.getTransactionCount(deployer.address);
    let error: Error | undefined;
    try {
      await run({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { provider: mainnetProvider });
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).to.match(/never deploys to Base mainnet/);
    expect(await ethers.provider.getTransactionCount(deployer.address)).to.equal(nonce);
  });

  it("pins decision 0086's delays for the mainnet script that comes with the Ledger", function () {
    expect(mainnetDelaysRefusal({ ...HANDLE_ANCHOR_MAINNET })).to.equal(null);
    expect(HANDLE_ANCHOR_MAINNET).to.deep.equal({ changeDelay: 72n * 3600n, freezeDuration: 14n * DAY, quarantine: 365n * DAY, safeDelay: 72n * 3600n });
    expect(mainnetDelaysRefusal(HANDLE_ANCHOR_SEPOLIA_DEFAULTS)).to.match(/changeDelay 600, not 259200.*freezeDuration.*quarantine.*safeDelay/);
    // Equal, not merely at least: a longer delay is refused too, as the contract does on chain 8453.
    expect(mainnetDelaysRefusal({ ...HANDLE_ANCHOR_MAINNET, quarantine: 400n * DAY })).to.match(/^On Base mainnet .*quarantine 34560000, not 31536000$/);
  });

  it('refuses a registrar that is not the plane\'s own hot key, and an owner that is not a Safe v1.4.1', async function () {
    const base = { registrar: REGISTRAR, deployer: deployer.address, safe: SAFE, safeOwners: [SAFE_SIGNER], relayers: [RELAYER], registrarHasCode: false };
    expect(registrarRefusal(base)).to.equal(null);
    expect(registrarRefusal({ ...base, registrar: deployer.address })).to.match(/is the deployer/);
    expect(registrarRefusal({ ...base, registrar: DEV_KEY_EXCEPTION.signer })).to.match(/CofferdamDev wallet/);
    expect(registrarRefusal({ ...base, registrar: RELAYER.toLowerCase() })).to.match(/plane's relayer/);
    expect(registrarRefusal({ ...base, registrar: SAFE })).to.match(/is the Safe/);
    expect(registrarRefusal({ ...base, registrar: SAFE_SIGNER })).to.match(/signs for the Safe/);
    expect(registrarRefusal({ ...base, registrarHasCode: true })).to.match(/has code/);

    expect(() => registrarFrom({})).to.throw(/HANDLE_REGISTRAR_ADDRESS is required/);
    expect(() => registrarFrom({ HANDLE_REGISTRAR_ADDRESS: 'plane' })).to.throw(/required/);
    expect(() => registrarFrom({ HANDLE_REGISTRAR_ADDRESS: `${REGISTRAR},${RELAYER}` })).to.throw(/required/);
    expect(() => registrarFrom({ HANDLE_REGISTRAR_ADDRESS: ethers.ZeroAddress })).to.throw(/zero address/);
    expect(registrarFrom({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR.toLowerCase() })).to.equal(REGISTRAR);

    expect(safeRefusal(SAFE, safeFacts([SAFE_SIGNER]), deployer.address)).to.equal(null);
    expect(safeRefusal(SAFE, safeFacts([SAFE_SIGNER], SAFE_V141.singleton), deployer.address)).to.equal(null);
    expect(safeRefusal(deployer.address, null, deployer.address)).to.match(/is the deployer/);
    expect(safeRefusal(SAFE, null, deployer.address)).to.match(/No Safe/);
    expect(safeRefusal(SAFE, safeFacts([SAFE_SIGNER], RELAYER), deployer.address)).to.match(/not a Safe v1.4.1/);

    // Through the deploy, before anything is sent.
    const nonce = await ethers.provider.getTransactionCount(deployer.address);
    const refused = async (env: NodeJS.ProcessEnv, o: Partial<Parameters<typeof deployHandleAnchor>[0]>, pattern: RegExp) => {
      let error: Error | undefined;
      try {
        await run(env, o);
      } catch (e) {
        error = e as Error;
      }
      expect(error?.message).to.match(pattern);
    };
    await refused({}, {}, /HANDLE_REGISTRAR_ADDRESS is required/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: deployer.address }, {}, /is the deployer/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: RELAYER }, {}, /plane's relayer/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { safe: deployer.address }, /is the deployer/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { readSafe: async () => null }, /No Safe/);
    const counter = await (await ethers.getContractFactory('MockCounter', deployer)).deploy();
    await counter.waitForDeployment();
    const afterCounter = await ethers.provider.getTransactionCount(deployer.address);
    expect(afterCounter).to.equal(nonce + 1);
    await refused({ HANDLE_REGISTRAR_ADDRESS: await counter.getAddress() }, {}, /has code/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { recordedAnchor: RELAYER }, /HANDLE_ANCHOR_REDEPLOY=1/);
    await refused({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR, HANDLE_FREEZE_SECONDS: '0' }, {}, /never 0/);
    expect(await ethers.provider.getTransactionCount(deployer.address)).to.equal(afterCounter);
  });

  it('replaces a recorded anchor only with HANDLE_ANCHOR_REDEPLOY=1, and a dry run sends nothing', async function () {
    const nonce = await ethers.provider.getTransactionCount(deployer.address);
    expect(await run({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR }, { dryRun: true })).to.equal(null);
    expect(await ethers.provider.getTransactionCount(deployer.address)).to.equal(nonce);
    const d = await run({ HANDLE_REGISTRAR_ADDRESS: REGISTRAR, HANDLE_ANCHOR_REDEPLOY: '1' }, { recordedAnchor: RELAYER });
    expect(d?.address).to.match(/^0x/);
  });
});
