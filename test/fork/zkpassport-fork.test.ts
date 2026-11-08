import { expect } from 'chai';
import * as fs from 'fs';
import { ethers, network } from 'hardhat';
import type { IZKPassportRootVerifier } from '../../typechain-types';

import { refuseMainnet } from '../../scripts/lib/chain';
import { deploymentsPath } from '../../scripts/lib/deployments';
import { refuseMainnetPaymaster } from '../../scripts/lib/paymaster';
import {
  IDENTITY_ACTIONS,
  ZKP_IDENTIFIER_TYPE,
  ZKP_ROOT_VERIFIER,
  encodeZkpEvidence,
  zkpCircuitsVersion,
  zkpExpirySection,
  zkpIdentifierKind,
  zkpScopeId,
} from '../../scripts/lib/identity';

// Decision 0080, M1: the identity registry against ZKPassport's live
// RootVerifier on a fork of Base mainnet that keeps chain id 8453.
//
//   yarn test:fork                      (BASE_FORK=1; BASE_RPC_URL, default mainnet.base.org)
//   ZKP_PARAMS_FILE=/path/params.json yarn test:fork
//
// ZKP_PARAMS_FILE is a compressed-EVM proof as SDK 0.19.3's
// getSolidityVerifierParameters returns it, kept OUTSIDE this repository: a
// real proof carries a person's identifier and must never enter git (decision
// 0080, D2). The test prints no field of it. Without it the real-proof cases
// are skipped. Every test skips unless the network is chain 8453.

const VERSION_0_21_1 = zkpCircuitsVersion('0.21.1');
const DAY = 24 * 3600;
const RPC = process.env.BASE_RPC_URL || 'https://mainnet.base.org';

type SolidityParams = {
  version: string;
  proofVerificationData: { vkeyHash: string; proof: string; publicInputs: string[] };
  committedInputs: string;
  serviceConfig: { validityPeriodInSeconds: number; domain: string; scope: string; devMode: boolean };
};

function evidenceOf(p: SolidityParams, committedInputs = p.committedInputs): string {
  return encodeZkpEvidence({ ...p.proofVerificationData, committedInputs });
}

describe('ZKPassport on a fork of Base mainnet (chain 8453)', function () {
  this.timeout(600_000);

  before(async function () {
    if ((await ethers.provider.getNetwork()).chainId !== 8453n) this.skip();
    // EDR treats calls at the fork block itself as historical and wants a
    // hardfork for it; one mined block puts every call on the configured one.
    await network.provider.send('hardhat_mine', ['0x1']);
  });

  /** The revert came from the adapter's section screening, which runs only after the verifier accepted the proof. */
  function screened(adapter: { interface: { getError(name: string): { selector: string } | null } }, reason: string): boolean {
    return ['DisclosureRefused', 'BindSectionCount'].some((e) => reason.includes(e) || reason.includes(adapter.interface.getError(e)!.selector));
  }

  async function rejection(p: Promise<unknown>): Promise<string> {
    try {
      await p;
    } catch (e) {
      return (e as Error).message;
    }
    return '';
  }

  async function deployAdapter(
    o: { root?: string; version?: string; scope?: string; type?: number; minAge?: number; expiryMargin?: number } = {},
  ) {
    const version = o.version ?? VERSION_0_21_1;
    const live = (await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER)) as unknown as IZKPassportRootVerifier;
    return (await ethers.getContractFactory('ZKPassportEvidenceAdapter')).deploy(
      o.root ?? ZKP_ROOT_VERIFIER,
      await live.getHelper(version),
      version,
      o.scope ?? 'cofferdam-zkp-test-1',
      3600,
      o.type ?? ZKP_IDENTIFIER_TYPE.nonSalted,
      ethers.ZeroHash,
      o.minAge ?? 18,
      o.expiryMargin ?? 30 * DAY,
    );
  }

  async function deployRegistry(adapter: string, scope: string, delays = 3 * DAY) {
    const [owner] = await ethers.getSigners();
    const kind = await (await ethers.getContractAt('ZKPassportEvidenceAdapter', adapter)).identifierKind();
    return (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
      owner.address,
      kind,
      zkpScopeId(scope),
      delays,
      delays,
      [adapter],
      false,
      [],
    );
  }

  it("ZKPassport's RootVerifier and its 0.21.1 helper are live", async () => {
    expect(await ethers.provider.getCode(ZKP_ROOT_VERIFIER)).to.not.equal('0x');
    const root = (await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER)) as unknown as IZKPassportRootVerifier;
    const helper = await root.getHelper(VERSION_0_21_1);
    expect(helper).to.not.equal(ethers.ZeroAddress);
    // The deployed helper answers only for the exact committed bound.
    const h = await ethers.getContractAt('IZKPassportHelper', helper);
    expect(await h.isAgeAboveOrEqual(18, '0x0100021200')).to.equal(true);
    expect(await h.isAgeAboveOrEqual(18, '0x0100021300')).to.equal(false);
    const expiry = (t: bigint) => ethers.hexlify(zkpExpirySection(t));
    expect(await h.isExpiryDateAfterOrEqual(1_900_000_000n, expiry(1_900_000_000n))).to.equal(true);
    expect(await h.isExpiryDateAfterOrEqual(1_900_000_000n, expiry(1_900_000_001n))).to.equal(false);
  });

  it('the registry refuses delays under 72 hours on chain 8453', async () => {
    const adapter = await deployAdapter();
    const F = await ethers.getContractFactory('CofferdamIdentityRegistry');
    const [owner] = await ethers.getSigners();
    const base = [owner.address, zkpIdentifierKind(0), zkpScopeId('cofferdam-zkp-test-1')] as const;
    await expect(F.deploy(...base, 0, 3 * DAY, [], false, [])).to.be.revertedWithCustomError(F, 'DelayTooShort');
    await expect(F.deploy(...base, 3 * DAY, 3 * DAY - 1, [], false, [])).to.be.revertedWithCustomError(F, 'DelayTooShort');
    await expect(F.deploy(...base, 3 * DAY, 3 * DAY, [await adapter.getAddress()], false, [])).to.not.be.reverted;
  });

  it('the adapter refuses any RootVerifier but the canonical one on chain 8453', async () => {
    const [, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory('ZKPassportEvidenceAdapter');
    await expect(deployAdapter({ root: other.address })).to.be.revertedWithCustomError(F, 'NotCanonicalVerifier');
  });

  it('the deploy guards see chain 8453: Self, escrow and the paymaster refuse; deployments want a GENERATION', async () => {
    expect(await rejection(refuseMainnet('test'))).to.contain('never deploys to Base mainnet');
    expect(await rejection(refuseMainnetPaymaster())).to.contain('never deploys to Base mainnet');
    const saved = process.env.GENERATION;
    try {
      delete process.env.GENERATION;
      expect(() => deploymentsPath(network.name, 8453n)).to.throw('set GENERATION');
      process.env.GENERATION = 'zkp-test-1';
      expect(deploymentsPath(network.name, 8453n)).to.match(/deployments\/hardhat\.zkp-test-1\.json$/);
      expect(deploymentsPath('baseSepolia', 84532n)).to.match(/deployments\/baseSepolia\.json$/);
    } finally {
      if (saved === undefined) delete process.env.GENERATION;
      else process.env.GENERATION = saved;
    }
  });

  it('a forged proof fails against the live verifier, through the registry', async () => {
    const adapter = await deployAdapter();
    const registry = await deployRegistry(await adapter.getAddress(), 'cofferdam-zkp-test-1');
    const [, account] = await ethers.getSigners();
    const publicInputs = Array.from({ length: 9 }, (_, i) => ethers.toBeHex(i === 2 ? Math.floor(Date.now() / 1000) : 0, 32));
    const forged = encodeZkpEvidence({
      vkeyHash: ethers.id('forged'),
      proof: ethers.randomBytes(512),
      publicInputs,
      committedInputs: '0x',
    });
    await expect((registry.connect(account) as typeof registry).bind(adapter, forged)).to.be.reverted;
    expect(await registry.isAccountBound(account.address)).to.equal(false);
  });

  describe("a real proof from ZKPassport's app (ZKP_PARAMS_FILE)", function () {
    let params: SolidityParams;

    before(async function () {
      const file = process.env.ZKP_PARAMS_FILE;
      if (!file) return this.skip();
      params = JSON.parse(fs.readFileSync(file, 'utf8'));
      // Pin the fork just after the proof's date, so its validity holds.
      const proofDate = Number(BigInt(params.proofVerificationData.publicInputs[2]));
      const upstream = new ethers.JsonRpcProvider(RPC);
      // The first block at least two minutes after the proof's date.
      const target = proofDate + 120;
      let lo = 0;
      let hi = (await upstream.getBlock('latest'))!.number;
      while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        if ((await upstream.getBlock(mid))!.timestamp < target) lo = mid + 1;
        else hi = mid;
      }
      const blockNumber = lo;
      const block = await upstream.getBlock(blockNumber);
      if (!block || block.timestamp < proofDate || block.timestamp > proofDate + 600) {
        throw new Error('Could not find a Base block just after the proof date');
      }
      await network.provider.request({ method: 'hardhat_reset', params: [{ forking: { jsonRpcUrl: RPC, blockNumber } }] });
      await network.provider.send('hardhat_mine', ['0x1']);
      console.log(`      fork pinned at block ${blockNumber}, ${block.timestamp - proofDate} s after the proof`);
    });

    it('RootVerifier.verify accepts it with its own configuration', async () => {
      const root = (await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER)) as unknown as IZKPassportRootVerifier;
      const p = { ...params, serviceConfig: { ...params.serviceConfig, validityPeriodInSeconds: 3600, devMode: false } };
      const [valid] = await root.verify(p);
      expect(valid).to.equal(true);
      console.log(`      RootVerifier.verify gas: ${await root.verify.estimateGas(p)}`);
    });

    it('the service configuration is checked: another scope fails', async () => {
      const root = (await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER)) as unknown as IZKPassportRootVerifier;
      const p = { ...params, serviceConfig: { ...params.serviceConfig, scope: 'another-scope', validityPeriodInSeconds: 3600 } };
      let valid = false;
      try {
        [valid] = await root.verify(p);
      } catch {
        valid = false;
      }
      expect(valid).to.equal(false);
    });

    it('through the adapter it passes the verifier and stops at the screening after it', async () => {
      // The founder's proof of 2026-11-07 discloses nationality and has no
      // bind section, so it can never bind: reaching the section screening
      // (which runs after RootVerifier.verify and the pinned-helper check)
      // means the verifier, the identifier type and the helper checks passed.
      const pi = params.proofVerificationData.publicInputs;
      const adapter = await deployAdapter({
        version: params.version,
        scope: params.serviceConfig.scope,
        type: Number(BigInt(pi[pi.length - 3])),
        minAge: 0,
        expiryMargin: 0,
      });
      const [, account] = await ethers.getSigners();
      const digest = ethers.id('any digest');
      const reason = await rejection(adapter.verify(account.address, digest, evidenceOf(params)));
      expect(screened(adapter, reason)).to.equal(true);
    });

    it('a tampered committed input fails the verifier', async () => {
      const pi = params.proofVerificationData.publicInputs;
      const adapter = await deployAdapter({
        version: params.version,
        scope: params.serviceConfig.scope,
        type: Number(BigInt(pi[pi.length - 3])),
        minAge: 0,
        expiryMargin: 0,
      });
      const ci = ethers.getBytes(params.committedInputs);
      ci[ci.length - 1] ^= 0x01;
      const [, account] = await ethers.getSigners();
      const reason = await rejection(adapter.verify(account.address, ethers.ZeroHash, evidenceOf(params, ethers.hexlify(ci))));
      expect(reason).to.not.equal('');
      expect(screened(adapter, reason)).to.equal(false);
    });

    it('the registry refuses it: unbound proofs never bind', async () => {
      const pi = params.proofVerificationData.publicInputs;
      const adapter = await deployAdapter({
        version: params.version,
        scope: params.serviceConfig.scope,
        type: Number(BigInt(pi[pi.length - 3])),
        minAge: 0,
        expiryMargin: 0,
      });
      const registry = await deployRegistry(await adapter.getAddress(), params.serviceConfig.scope);
      const [, account] = await ethers.getSigners();
      const reason = await rejection(registry.check(IDENTITY_ACTIONS.bind, account.address, adapter, evidenceOf(params)));
      expect(screened(adapter, reason)).to.equal(true);
    });
  });
});
