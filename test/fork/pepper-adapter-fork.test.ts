import { expect } from 'chai';
import { ethers, network } from 'hardhat';
import type { CofferdamZKPassportPepperAdapter, IZKPassportRootVerifierState, IZKPassportSubVerifier } from '../../typechain-types';

import {
  ZKP_DOMAIN,
  ZKP_GLOBAL_OPRF_KEY_HASH,
  ZKP_OUTER_VERIFIERS_0_23_0,
  ZKP_ROOT_VERIFIER,
  encodeZkpEvidence,
  zkpBindSection,
  zkpCircuitsVersion,
  zkpCustomData,
  zkpExpirySection,
  zkpParamCommitment,
  zkpScopeHash,
  zkpSection,
} from '../../scripts/lib/identity';

// Decision 0080, the pepper: CofferdamZKPassportPepperAdapter against
// ZKPassport's live contracts for circuits 0.23.0, on a fork of Base mainnet
// that keeps chain id 8453. Read-only: it deploys the adapter on the local
// fork and sends nothing to Base.
//
//   yarn test:fork          (BASE_FORK=1; BASE_RPC_URL, default mainnet.base.org)
//
// No real proof salted under a Cofferdam key exists yet (the fork spike of
// 0080's build order, step 1), so this shows that the adapter's own checks
// pass on live roots and encodings and that the call reaches the pinned outer
// verifier, which refuses a forged proof. Every test skips unless the network
// is chain 8453.

const V23 = zkpCircuitsVersion('0.23.0');
const SCOPE = 'cofferdam-pepper-fork-test';
const TEST_KEY = ethers.id('a throwaway key hash, never a real pepper');
const DAY = 24 * 3600;

describe('The pepper adapter on a fork of Base mainnet (chain 8453)', function () {
  this.timeout(600_000);

  let root: IZKPassportRootVerifierState;
  let sub: IZKPassportSubVerifier;

  before(async function () {
    if ((await ethers.provider.getNetwork()).chainId !== 8453n) this.skip();
    await network.provider.send('hardhat_mine', ['0x1']);
    root = (await ethers.getContractAt('IZKPassportRootVerifierState', ZKP_ROOT_VERIFIER)) as unknown as IZKPassportRootVerifierState;
    let subAddress = await root.getSubVerifier(V23);
    if (subAddress === ethers.ZeroAddress) {
      // zkpassport-fork.test.ts pins the fork at an older proof's block when
      // ZKP_PARAMS_FILE is set, before 0.23.0 was registered: move it back to
      // the latest block. A fork pinned on purpose (BASE_FORK_BLOCK) fails here.
      if (process.env.BASE_FORK_BLOCK?.trim()) throw new Error('BASE_FORK_BLOCK is before circuits 0.23.0 was registered');
      const rpc = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
      await network.provider.request({ method: 'hardhat_reset', params: [{ forking: { jsonRpcUrl: rpc } }] });
      await network.provider.send('hardhat_mine', ['0x1']);
      subAddress = await root.getSubVerifier(V23);
      if (subAddress === ethers.ZeroAddress) throw new Error('No sub-verifier for circuits 0.23.0 on Base mainnet');
    }
    sub = (await ethers.getContractAt('IZKPassportSubVerifier', subAddress)) as unknown as IZKPassportSubVerifier;
  });

  async function deployAdapter(o: { key?: string; pins?: [string, string][] } = {}) {
    const pins = o.pins ?? Object.entries(ZKP_OUTER_VERIFIERS_0_23_0);
    return (await (await ethers.getContractFactory('CofferdamZKPassportPepperAdapter')).deploy(
      ZKP_ROOT_VERIFIER,
      await root.getHelper(V23),
      V23,
      SCOPE,
      3600,
      o.key ?? TEST_KEY,
      18,
      30 * DAY,
      pins.map(([h]) => h),
      pins.map(([, v]) => v),
    )) as unknown as CofferdamZKPassportPepperAdapter;
  }

  it("0.23.0's sub-verifier lists every pinned outer verifier, and holds ZKPassport's global key", async () => {
    expect(await sub.rootVerifier()).to.equal(ZKP_ROOT_VERIFIER);
    expect(await sub.globalOPRFPubKeyHash()).to.equal(ZKP_GLOBAL_OPRF_KEY_HASH);
    for (const [vkeyHash, verifier] of Object.entries(ZKP_OUTER_VERIFIERS_0_23_0)) {
      expect(await sub.proofVerifiers(vkeyHash)).to.equal(verifier);
      expect(await ethers.provider.getCode(verifier)).to.not.equal('0x');
    }
    // The 0.23.0 helper the adapter pins answers only for the exact committed lower bound, and decodes the bind section.
    const h = await ethers.getContractAt('IZKPassportHelper', await root.getHelper(V23));
    expect(await h.isAgeAboveOrEqual(18, '0x0100021200')).to.equal(true);
    expect(await h.isAgeAboveOrEqual(18, '0x0100021300')).to.equal(false);
    const expiry = (t: bigint) => ethers.hexlify(zkpExpirySection(t));
    expect(await h.isExpiryDateAfterOrEqual(1_900_000_000n, expiry(1_900_000_000n))).to.equal(true);
    expect(await h.isExpiryDateAfterOrEqual(1_900_000_000n, expiry(1_900_000_001n))).to.equal(false);
    const [account] = await ethers.getSigners();
    const custom = zkpCustomData(ethers.id('any digest'));
    const bound = await h.getBoundData(ethers.hexlify(zkpBindSection({ userAddress: account.address, chainId: 8453n, customData: custom })));
    expect([bound.senderAddress, bound.chainId, bound.customData]).to.deep.equal([account.address, 8453n, custom]);
  });

  it("deploys with all twelve pins, and refuses ZKPassport's global key", async () => {
    const adapter = await deployAdapter();
    expect(await adapter.vkeyHashes()).to.have.length(12);
    const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
    await expect(deployAdapter({ key: ZKP_GLOBAL_OPRF_KEY_HASH })).to.be.revertedWithCustomError(F, 'GlobalOprfKeyRefused');
  });

  it('a forged proof passes every check of the adapter and is refused by the outer verifier', async () => {
    const adapter = await deployAdapter();
    const [, account] = await ethers.getSigners();
    const digest = ethers.id('any digest');
    const now = (await ethers.provider.getBlock('latest'))!.timestamp;
    const registry = await ethers.getContractAt(
      ['function latestRoot(bytes32) view returns (bytes32)'],
      await root.rootRegistry(),
    );
    const sections = [
      zkpSection(1, [18, 0]),
      zkpExpirySection(BigInt(now + 365 * DAY)),
      zkpBindSection({ userAddress: account.address, chainId: 8453n, customData: zkpCustomData(digest) }),
    ];
    const publicInputs = [
      await registry.latestRoot(ethers.toBeHex(1, 32)),
      await registry.latestRoot(ethers.toBeHex(2, 32)),
      ethers.toBeHex(now, 32),
      zkpScopeHash(ZKP_DOMAIN),
      zkpScopeHash(SCOPE),
      ...sections.map((s) => zkpParamCommitment(s)),
      ethers.toBeHex(1, 32),
      ethers.id('not a real identifier'),
      TEST_KEY,
      ethers.toBeHex(100, 32),
    ];
    const [vkeyHash] = Object.keys(ZKP_OUTER_VERIFIERS_0_23_0);
    const ev = (proof: Uint8Array, vk = vkeyHash) =>
      encodeZkpEvidence({ vkeyHash: vk, proof, publicInputs, committedInputs: ethers.concat(sections) });

    // A vkey hash it did not pin stops before the verifier, with the adapter's own error.
    await expect(adapter.verify(account.address, digest, ev(ethers.randomBytes(64), ethers.id('unpinned')))).to.be.revertedWithCustomError(
      adapter,
      'UnknownVerificationKey',
    );

    // With a pinned one, every earlier check passes (live roots, scopes,
    // commitments, pauses, the helper) and the outer verifier answers: it
    // refuses the proof with an error of its own, or returns false.
    let data = '';
    try {
      await adapter.verify(account.address, digest, ev(ethers.randomBytes(64)));
    } catch (e) {
      data = ((e as { data?: string }).data ?? '') as string;
    }
    // The UltraHonk verifier's errors (Barretenberg's generated Solidity verifier), and the adapter's
    // ProofInvalid when the verifier returns false. 2026-11-19: ProofLengthWrongWithLogN for 64 random bytes.
    const answers = [
      'ProofLengthWrong()',
      'ProofLengthWrongWithLogN(uint256,uint256,uint256)',
      'PublicInputsLengthWrong()',
      'SumcheckFailed()',
      'ShpleminiFailed()',
      'ConsistencyCheckFailed()',
      'GeminiChallengeInSubgroup()',
    ].map((s) => ethers.id(s).slice(0, 10));
    answers.push(adapter.interface.getError('ProofInvalid')!.selector);
    expect(answers, `stopped before the verifier: ${data.slice(0, 10)}`).to.include(data.slice(0, 10));
    console.log(`      the outer verifier refused the forged proof (revert selector ${data.slice(0, 10)})`);

    // ZKPassport's own path refuses the same inputs at the key check, which
    // runs after roots, date, scopes, commitments and the method and before
    // the proof (SubVerifier.sol:385-386): why this adapter exists. Under
    // ZKPassport's global key it goes on to the verifier.
    const live = await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER);
    const params = (key: string) => ({
      version: V23,
      proofVerificationData: {
        vkeyHash,
        proof: ethers.randomBytes(64),
        publicInputs: [...publicInputs.slice(0, -2), key, publicInputs[publicInputs.length - 1]],
      },
      committedInputs: ethers.concat(sections),
      serviceConfig: { validityPeriodInSeconds: 3600, domain: ZKP_DOMAIN, scope: SCOPE, devMode: false },
    });
    await expect(live.verify(params(TEST_KEY))).to.be.revertedWith('Invalid OPRF public key');
    await expect(live.verify(params(ZKP_GLOBAL_OPRF_KEY_HASH))).to.be.revertedWithCustomError(
      { interface: new ethers.Interface(['error ProofLengthWrongWithLogN(uint256,uint256,uint256)']) },
      'ProofLengthWrongWithLogN',
    );
  });
});
