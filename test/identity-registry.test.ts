import { expect } from 'chai';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';
import { ethers } from 'hardhat';
import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import type {
  CofferdamIdentityRegistry,
  MockZKPassportHelper,
  MockZKPassportRootVerifier,
  ZKPassportEvidenceAdapter,
} from '../typechain-types';

import fixture from './fixtures/identity-digest.json';
import { NO_PERMISSION, webauthnKey } from './helpers/keys';
import {
  IDENTITY_ACTIONS,
  IdentityAction,
  ZKP_DOMAIN,
  ZKP_IDENTIFIER_TYPE,
  encodeZkpEvidence,
  identityDigest,
  zkpBindSection,
  zkpCircuitsVersion,
  zkpCustomData,
  zkpExpirySection,
  zkpIdentifierKind,
  zkpScopeId,
  zkpSection,
} from '../scripts/lib/identity';

// Unit tests of CofferdamIdentityRegistry and ZKPassportEvidenceAdapter
// (decision 0080) on mock ZKPassport contracts. The real RootVerifier runs in
// test/fork/zkpassport-fork.test.ts on a fork of Base mainnet.

const VERSION = zkpCircuitsVersion('0.21.1');
const SCOPE = 'cofferdam-zkp-test-1';
const VALIDITY = 3600;
const MIN_AGE = 18;
const MOCK_PROOF = ethers.toUtf8Bytes('mock-zkpassport-proof');
const ZERO32 = ethers.ZeroHash;
const ID_A = ethers.id('passport-a');
const ID_B = ethers.id('passport-b');
const OPRF = ethers.id('oprf-key-1');
const DAY = 24 * 3600;
const EXPIRY_MARGIN = 30 * DAY;

type EvidenceOptions = {
  account?: string;
  action?: IdentityAction;
  digest?: string;
  identifier?: string;
  identifierType?: number;
  oprf?: string;
  /** The verification method a circuits 0.23.0 proof ends with; undefined: none (before 0.23.0). */
  method?: number;
  chainId?: bigint;
  age?: number;
  /** The proof's lower bound on the document's expiry; default bind time + 1 year. null: no expiry section. */
  expiry?: bigint | null;
  extra?: Uint8Array[];
  date?: number;
  proof?: Uint8Array;
  tamper?: boolean;
  noBind?: boolean;
};

describe('CofferdamIdentityRegistry + ZKPassportEvidenceAdapter', () => {
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner;
  let bob: HardhatEthersSigner;
  let carol: HardhatEthersSigner;
  let chainId: bigint;

  beforeEach(async () => {
    [owner, alice, bob, carol] = await ethers.getSigners();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  async function deployMocks() {
    const helper = (await (await ethers.getContractFactory('MockZKPassportHelper')).deploy()) as unknown as MockZKPassportHelper;
    const root = (await (await ethers.getContractFactory('MockZKPassportRootVerifier')).deploy()) as unknown as MockZKPassportRootVerifier;
    await root.setHelper(VERSION, await helper.getAddress());
    await root.setExpected(VERSION, VALIDITY, ZKP_DOMAIN, SCOPE, false);
    return { helper, root };
  }

  async function deployAdapter(
    root: string,
    o: { type?: number; oprf?: string; scope?: string; minAge?: number; expiryMargin?: number } = {},
  ) {
    const helper = await (
      (await ethers.getContractAt('MockZKPassportRootVerifier', root)) as unknown as MockZKPassportRootVerifier
    ).getHelper(VERSION);
    return (await (await ethers.getContractFactory('ZKPassportEvidenceAdapter')).deploy(
      root,
      helper,
      VERSION,
      o.scope ?? SCOPE,
      VALIDITY,
      o.type ?? ZKP_IDENTIFIER_TYPE.nonSalted,
      o.oprf ?? ZERO32,
      o.minAge ?? MIN_AGE,
      o.expiryMargin ?? EXPIRY_MARGIN,
    )) as unknown as ZKPassportEvidenceAdapter;
  }

  async function deploy(o: { rebindDelay?: number; adapterDelay?: number; allowlistOnly?: boolean; testAccounts?: string[] } = {}) {
    const { helper, root } = await deployMocks();
    const adapter = await deployAdapter(await root.getAddress());
    const registry = (await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
      owner.address,
      zkpIdentifierKind(ZKP_IDENTIFIER_TYPE.nonSalted),
      zkpScopeId(SCOPE),
      o.rebindDelay ?? 0,
      o.adapterDelay ?? 0,
      [await adapter.getAddress()],
      o.allowlistOnly ?? false,
      o.testAccounts ?? [],
    )) as unknown as CofferdamIdentityRegistry;
    return { helper, root, adapter, registry };
  }

  type Deployed = Awaited<ReturnType<typeof deploy>>;

  /** Evidence the mocks accept for `account` and the registry's current digest of `action`. */
  async function evidence(d: Deployed, o: EvidenceOptions = {}): Promise<string> {
    const account = o.account ?? alice.address;
    const digest = o.digest ?? (await d.registry.digest(IDENTITY_ACTIONS[o.action ?? 'bind'], account));
    const now = await time.latest();
    const expiry = o.expiry === undefined ? BigInt(now + 365 * DAY) : o.expiry;
    const sections: Uint8Array[] = [zkpSection(1, [o.age ?? 18, 0]), ...(o.extra ?? [])];
    if (expiry !== null) sections.push(zkpExpirySection(expiry));
    if (!o.noBind) {
      sections.push(zkpBindSection({ userAddress: account, chainId: o.chainId ?? chainId, customData: zkpCustomData(digest) }));
    }
    const ci = ethers.concat(sections);
    const date = o.date ?? now;
    const publicInputs = [
      ethers.id('certificate-root'),
      ethers.id('circuit-root'),
      ethers.toBeHex(date, 32),
      ethers.id('scope'),
      ethers.id('subscope'),
      ethers.keccak256(ci),
      ethers.toBeHex(o.identifierType ?? ZKP_IDENTIFIER_TYPE.nonSalted, 32),
      o.identifier ?? ID_A,
      o.oprf ?? ZERO32,
      ...(o.method === undefined ? [] : [ethers.toBeHex(o.method, 32)]),
    ];
    return encodeZkpEvidence({
      vkeyHash: ethers.id('vkey'),
      proof: o.proof ?? MOCK_PROOF,
      publicInputs,
      committedInputs: o.tamper ? ethers.concat([ci, '0x00']) : ci,
    });
  }

  describe('digest and custom_data', () => {
    it('matches the shared fixture (computed independently with viem)', async () => {
      for (const v of fixture.vectors) {
        const d = identityDigest(v.action as IdentityAction, BigInt(v.chainId), v.registry, v.account, BigInt(v.nonce));
        expect(d).to.equal(v.digest);
        expect(zkpCustomData(d)).to.equal(v.customData);
        expect(ethers.id(fixture.tags[v.action as IdentityAction])).to.equal(IDENTITY_ACTIONS[v.action as IdentityAction]);
      }
    });

    it('the contract computes the same digest and custom_data', async () => {
      const d = await deploy();
      const registry = await d.registry.getAddress();
      for (const action of ['bind', 'rebind', 'relink'] as IdentityAction[]) {
        const onChain = await d.registry.digest(IDENTITY_ACTIONS[action], alice.address);
        expect(onChain).to.equal(identityDigest(action, chainId, registry, alice.address, 0n));
        expect(await d.adapter.customData(onChain)).to.equal(zkpCustomData(onChain));
      }
      expect(await d.registry.BIND()).to.equal(IDENTITY_ACTIONS.bind);
      expect(await d.registry.REBIND()).to.equal(IDENTITY_ACTIONS.rebind);
      expect(await d.registry.RELINK()).to.equal(IDENTITY_ACTIONS.relink);
    });

    it('pins kind and scope as the TypeScript helpers compute them', async () => {
      const d = await deploy();
      expect(await d.adapter.identifierKind()).to.equal(zkpIdentifierKind(0));
      expect(await d.adapter.scopeId()).to.equal(zkpScopeId(SCOPE));
      expect(await d.adapter.scope()).to.equal(SCOPE);
      expect(await d.adapter.DOMAIN()).to.equal('cofferdam.xyz');
      expect(await d.adapter.DEV_MODE()).to.equal(false);
    });
  });

  describe('bind', () => {
    it('binds the calling account, consumes its nonce and answers isAccountBound', async () => {
      const d = await deploy();
      const ev = await evidence(d);
      await expect(d.registry.connect(alice).bind(d.adapter, ev))
        .to.emit(d.registry, 'Bound')
        .withArgs(alice.address, ID_A, await d.adapter.getAddress(), 0n);
      expect(await d.registry.isAccountBound(alice.address)).to.equal(true);
      expect(await d.registry.isIdentifierBound(ID_A)).to.equal(true);
      expect(await d.registry.identifierToAccount(ID_A)).to.equal(alice.address);
      expect(await d.registry.accountToIdentifier(alice.address)).to.equal(ID_A);
      expect(await d.registry.nonces(alice.address)).to.equal(1n);
    });

    it('refuses a proof made for another account, even when sent by that account', async () => {
      const d = await deploy();
      const ev = await evidence(d, { account: alice.address });
      // Bob submits Alice's proof: the digest is Bob's, the bound address Alice's.
      await expect(d.registry.connect(bob).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'WrongBoundAccount');
    });

    it('refuses a proof bound to another chain', async () => {
      const d = await deploy();
      const ev = await evidence(d, { chainId: 8453n + (chainId === 8453n ? 1n : 0n) });
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'WrongBoundChain');
    });

    it('refuses a proof bound to another action, nonce or registry', async () => {
      const d = await deploy();
      const other = await deploy();
      const wrong = [
        await evidence(d, { action: 'rebind' }),
        await evidence(d, { digest: identityDigest('bind', chainId, await d.registry.getAddress(), alice.address, 1n) }),
        await evidence(d, { digest: await other.registry.digest(IDENTITY_ACTIONS.bind, alice.address) }),
      ];
      for (const ev of wrong) {
        await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'WrongBoundDigest');
      }
    });

    it('a used proof never replays: its nonce is consumed', async () => {
      const d = await deploy();
      const ev = await evidence(d);
      await d.registry.connect(alice).bind(d.adapter, ev);
      // Free Alice again (her identifier moves to Bob), then replay her bind proof.
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      expect(await d.registry.isAccountBound(alice.address)).to.equal(false);
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'WrongBoundDigest');
    });

    it('refuses a proof without bound data', async () => {
      const d = await deploy();
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { noBind: true })))
        .to.be.revertedWithCustomError(d.adapter, 'BindSectionCount')
        .withArgs(0);
    });

    it('refuses a second bind section', async () => {
      const d = await deploy();
      const digest = await d.registry.digest(IDENTITY_ACTIONS.bind, alice.address);
      const decoy = zkpBindSection({ userAddress: alice.address, chainId, customData: zkpCustomData(digest) });
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { extra: [decoy] })))
        .to.be.revertedWithCustomError(d.adapter, 'BindSectionCount')
        .withArgs(2);
    });

    it('one identifier per account and one account per identifier', async () => {
      const d = await deploy();
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address })))
        .to.be.revertedWithCustomError(d.registry, 'IdentifierAlreadyBound')
        .withArgs(ID_A, alice.address);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { identifier: ID_B })))
        .to.be.revertedWithCustomError(d.registry, 'AccountAlreadyBound')
        .withArgs(alice.address, ID_A);
    });

    it('never binds identifier 0', async () => {
      const d = await deploy();
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { identifier: ZERO32 }))).to.be.revertedWithCustomError(
        d.registry,
        'ZeroIdentifier',
      );
    });
  });

  describe('ZKPassport adapter', () => {
    it('refuses the mock identifier types and none', async () => {
      const d = await deploy();
      for (const t of [ZKP_IDENTIFIER_TYPE.salted, ZKP_IDENTIFIER_TYPE.nonSaltedMock, ZKP_IDENTIFIER_TYPE.saltedMock, ZKP_IDENTIFIER_TYPE.none]) {
        await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { identifierType: t })))
          .to.be.revertedWithCustomError(d.adapter, 'WrongIdentifierType')
          .withArgs(0, t);
      }
    });

    it('cannot be built for a mock type, devMode or a salted type without its OPRF key', async () => {
      const { root } = await deployMocks();
      const F = await ethers.getContractFactory('ZKPassportEvidenceAdapter');
      const rootAddr = await root.getAddress();
      const H = await root.getHelper(VERSION);
      const M = EXPIRY_MARGIN;
      await expect(F.deploy(rootAddr, alice.address, VERSION, SCOPE, VALIDITY, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(
        F,
        'HelperMismatch',
      );
      for (const t of [2, 3, 4]) {
        await expect(F.deploy(rootAddr, H, VERSION, SCOPE, VALIDITY, t, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'BadIdentifierType');
      }
      await expect(F.deploy(rootAddr, H, VERSION, SCOPE, VALIDITY, 1, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'BadOprfKeyHash');
      await expect(F.deploy(rootAddr, H, VERSION, SCOPE, VALIDITY, 0, OPRF, 18, M)).to.be.revertedWithCustomError(F, 'BadOprfKeyHash');
      await expect(F.deploy(rootAddr, H, VERSION, SCOPE, 0, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'BadValidity');
      await expect(F.deploy(rootAddr, H, VERSION, SCOPE, DAY + 1, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'BadValidity');
      await expect(F.deploy(rootAddr, H, ZERO32, SCOPE, VALIDITY, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'ZeroVersion');
      await expect(F.deploy(rootAddr, H, VERSION, '', VALIDITY, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'EmptyScope');
      await expect(F.deploy(ethers.ZeroAddress, H, VERSION, SCOPE, VALIDITY, 0, ZERO32, 18, M)).to.be.revertedWithCustomError(F, 'ZeroAddress');
      await expect(F.deploy(rootAddr, H, VERSION, SCOPE, VALIDITY, 0, ZERO32, 18, 5 * 365 * DAY + 1)).to.be.revertedWithCustomError(
        F,
        'BadExpiryMargin',
      );
    });

    it('a salted adapter pins its OPRF key, which is part of its kind', async () => {
      const { root } = await deployMocks();
      const adapter = await deployAdapter(await root.getAddress(), { type: ZKP_IDENTIFIER_TYPE.salted, oprf: OPRF });
      expect(await adapter.identifierKind()).to.equal(zkpIdentifierKind(1, OPRF));
      expect(await adapter.identifierKind()).to.not.equal(zkpIdentifierKind(1, ethers.id('oprf-key-2')));
      const registry = (await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
        owner.address,
        zkpIdentifierKind(1, OPRF),
        zkpScopeId(SCOPE),
        0,
        0,
        [await adapter.getAddress()],
        false,
        [],
      )) as unknown as CofferdamIdentityRegistry;
      const d = { registry, adapter } as unknown as Deployed;
      await expect(registry.connect(alice).bind(adapter, await evidence(d, { identifierType: 1, oprf: ethers.id('oprf-key-2') })))
        .to.be.revertedWithCustomError(adapter, 'WrongOprfKey');
      await expect(registry.connect(alice).bind(adapter, await evidence(d, { identifierType: 1, oprf: OPRF }))).to.emit(registry, 'Bound');
    });

    it('sends the pinned version and service configuration, never devMode', async () => {
      const d = await deploy();
      // The mock verifier answers valid only for the configuration it expects.
      await d.root.setExpected(VERSION, VALIDITY, ZKP_DOMAIN, SCOPE, true);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
      await d.root.setExpected(VERSION, VALIDITY, ZKP_DOMAIN, 'another-scope', false);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
      await d.root.setExpected(VERSION, VALIDITY, ZKP_DOMAIN, SCOPE, false);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.emit(d.registry, 'Bound');
    });

    it('refuses an invalid proof, tampered committed inputs and an expired proof', async () => {
      const d = await deploy();
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { proof: ethers.toUtf8Bytes('forged') })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { tamper: true })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
      const old = (await time.latest()) - VALIDITY - 10;
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { date: old })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
    });

    it('only the deployer configures the mock verifier', async () => {
      const d = await deploy();
      await expect(d.root.connect(alice).setHelper(VERSION, alice.address)).to.be.revertedWith('owner');
      await expect(d.root.connect(alice).setExpected(VERSION, VALIDITY, ZKP_DOMAIN, SCOPE, true)).to.be.revertedWith('owner');
    });

    it('pins the helper: a helper swapped by the verifier fails closed', async () => {
      const d = await deploy();
      const pinned = await d.helper.getAddress();
      expect(await d.adapter.HELPER()).to.equal(pinned);
      const other = (await (await ethers.getContractFactory('MockZKPassportHelper')).deploy()) as unknown as MockZKPassportHelper;
      const ev = await evidence(d);
      await d.root.setHelper(VERSION, await other.getAddress());
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'HelperMismatch');
      await d.root.setHelper(VERSION, ethers.ZeroAddress);
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'HelperMismatch');
      await d.root.setHelper(VERSION, pinned);
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.emit(d.registry, 'Bound');
    });

    it('requires the minimum age, as the exact bound the proof commits to', async () => {
      const d = await deploy();
      for (const age of [17, 19]) {
        await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { age })))
          .to.be.revertedWithCustomError(d.adapter, 'AgeNotProven')
          .withArgs(18);
      }
    });

    it('requires the document to stay valid for the expiry margin after the bind', async () => {
      const d = await deploy();
      const soon = BigInt((await time.latest()) + EXPIRY_MARGIN - 60);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { expiry: soon }))).to.be.revertedWithCustomError(
        d.adapter,
        'ExpiryNotProven',
      );
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { expiry: null }))).to.be.revertedWithCustomError(
        d.adapter,
        'ExpiryNotProven',
      );
      // An upper bound on the expiry would let a range close on the date: refused as disclosure.
      const bounded = await evidence(d, { expiry: null, extra: [zkpExpirySection(BigInt((await time.latest()) + 365 * DAY), 1n)] });
      await expect(d.registry.connect(alice).bind(d.adapter, bounded))
        .to.be.revertedWithCustomError(d.adapter, 'DisclosureRefused')
        .withArgs(3);
      const enough = BigInt((await time.latest()) + EXPIRY_MARGIN + 3600);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { expiry: enough }))).to.emit(d.registry, 'Bound');
    });

    it('an adapter with no expiry margin checks none', async () => {
      const { root } = await deployMocks();
      const adapter = await deployAdapter(await root.getAddress(), { expiryMargin: 0 });
      const registry = (await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
        owner.address,
        zkpIdentifierKind(0),
        zkpScopeId(SCOPE),
        0,
        0,
        [await adapter.getAddress()],
        false,
        [],
      )) as unknown as CofferdamIdentityRegistry;
      const d = { registry, adapter } as unknown as Deployed;
      await expect(registry.connect(alice).bind(adapter, await evidence(d, { expiry: null }))).to.emit(registry, 'Bound');
    });

    it('refuses disclosure: document bytes, birth-date range, nationality or issuing-country inclusion, bounded age', async () => {
      const d = await deploy();
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { extra: [zkpSection(1, [18, 18])] })))
        .to.be.revertedWithCustomError(d.adapter, 'DisclosureRefused')
        .withArgs(1);
      for (const t of [0, 2, 4, 6]) {
        await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { extra: [zkpSection(t, [1, 2, 3])] })))
          .to.be.revertedWithCustomError(d.adapter, 'DisclosureRefused')
          .withArgs(t);
      }
      // An exclusion list (sanctions, type 9) is fine.
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { extra: [zkpSection(9, new Array(33).fill(0))] })))
        .to.emit(d.registry, 'Bound');
    });

    it('refuses evidence too short to hold the outer public inputs', async () => {
      const d = await deploy();
      const ev = encodeZkpEvidence({ vkeyHash: ZERO32, proof: MOCK_PROOF, publicInputs: [ZERO32], committedInputs: '0x' });
      await expect(d.registry.connect(alice).bind(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'MalformedEvidence');
    });
  });

  describe('circuits 0.23.0: the verification method (decision 0080, ruling S7)', () => {
    const V23 = zkpCircuitsVersion('0.23.0');

    async function deploy23(o: { type?: number; oprf?: string } = {}) {
      const type = o.type ?? ZKP_IDENTIFIER_TYPE.nonSalted;
      const oprf = o.oprf ?? ZERO32;
      const helper = await (await ethers.getContractFactory('MockZKPassportHelper')).deploy();
      const root = (await (await ethers.getContractFactory('MockZKPassportRootVerifier')).deploy()) as unknown as MockZKPassportRootVerifier;
      await root.setHelper(V23, await helper.getAddress());
      await root.setExpected(V23, VALIDITY, ZKP_DOMAIN, SCOPE, false);
      const adapter = (await (await ethers.getContractFactory('ZKPassportEvidenceAdapter')).deploy(
        await root.getAddress(),
        await helper.getAddress(),
        V23,
        SCOPE,
        VALIDITY,
        type,
        oprf,
        MIN_AGE,
        EXPIRY_MARGIN,
      )) as unknown as ZKPassportEvidenceAdapter;
      const registry = (await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
        owner.address,
        zkpIdentifierKind(type, oprf),
        zkpScopeId(SCOPE),
        0,
        0,
        [await adapter.getAddress()],
        false,
        [],
      )) as unknown as CofferdamIdentityRegistry;
      return { helper, root, adapter, registry } as unknown as Deployed;
    }

    it('reads four trailing inputs from 0.23.0, three before', async () => {
      const d = await deploy23();
      expect(await d.adapter.VERIFICATION_METHOD_VERSION()).to.equal(V23);
      expect(await d.adapter.TRAILING_INPUTS()).to.equal(4);
      expect(await (await deploy()).adapter.TRAILING_INPUTS()).to.equal(3);
    });

    it('binds a government-signed document: the chip, Aadhaar, the top of the range', async () => {
      const d = await deploy23();
      const cases: [HardhatEthersSigner, string, number][] = [
        [alice, ID_A, 100],
        [bob, ID_B, 101],
        [carol, ethers.id('passport-c'), 199],
      ];
      for (const [who, identifier, method] of cases) {
        await expect(d.registry.connect(who).bind(d.adapter, await evidence(d, { account: who.address, identifier, method })))
          .to.emit(d.registry, 'Bound');
      }
    });

    it('refuses a camera read attested by a device, and anything outside 100 to 199', async () => {
      const d = await deploy23();
      for (const method of [0, 99, 200, 201, 299, 300]) {
        await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { method })))
          .to.be.revertedWithCustomError(d.adapter, 'VerificationMethodRefused')
          .withArgs(method);
      }
    });

    it("a salted 0.23.0 proof: the OPRF key read before the method, as ZKPassport's app proved on 2026-11-18", async () => {
      const d = await deploy23({ type: ZKP_IDENTIFIER_TYPE.salted, oprf: OPRF });
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { identifierType: 1, oprf: ethers.id('oprf-key-2'), method: 100 })))
        .to.be.revertedWithCustomError(d.adapter, 'WrongOprfKey');
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d, { identifierType: 1, oprf: OPRF, method: 100 })))
        .to.emit(d.registry, 'Bound')
        .withArgs(alice.address, ID_A, await d.adapter.getAddress(), anyValue);
    });

    it("refuses a proof of the other layout: an earlier adapter reads a 0.23.0 proof's identifier as its type", async () => {
      const old = await deploy();
      await expect(old.registry.connect(alice).bind(old.adapter, await evidence(old, { method: 100 })))
        .to.be.revertedWithCustomError(old.adapter, 'WrongIdentifierType')
        .withArgs(0, BigInt(ID_A));
      const d = await deploy23();
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'WrongIdentifierType');
      const short = encodeZkpEvidence({ vkeyHash: ZERO32, proof: MOCK_PROOF, publicInputs: new Array(8).fill(ZERO32), committedInputs: '0x' });
      await expect(d.registry.connect(alice).bind(d.adapter, short)).to.be.revertedWithCustomError(d.adapter, 'MalformedEvidence');
    });
  });

  describe('relink', () => {
    it('an honest passport renewal: moves the account to the new identifier at once and retires the old one', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B })))
        .to.emit(d.registry, 'Relinked')
        .withArgs(alice.address, ID_A, ID_B, await d.adapter.getAddress(), 1n)
        .and.to.emit(d.registry, 'IdentifierRetired')
        .withArgs(ID_A);
      expect(await d.registry.accountToIdentifier(alice.address)).to.equal(ID_B);
      expect(await d.registry.identifierToAccount(ID_B)).to.equal(alice.address);
      expect(await d.registry.identifierToAccount(ID_A)).to.equal(ethers.ZeroAddress);
      expect(await d.registry.isRetired(ID_A)).to.equal(true);
      expect(await d.registry.retiredBy(ID_A)).to.equal(alice.address);
      // The old passport can never open a second account by bind, nor be relinked to.
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_A })))
        .to.be.revertedWithCustomError(d.registry, 'RetiredIdentifier')
        .withArgs(ID_A);
      await d.registry.connect(carol).bind(d.adapter, await evidence(d, { account: carol.address, identifier: ethers.id('passport-c') }));
      await expect(d.registry.connect(carol).relink(d.adapter, await evidence(d, { account: carol.address, action: 'relink', identifier: ID_A })))
        .to.be.revertedWithCustomError(d.registry, 'RetiredIdentifier')
        .withArgs(ID_A);
      // A claim on it never applies by itself: it waits for the owner's ruling.
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind', identifier: ID_A }));
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'RetiredNeedsRuling').withArgs(ID_A);
      // The renewer still holds the new passport after a refused claim, and can renew again.
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, false))
        .to.emit(d.registry, 'RetiredClaimRuled')
        .withArgs(ID_A, alice.address, bob.address, false);
      expect(await d.registry.isRetired(ID_A)).to.equal(true);
      expect(await d.registry.isAccountBound(bob.address)).to.equal(false);
      const ID_D = ethers.id('passport-d');
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_D })))
        .to.emit(d.registry, 'Relinked')
        .withArgs(alice.address, ID_B, ID_D, await d.adapter.getAddress(), 2n);
    });

    it('refuses an unbound account, the same identifier and a taken identifier', async () => {
      const d = await deploy();
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink' })))
        .to.be.revertedWithCustomError(d.registry, 'AccountNotBound');
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_B }));
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink' })))
        .to.be.revertedWithCustomError(d.registry, 'SameIdentifier');
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B })))
        .to.be.revertedWithCustomError(d.registry, 'IdentifierAlreadyBound')
        .withArgs(ID_B, bob.address);
    });

    it('is refused while a rebind of the old identifier is pending, so it never escapes a contest', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      const relinkEv = await evidence(d, { action: 'relink', identifier: ID_B });
      await expect(d.registry.check(IDENTITY_ACTIONS.relink, alice.address, d.adapter, relinkEv))
        .to.be.revertedWithCustomError(d.registry, 'RebindPending')
        .withArgs(ID_A);
      await expect(d.registry.connect(alice).relink(d.adapter, relinkEv))
        .to.be.revertedWithCustomError(d.registry, 'RebindPending')
        .withArgs(ID_A);
      // The contest stands: unanswered, it moves the binding to the claimant.
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.emit(d.registry, 'Rebound').withArgs(alice.address, bob.address, ID_A);
      expect(await d.registry.isRetired(ID_A)).to.equal(false);
    });

    it('once the bound account answers the contest, it may relink', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(alice).cancelRebind(ID_A);
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B }))).to.emit(
        d.registry,
        'Relinked',
      );
    });

    it('the squatter: whoever bound a passport first and relinked away cannot lock its holder out', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      // Alice (the squatter) binds the holder's passport ID_A from a copy of its chip data,
      // then relinks to a second document, retiring ID_A.
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B }));
      // The holder (Bob) cannot bind, but can claim the retired identifier.
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address })))
        .to.be.revertedWithCustomError(d.registry, 'RetiredIdentifier');
      const claim = await evidence(d, { account: bob.address, action: 'rebind' });
      expect(await d.registry.check(IDENTITY_ACTIONS.rebind, bob.address, d.adapter, claim)).to.deep.equal([ID_A, alice.address]);
      await expect(d.registry.connect(bob).requestRebind(d.adapter, claim))
        .to.emit(d.registry, 'RebindRequested')
        .withArgs(alice.address, bob.address, ID_A, 0n, anyValue);
      // Only the account that retired it may veto; nobody finalizes it; the owner rules after the delay.
      await expect(d.registry.connect(carol).cancelRebind(ID_A))
        .to.be.revertedWithCustomError(d.registry, 'NotBoundAccount')
        .withArgs(carol.address, alice.address);
      await expect(d.registry.connect(alice).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(d.registry, 'NotOwner');
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(d.registry, 'RebindNotReady');
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'RetiredNeedsRuling');
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true))
        .to.emit(d.registry, 'RetiredClaimRuled')
        .withArgs(ID_A, alice.address, bob.address, true);
      // The holder is bound to their passport; the squatter keeps only the second document.
      expect(await d.registry.identifierToAccount(ID_A)).to.equal(bob.address);
      expect(await d.registry.accountToIdentifier(bob.address)).to.equal(ID_A);
      expect(await d.registry.isRetired(ID_A)).to.equal(false);
      expect(await d.registry.retiredBy(ID_A)).to.equal(ethers.ZeroAddress);
      expect(await d.registry.accountToIdentifier(alice.address)).to.equal(ID_B);
      // One passport, one account still: nobody binds ID_A again.
      await expect(d.registry.connect(carol).bind(d.adapter, await evidence(d, { account: carol.address })))
        .to.be.revertedWithCustomError(d.registry, 'IdentifierAlreadyBound')
        .withArgs(ID_A, bob.address);
    });

    it('the account that retired an identifier may veto a claim on it, paused or not', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B }));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(owner).setPaused(true);
      await expect(d.registry.connect(alice).cancelRebind(ID_A))
        .to.emit(d.registry, 'RebindCancelled')
        .withArgs(alice.address, ID_A, bob.address);
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, false)).to.be.revertedWithCustomError(d.registry, 'NoPendingRebind');
    });

    it('a claim on a retired identifier never applies at once, even with no rebind delay', async () => {
      const d = await deploy();
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B }));
      await expect(d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' })))
        .to.emit(d.registry, 'RebindRequested')
        .and.not.to.emit(d.registry, 'Rebound');
      expect(await d.registry.isAccountBound(bob.address)).to.equal(false);
      expect(await d.registry.isRetired(ID_A)).to.equal(true);
    });

    it("an award checks what finalizeRebind checks; a ruling needs a retired identifier's pending claim", async () => {
      const d = await deploy({ rebindDelay: DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(d.registry, 'NoPendingRebind');
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      // A pending rebind of a bound identifier is not the owner's to rule.
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true))
        .to.be.revertedWithCustomError(d.registry, 'NotRetired')
        .withArgs(ID_A);
      await d.registry.connect(alice).cancelRebind(ID_A);
      await d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B }));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await time.increase(DAY);
      await d.registry.connect(owner).setPaused(true);
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(d.registry, 'Paused');
      await d.registry.connect(owner).setPaused(false);
      // The claimant bound another document meanwhile.
      await d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ethers.id('passport-c') }));
      await expect(d.registry.connect(owner).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(d.registry, 'AccountAlreadyBound');
      // The adapter that checked the claim was removed.
      const fresh = await deploy({ rebindDelay: DAY });
      await fresh.registry.connect(alice).bind(fresh.adapter, await evidence(fresh));
      await fresh.registry.connect(alice).relink(fresh.adapter, await evidence(fresh, { action: 'relink', identifier: ID_B }));
      await fresh.registry.connect(bob).requestRebind(fresh.adapter, await evidence(fresh, { account: bob.address, action: 'rebind' }));
      await fresh.registry.connect(owner).removeAdapter(fresh.adapter);
      await time.increase(DAY);
      await expect(fresh.registry.connect(owner).ruleRetiredClaim(ID_A, true)).to.be.revertedWithCustomError(fresh.registry, 'AdapterNotActive');
      // A refusal still works.
      await expect(fresh.registry.connect(owner).ruleRetiredClaim(ID_A, false)).to.emit(fresh.registry, 'RetiredClaimRuled');
    });
  });

  describe('rebind (decision 0022)', () => {
    it('applies at once with no delay', async () => {
      const d = await deploy();
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await expect(d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' })))
        .to.emit(d.registry, 'Rebound')
        .withArgs(alice.address, bob.address, ID_A);
      expect(await d.registry.isAccountBound(alice.address)).to.equal(false);
      expect(await d.registry.identifierToAccount(ID_A)).to.equal(bob.address);
    });

    it('waits for the delay, and the bound account may cancel', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'RebindNotReady');
      await expect(d.registry.connect(carol).cancelRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'NotBoundAccount');
      // The veto works while paused.
      await d.registry.connect(owner).setPaused(true);
      await expect(d.registry.connect(alice).cancelRebind(ID_A))
        .to.emit(d.registry, 'RebindCancelled')
        .withArgs(alice.address, ID_A, bob.address);
      await d.registry.connect(owner).setPaused(false);
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'NoPendingRebind');
    });

    it('anyone finalizes after the delay', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await time.increase(3 * DAY);
      await expect(d.registry.connect(carol).finalizeRebind(ID_A)).to.emit(d.registry, 'Rebound').withArgs(alice.address, bob.address, ID_A);
      expect(await d.registry.accountToIdentifier(bob.address)).to.equal(ID_A);
      expect(await d.registry.isAccountBound(alice.address)).to.equal(false);
    });

    it('removing the adapter voids the rebinds it authorised', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(owner).removeAdapter(d.adapter);
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'AdapterNotActive');
    });

    it('a new account taken off the test allowlist cannot finalize', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY, allowlistOnly: true, testAccounts: [alice.address, bob.address] });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(owner).setTestAccount(bob.address, false);
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'NotTestAccount');
    });

    it('fails at finalize if the new account bound meanwhile', async () => {
      const d = await deploy({ rebindDelay: 3 * DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_B }));
      await time.increase(3 * DAY);
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'AccountAlreadyBound');
    });

    it('refuses an unbound identifier, the bound account itself and a bound new account', async () => {
      const d = await deploy();
      await expect(d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' })))
        .to.be.revertedWithCustomError(d.registry, 'IdentifierNotBound');
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await expect(d.registry.connect(alice).requestRebind(d.adapter, await evidence(d, { action: 'rebind' })))
        .to.be.revertedWithCustomError(d.registry, 'SameAccount');
      await d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_B }));
      await expect(d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' })))
        .to.be.revertedWithCustomError(d.registry, 'AccountAlreadyBound');
    });
  });

  describe('pause, test allowlist and pre-flight', () => {
    it('pause stops bind, relink, rebind and finalize', async () => {
      const d = await deploy({ rebindDelay: DAY });
      await d.registry.connect(alice).bind(d.adapter, await evidence(d));
      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await d.registry.connect(owner).setPaused(true);
      // (The relink below would also be refused for the pending rebind; the pause is checked first.)
      await time.increase(DAY);
      await expect(d.registry.connect(carol).bind(d.adapter, await evidence(d, { account: carol.address, identifier: ID_B })))
        .to.be.revertedWithCustomError(d.registry, 'Paused');
      await expect(d.registry.connect(alice).relink(d.adapter, await evidence(d, { action: 'relink', identifier: ID_B })))
        .to.be.revertedWithCustomError(d.registry, 'Paused');
      await expect(d.registry.finalizeRebind(ID_A)).to.be.revertedWithCustomError(d.registry, 'Paused');
      await expect(d.registry.connect(carol).requestRebind(d.adapter, await evidence(d, { account: carol.address, action: 'rebind' })))
        .to.be.revertedWithCustomError(d.registry, 'Paused');
      await expect(d.registry.connect(alice).setPaused(false)).to.be.revertedWithCustomError(d.registry, 'NotOwner');
    });

    it('the test allowlist admits only listed accounts', async () => {
      const d = await deploy({ allowlistOnly: true, testAccounts: [alice.address] });
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_B })))
        .to.be.revertedWithCustomError(d.registry, 'NotTestAccount')
        .withArgs(bob.address);
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.emit(d.registry, 'Bound');
      await d.registry.connect(owner).setTestAccount(bob.address, true);
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: bob.address, identifier: ID_B }))).to.emit(
        d.registry,
        'Bound',
      );
      await expect(d.registry.connect(alice).setTestAccount(carol.address, true)).to.be.revertedWithCustomError(d.registry, 'NotOwner');
    });

    it('check() returns what the action would do, or its error', async () => {
      const d = await deploy();
      const ev = await evidence(d);
      expect(await d.registry.check(IDENTITY_ACTIONS.bind, alice.address, d.adapter, ev)).to.deep.equal([ID_A, ethers.ZeroAddress]);
      await expect(d.registry.check(IDENTITY_ACTIONS.bind, bob.address, d.adapter, ev)).to.be.revertedWithCustomError(
        d.adapter,
        'WrongBoundAccount',
      );
      await expect(d.registry.check(ethers.id('cofferdam-identity-recover-v1'), alice.address, d.adapter, ev))
        .to.be.revertedWithCustomError(d.registry, 'UnknownAction');
      await d.registry.connect(alice).bind(d.adapter, ev);
      const rb = await evidence(d, { account: bob.address, action: 'rebind' });
      expect(await d.registry.check(IDENTITY_ACTIONS.rebind, bob.address, d.adapter, rb)).to.deep.equal([ID_A, alice.address]);
    });
  });

  describe('adapter allowlist', () => {
    it('adds an adapter only after the timelock, and removes one at once', async () => {
      const d = await deploy({ adapterDelay: 3 * DAY });
      const second = await deployAdapter(await d.root.getAddress());
      await expect(d.registry.connect(alice).proposeAdapter(second)).to.be.revertedWithCustomError(d.registry, 'NotOwner');
      await expect(d.registry.connect(owner).activateAdapter(second)).to.be.revertedWithCustomError(d.registry, 'AdapterNotProposed');
      await d.registry.connect(owner).proposeAdapter(second);
      await expect(d.registry.connect(owner).activateAdapter(second)).to.be.revertedWithCustomError(d.registry, 'AdapterNotReady');
      await expect(d.registry.connect(alice).bind(second, await evidence(d))).to.be.revertedWithCustomError(d.registry, 'AdapterNotActive');
      await time.increase(3 * DAY);
      await expect(d.registry.connect(owner).activateAdapter(second)).to.emit(d.registry, 'AdapterActivated');
      await expect(d.registry.connect(owner).removeAdapter(d.adapter)).to.emit(d.registry, 'AdapterRemoved');
      await expect(d.registry.connect(alice).bind(d.adapter, await evidence(d))).to.be.revertedWithCustomError(d.registry, 'AdapterNotActive');
      await expect(d.registry.connect(alice).bind(second, await evidence(d))).to.emit(d.registry, 'Bound');
    });

    it('a proposal left past its grace window must be made again', async () => {
      const d = await deploy({ adapterDelay: DAY });
      const second = await deployAdapter(await d.root.getAddress());
      await d.registry.connect(owner).proposeAdapter(second);
      await time.increase(DAY + 7 * DAY + 1);
      await expect(d.registry.connect(owner).activateAdapter(second)).to.be.revertedWithCustomError(d.registry, 'AdapterProposalExpired');
      await d.registry.connect(owner).proposeAdapter(second);
      await time.increase(DAY);
      await expect(d.registry.connect(owner).activateAdapter(second)).to.emit(d.registry, 'AdapterActivated');
    });

    it('a cancelled proposal never activates', async () => {
      const d = await deploy({ adapterDelay: DAY });
      const second = await deployAdapter(await d.root.getAddress());
      await d.registry.connect(owner).proposeAdapter(second);
      await d.registry.connect(owner).cancelAdapterProposal(second);
      await time.increase(DAY);
      await expect(d.registry.connect(owner).activateAdapter(second)).to.be.revertedWithCustomError(d.registry, 'AdapterNotProposed');
    });

    it('refuses an adapter of another identifier kind or scope', async () => {
      const d = await deploy();
      const salted = await deployAdapter(await d.root.getAddress(), { type: 1, oprf: OPRF });
      const otherScope = await deployAdapter(await d.root.getAddress(), { scope: 'cofferdam-id-v1' });
      await expect(d.registry.connect(owner).proposeAdapter(salted)).to.be.revertedWithCustomError(d.registry, 'WrongIdentifierKind');
      await expect(d.registry.connect(owner).proposeAdapter(otherScope)).to.be.revertedWithCustomError(d.registry, 'WrongScope');
      const F = await ethers.getContractFactory('CofferdamIdentityRegistry');
      await expect(
        F.deploy(owner.address, zkpIdentifierKind(0), zkpScopeId(SCOPE), 0, 0, [await salted.getAddress()], false, []),
      ).to.be.revertedWithCustomError(F, 'WrongIdentifierKind');
    });
  });

  describe('construction and ownership', () => {
    it('refuses a zero owner, kind or scope, and delays over 30 days', async () => {
      const { root } = await deployMocks();
      const adapter = await deployAdapter(await root.getAddress());
      const F = await ethers.getContractFactory('CofferdamIdentityRegistry');
      const kind = zkpIdentifierKind(0);
      const scope = zkpScopeId(SCOPE);
      await expect(F.deploy(ethers.ZeroAddress, kind, scope, 0, 0, [], false, [])).to.be.revertedWithCustomError(F, 'ZeroAddress');
      await expect(F.deploy(owner.address, ZERO32, scope, 0, 0, [], false, [])).to.be.revertedWithCustomError(F, 'ZeroValue');
      await expect(F.deploy(owner.address, kind, ZERO32, 0, 0, [], false, [])).to.be.revertedWithCustomError(F, 'ZeroValue');
      await expect(F.deploy(owner.address, kind, scope, 31 * DAY, 0, [], false, [])).to.be.revertedWithCustomError(F, 'DelayTooLong');
      await expect(F.deploy(owner.address, kind, scope, 0, 31 * DAY, [], false, [])).to.be.revertedWithCustomError(F, 'DelayTooLong');
      await expect(F.deploy(owner.address, kind, scope, 0, 0, [await adapter.getAddress()], false, [])).to.not.be.reverted;
    });

    it('transfers ownership in two steps', async () => {
      const d = await deploy();
      await d.registry.connect(owner).transferOwnership(bob.address);
      expect(await d.registry.owner()).to.equal(owner.address);
      await expect(d.registry.connect(carol).acceptOwnership()).to.be.revertedWithCustomError(d.registry, 'NotPendingOwner');
      await d.registry.connect(bob).acceptOwnership();
      expect(await d.registry.owner()).to.equal(bob.address);
      await expect(d.registry.connect(owner).setPaused(true)).to.be.revertedWithCustomError(d.registry, 'NotOwner');
    });
  });
  describe('through a CofferdamAccount4337 (today\'s account code, as in the test generation)', () => {
    async function accountOn(registry: string, ep: HardhatEthersSigner) {
      const highModule = await (await ethers.getContractFactory('WebAuthnPasskeyAuthority')).deploy();
      const modules = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(owner.address, [await highModule.getAddress()]);
      const ceremony = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(owner.address, []);
      const high = webauthnKey();
      const account: any = await (await ethers.getContractFactory('CofferdamAccount4337')).deploy(
        ep.address, modules, ceremony, registry, 0n, 600n, highModule, high.config, NO_PERMISSION,
      );
      return { account, highModule };
    }

    it('the account binds, vetoes a rebind and is bound, by its own execute calls', async () => {
      const [, , , , ep] = await ethers.getSigners();
      const d = await deploy({ rebindDelay: 3 * DAY });
      const { account } = await accountOn(await d.registry.getAddress(), ep);
      const addr = await account.getAddress();
      const call = (fn: string, args: unknown[]) =>
        account.connect(ep).execute(d.registry, 0, d.registry.interface.encodeFunctionData(fn as any, args as any));

      await expect(call('bind', [await d.adapter.getAddress(), await evidence(d, { account: addr })]))
        .to.emit(d.registry, 'Bound')
        .withArgs(addr, ID_A, await d.adapter.getAddress(), 0n);
      expect(await d.registry.isAccountBound(addr)).to.equal(true);
      // Someone else cannot bind for the account: the proof names it, msg.sender does not.
      await expect(d.registry.connect(bob).bind(d.adapter, await evidence(d, { account: addr, identifier: ID_B })))
        .to.be.revertedWithCustomError(d.adapter, 'WrongBoundAccount');

      await d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' }));
      await expect(call('cancelRebind', [ID_A])).to.emit(d.registry, 'RebindCancelled').withArgs(addr, ID_A, bob.address);
    });

    it("the account's recoverHigh reverts: it calls Self's provenNullifier, which this registry lacks", async () => {
      const [, , , , ep] = await ethers.getSigners();
      const d = await deploy();
      const { account, highModule } = await accountOn(await d.registry.getAddress(), ep);
      const newKey = webauthnKey();
      const assertion = newKey.sign(await account.recoveryChallenge(await account.ceremonyNonce()));
      const zero = { a: [0n, 0n], b: [[0n, 0n], [0n, 0n]], c: [0n, 0n], pubSignals: new Array(21).fill(0n), userContextData: '0x' };
      await expect(
        account.recoverHigh(highModule, newKey.config, assertion, zero, '0x', { notBefore: 0n, expiry: 0n, signature: '0x' }),
      ).to.be.revertedWithoutReason();
    });
  });
});
