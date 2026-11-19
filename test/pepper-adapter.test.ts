import { expect } from 'chai';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';
import { ethers } from 'hardhat';
import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import type {
  CofferdamIdentityRegistry,
  CofferdamZKPassportPepperAdapter,
  MockZKPassportHelper,
  MockZKPassportProofVerifier,
  MockZKPassportRootRegistry,
  MockZKPassportRootVerifier,
  MockZKPassportSubVerifier,
} from '../typechain-types';

import {
  IDENTITY_ACTIONS,
  IdentityAction,
  ZKP_DOMAIN,
  ZKP_GLOBAL_OPRF_KEY_HASH,
  ZKP_IDENTIFIER_TYPE,
  encodeZkpEvidence,
  zkpBindSection,
  zkpCircuitsVersion,
  zkpCustomData,
  zkpExpirySection,
  zkpIdentifierKind,
  zkpParamCommitment,
  zkpScopeHash,
  zkpScopeId,
  zkpSection,
} from '../scripts/lib/identity';

// Unit tests of CofferdamZKPassportPepperAdapter (decision 0080, the pepper)
// on mock ZKPassport contracts: the sub-verifier, root registry and outer
// verifiers it reads instead of RootVerifier.verify, which refuses a proof
// salted under any key but ZKPassport's global one. Commitments and scope
// hashes are computed as ZKPassport computes them, so the ported checks run
// on real encodings; only the outer proof is a stand-in.

const V23 = zkpCircuitsVersion('0.23.0');
const SCOPE = 'cofferdam-pepper-test';
const VALIDITY = 3600;
const MIN_AGE = 18;
const DAY = 24 * 3600;
const EXPIRY_MARGIN = 30 * DAY;
const ZERO32 = ethers.ZeroHash;
const KEY = ethers.id('cofferdam-oprf-key-1');
const OTHER_KEY = ethers.id('cofferdam-oprf-key-2');
/** A global key the mock sub-verifier holds, other than mainnet's (which the adapter refuses by constant). */
const LIVE_GLOBAL = ethers.id('zkpassport-global-on-this-chain');
const ID_A = ethers.id('salted-passport-a');
const ID_B = ethers.id('salted-passport-b');
const CERT_ROOT = ethers.id('certificate-root');
const CIRCUIT_ROOT = ethers.id('circuit-root');
const VK1 = ethers.id('outer-count-5');
const VK2 = ethers.id('outer-count-6');
const ICAO_CHIP = 100;

type EvidenceOptions = {
  account?: string;
  action?: IdentityAction;
  digest?: string;
  identifier?: string;
  identifierType?: number;
  oprf?: string;
  method?: number;
  chainId?: bigint;
  age?: number;
  /** The proof's lower bound on the document's expiry; default bind time + 1 year. null: no expiry section. */
  expiry?: bigint | null;
  extra?: Uint8Array[];
  date?: number;
  vkeyHash?: string;
  certRoot?: string;
  circuitRoot?: string;
  domainHash?: string;
  scopeHash?: string;
  noBind?: boolean;
  /** Edit the public inputs after the commitments are made, before proving. */
  editInputs?: (pi: string[]) => void;
  /** Edit the committed inputs after the commitments are made and proved. */
  editCommitted?: (ci: Uint8Array) => Uint8Array;
  /** Edit the public inputs after proving: the proof no longer matches. */
  tamperAfterProof?: (pi: string[]) => void;
};

describe('CofferdamZKPassportPepperAdapter (decision 0080, the pepper)', () => {
  let owner: HardhatEthersSigner;
  let alice: HardhatEthersSigner;
  let bob: HardhatEthersSigner;
  let chainId: bigint;

  beforeEach(async () => {
    [owner, alice, bob] = await ethers.getSigners();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  async function deployZkp() {
    const helper = (await (await ethers.getContractFactory('MockZKPassportHelper')).deploy()) as unknown as MockZKPassportHelper;
    const root = (await (await ethers.getContractFactory('MockZKPassportRootVerifier')).deploy()) as unknown as MockZKPassportRootVerifier;
    const rootRegistry = (await (
      await ethers.getContractFactory('MockZKPassportRootRegistry')
    ).deploy()) as unknown as MockZKPassportRootRegistry;
    const sub = (await (
      await ethers.getContractFactory('MockZKPassportSubVerifier')
    ).deploy(await root.getAddress(), LIVE_GLOBAL)) as unknown as MockZKPassportSubVerifier;
    const PV = await ethers.getContractFactory('MockZKPassportProofVerifier');
    const pv1 = (await PV.deploy(ethers.id('salt-1'))) as unknown as MockZKPassportProofVerifier;
    const pv2 = (await PV.deploy(ethers.id('salt-2'))) as unknown as MockZKPassportProofVerifier;
    await sub.setProofVerifier(VK1, pv1);
    await sub.setProofVerifier(VK2, pv2);
    await root.setHelper(V23, helper);
    await root.setSubVerifier(V23, sub);
    await root.setRootRegistry(rootRegistry);
    await rootRegistry.setRoot(ethers.toBeHex(1, 32), CERT_ROOT, 0, 2n ** 40n);
    await rootRegistry.setRoot(ethers.toBeHex(2, 32), CIRCUIT_ROOT, 0, 2n ** 40n);
    return { helper, root, rootRegistry, sub, pv1, pv2 };
  }

  type Zkp = Awaited<ReturnType<typeof deployZkp>>;

  type AdapterArgs = {
    root?: string;
    helper?: string;
    version?: string;
    scope?: string;
    validity?: number;
    key?: string;
    minAge?: number;
    expiryMargin?: number;
    vkeyHashes?: string[];
    verifiers?: string[];
  };

  async function adapterArgs(z: Zkp, o: AdapterArgs = {}) {
    return [
      o.root ?? (await z.root.getAddress()),
      o.helper ?? (await z.helper.getAddress()),
      o.version ?? V23,
      o.scope ?? SCOPE,
      o.validity ?? VALIDITY,
      o.key ?? KEY,
      o.minAge ?? MIN_AGE,
      o.expiryMargin ?? EXPIRY_MARGIN,
      o.vkeyHashes ?? [VK1, VK2],
      o.verifiers ?? [await z.pv1.getAddress(), await z.pv2.getAddress()],
    ] as const;
  }

  async function deployAdapter(z: Zkp, o: AdapterArgs = {}) {
    const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
    return (await F.deploy(...(await adapterArgs(z, o)))) as unknown as CofferdamZKPassportPepperAdapter;
  }

  async function deploy(o: AdapterArgs = {}) {
    const z = await deployZkp();
    const adapter = await deployAdapter(z, o);
    const registry = (await (await ethers.getContractFactory('CofferdamIdentityRegistry')).deploy(
      owner.address,
      zkpIdentifierKind(ZKP_IDENTIFIER_TYPE.salted, o.key ?? KEY),
      zkpScopeId(o.scope ?? SCOPE),
      0,
      0,
      [await adapter.getAddress()],
      false,
      [],
    )) as unknown as CofferdamIdentityRegistry;
    return { ...z, adapter, registry };
  }

  type Deployed = Awaited<ReturnType<typeof deploy>>;

  /** Evidence the mocks accept for `account` and the registry's current digest of `action`. */
  async function evidence(d: Deployed, o: EvidenceOptions = {}): Promise<string> {
    const account = o.account ?? alice.address;
    const digest = o.digest ?? (await d.registry.digest(IDENTITY_ACTIONS[o.action ?? 'bind'], account));
    const now = await time.latest();
    const expiry = o.expiry === undefined ? BigInt(now + 365 * DAY) : o.expiry;
    const sections: Uint8Array[] = [zkpSection(1, [o.age ?? MIN_AGE, 0]), ...(o.extra ?? [])];
    if (expiry !== null) sections.push(zkpExpirySection(expiry));
    if (!o.noBind) {
      sections.push(zkpBindSection({ userAddress: account, chainId: o.chainId ?? chainId, customData: zkpCustomData(digest) }));
    }
    const publicInputs = [
      o.certRoot ?? CERT_ROOT,
      o.circuitRoot ?? CIRCUIT_ROOT,
      ethers.toBeHex(o.date ?? now, 32),
      o.domainHash ?? zkpScopeHash(ZKP_DOMAIN),
      o.scopeHash ?? zkpScopeHash(SCOPE),
      ...sections.map((s) => zkpParamCommitment(s)),
      ethers.toBeHex(o.identifierType ?? ZKP_IDENTIFIER_TYPE.salted, 32),
      o.identifier ?? ID_A,
      o.oprf ?? KEY,
      ethers.toBeHex(o.method ?? ICAO_CHIP, 32),
    ];
    o.editInputs?.(publicInputs);
    const vkeyHash = o.vkeyHash ?? VK1;
    const salt = vkeyHash === VK2 ? ethers.id('salt-2') : ethers.id('salt-1');
    const proof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32[]'], [salt, publicInputs]));
    o.tamperAfterProof?.(publicInputs);
    let ci = ethers.getBytes(ethers.concat(sections));
    if (o.editCommitted) ci = o.editCommitted(ci);
    return encodeZkpEvidence({ vkeyHash, proof, publicInputs, committedInputs: ci });
  }

  const bind = (d: Deployed, who: HardhatEthersSigner, ev: string) => d.registry.connect(who).bind(d.adapter, ev);

  describe('a salted chip proof under Cofferdam\'s key binds through the registry', () => {
    it('binds, with the kind (SALTED, our key) and the scope the TypeScript helpers compute', async () => {
      const d = await deploy();
      expect(await d.adapter.identifierKind()).to.equal(zkpIdentifierKind(ZKP_IDENTIFIER_TYPE.salted, KEY));
      expect(await d.adapter.scopeId()).to.equal(zkpScopeId(SCOPE));
      expect(await d.registry.IDENTIFIER_KIND()).to.equal(await d.adapter.identifierKind());
      await expect(bind(d, alice, await evidence(d)))
        .to.emit(d.registry, 'Bound')
        .withArgs(alice.address, ID_A, await d.adapter.getAddress(), 0);
      expect(await d.registry.accountToIdentifier(alice.address)).to.equal(ID_A);
    });

    it('takes either pinned outer verifier, and a rebind and a relink through it', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { vkeyHash: VK2 }))).to.emit(d.registry, 'Bound');
      await expect(
        d.registry.connect(bob).requestRebind(d.adapter, await evidence(d, { account: bob.address, action: 'rebind' })),
      ).to.emit(d.registry, 'Rebound');
      await expect(
        d.registry.connect(bob).relink(d.adapter, await evidence(d, { account: bob.address, action: 'relink', identifier: ID_B })),
      ).to.emit(d.registry, 'Relinked');
    });

    it('the check() pre-flight returns the identifier', async () => {
      const d = await deploy();
      const [identifier] = await d.registry.check(IDENTITY_ACTIONS.bind, alice.address, d.adapter, await evidence(d));
      expect(identifier).to.equal(ID_A);
    });

    it('pins what it was built with', async () => {
      const d = await deploy();
      expect(await d.adapter.OPRF_KEY_HASH()).to.equal(KEY);
      expect(await d.adapter.VERSION()).to.equal(V23);
      expect(await d.adapter.ROOT_VERIFIER()).to.equal(await d.root.getAddress());
      expect(await d.adapter.HELPER()).to.equal(await d.helper.getAddress());
      expect(await d.adapter.scope()).to.equal(SCOPE);
      expect(await d.adapter.vkeyHashes()).to.deep.equal([VK1, VK2]);
      expect(await d.adapter.outerVerifier(VK1)).to.equal(await d.pv1.getAddress());
      expect(await d.adapter.outerVerifier(VK2)).to.equal(await d.pv2.getAddress());
      expect(await d.adapter.ZKPASSPORT_GLOBAL_OPRF_KEY_HASH()).to.equal(ZKP_GLOBAL_OPRF_KEY_HASH);
      expect(await d.adapter.MIN_VERSION()).to.equal(V23);
    });
  });

  describe('the OPRF key, the identifier type and the method', () => {
    it('refuses another OPRF key hash', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { oprf: OTHER_KEY })))
        .to.be.revertedWithCustomError(d.adapter, 'WrongOprfKey')
        .withArgs(KEY, OTHER_KEY);
    });

    it("refuses a proof salted under ZKPassport's global key, the one RootVerifier accepts", async () => {
      const d = await deploy();
      for (const global of [ZKP_GLOBAL_OPRF_KEY_HASH, LIVE_GLOBAL]) {
        await expect(bind(d, alice, await evidence(d, { oprf: global })))
          .to.be.revertedWithCustomError(d.adapter, 'WrongOprfKey')
          .withArgs(KEY, global);
      }
    });

    it('refuses an unsalted identifier, the mock types and none', async () => {
      const d = await deploy();
      for (const t of [0, 2, 3, 4, 5]) {
        await expect(bind(d, alice, await evidence(d, { identifierType: t, oprf: t === 0 ? ZERO32 : KEY })))
          .to.be.revertedWithCustomError(d.adapter, 'WrongIdentifierType')
          .withArgs(1, t);
      }
    });

    it('accepts the eMRTD chip only: Aadhaar, JPKI, mDoc, camera reads and anything else are refused', async () => {
      const d = await deploy();
      for (const method of [0, 1, 99, 101, 102, 103, 199, 200, 201, 299, 300]) {
        await expect(bind(d, alice, await evidence(d, { method })))
          .to.be.revertedWithCustomError(d.adapter, 'VerificationMethodRefused')
          .withArgs(method);
      }
    });

    it('never returns identifier 0', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { identifier: ZERO32 }))).to.be.revertedWithCustomError(d.adapter, 'ZeroIdentifier');
    });

    it('refuses evidence too short to hold the outer public inputs', async () => {
      const d = await deploy();
      const short = encodeZkpEvidence({ vkeyHash: VK1, proof: '0x', publicInputs: new Array(9).fill(ZERO32), committedInputs: '0x' });
      await expect(bind(d, alice, short)).to.be.revertedWithCustomError(d.adapter, 'MalformedEvidence');
    });
  });

  describe("the sub-verifier's checks, repeated", () => {
    it('refuses an invalid proof, and a public input changed after proving', async () => {
      const d = await deploy();
      // A proof made for the other outer verifier.
      const ev = await evidence(d);
      const [, proof, pi, ci] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes32', 'bytes', 'bytes32[]', 'bytes'], ev);
      await expect(bind(d, alice, encodeZkpEvidence({ vkeyHash: VK2, proof, publicInputs: [...pi], committedInputs: ci })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
      // The identifier swapped after proving.
      await expect(bind(d, alice, await evidence(d, { tamperAfterProof: (p) => (p[p.length - 3] = ID_B) })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofInvalid');
    });

    it('refuses a vkey hash it did not pin, and one ZKPassport withdrew or swapped', async () => {
      const d = await deploy();
      const vk3 = ethers.id('outer-count-7');
      await expect(bind(d, alice, await evidence(d, { vkeyHash: vk3 })))
        .to.be.revertedWithCustomError(d.adapter, 'UnknownVerificationKey')
        .withArgs(vk3);
      await d.sub.setProofVerifier(VK1, ethers.ZeroAddress);
      await expect(bind(d, alice, await evidence(d)))
        .to.be.revertedWithCustomError(d.adapter, 'OuterVerifierWithdrawn')
        .withArgs(VK1);
      // A new verifier under the same vkey hash is not ours: still refused.
      const pv = await (await ethers.getContractFactory('MockZKPassportProofVerifier')).deploy(ethers.id('salt-1'));
      await d.sub.setProofVerifier(VK1, pv);
      await expect(bind(d, alice, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'OuterVerifierWithdrawn');
      await d.sub.setProofVerifier(VK1, d.pv1);
      await expect(bind(d, alice, await evidence(d))).to.emit(d.registry, 'Bound');
    });

    it("follows ZKPassport's pauses and a removed sub-verifier", async () => {
      const d = await deploy();
      await d.root.setPaused(true);
      await expect(bind(d, alice, await evidence(d)))
        .to.be.revertedWithCustomError(d.adapter, 'VerifierPaused')
        .withArgs(await d.root.getAddress());
      await d.root.setPaused(false);
      await d.sub.setPaused(true);
      await expect(bind(d, alice, await evidence(d)))
        .to.be.revertedWithCustomError(d.adapter, 'VerifierPaused')
        .withArgs(await d.sub.getAddress());
      await d.sub.setPaused(false);
      await d.root.setSubVerifier(V23, ethers.ZeroAddress);
      await expect(bind(d, alice, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'NoSubVerifier');
      // A new sub-verifier that lists our verifier keeps the adapter working.
      const sub2 = await (await ethers.getContractFactory('MockZKPassportSubVerifier')).deploy(d.root, LIVE_GLOBAL);
      await sub2.setProofVerifier(VK1, d.pv1);
      await d.root.setSubVerifier(V23, sub2);
      await expect(bind(d, alice, await evidence(d))).to.emit(d.registry, 'Bound');
    });

    it('pins the helper: a helper swapped by ZKPassport fails closed', async () => {
      const d = await deploy();
      const other = await (await ethers.getContractFactory('MockZKPassportHelper')).deploy();
      await d.root.setHelper(V23, other);
      await expect(bind(d, alice, await evidence(d)))
        .to.be.revertedWithCustomError(d.adapter, 'HelperMismatch')
        .withArgs(await d.helper.getAddress(), await other.getAddress());
    });

    it('refuses an expired proof and one dated in the future', async () => {
      const d = await deploy();
      const now = await time.latest();
      await expect(bind(d, alice, await evidence(d, { date: now - VALIDITY })))
        .to.be.revertedWithCustomError(d.adapter, 'ProofDateInvalid');
      await expect(bind(d, alice, await evidence(d, { date: now + 60 }))).to.be.revertedWithCustomError(d.adapter, 'ProofDateInvalid');
      const max = await evidence(d, { editInputs: (p) => (p[2] = ethers.toBeHex(ethers.MaxUint256, 32)) });
      await expect(bind(d, alice, max)).to.be.revertedWithCustomError(d.adapter, 'ProofDateInvalid');
      await expect(bind(d, alice, await evidence(d, { date: now - VALIDITY + 10 }))).to.emit(d.registry, 'Bound');
    });

    it('refuses another domain or scope, and an empty one', async () => {
      const d = await deploy();
      for (const o of [
        { domainHash: zkpScopeHash('zkpassport.id') },
        { scopeHash: zkpScopeHash('cofferdam-zkp-test-1') },
        { scopeHash: ZERO32 },
        { domainHash: ZERO32 },
      ]) {
        await expect(bind(d, alice, await evidence(d, o))).to.be.revertedWithCustomError(d.adapter, 'WrongScope');
      }
    });

    it('refuses a certificate or circuit root the root registry does not hold at the proof date', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { certRoot: ethers.id('unknown') }))).to.be.revertedWithCustomError(
        d.adapter,
        'InvalidCertificateRoot',
      );
      // A circuit root presented as the certificate root.
      await expect(bind(d, alice, await evidence(d, { certRoot: CIRCUIT_ROOT }))).to.be.revertedWithCustomError(
        d.adapter,
        'InvalidCertificateRoot',
      );
      await expect(bind(d, alice, await evidence(d, { circuitRoot: ethers.id('unknown') }))).to.be.revertedWithCustomError(
        d.adapter,
        'InvalidCircuitRoot',
      );
      // A root valid only before the proof's date.
      const now = await time.latest();
      await d.rootRegistry.setRoot(ethers.toBeHex(1, 32), CERT_ROOT, 0, now - 100);
      await expect(bind(d, alice, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'InvalidCertificateRoot');
      await d.rootRegistry.setRoot(ethers.toBeHex(1, 32), CERT_ROOT, 0, 2n ** 40n);
      await d.rootRegistry.setPaused(true);
      await expect(bind(d, alice, await evidence(d))).to.be.revertedWithCustomError(d.adapter, 'InvalidCertificateRoot');
    });

    it('refuses committed inputs that do not match the parameter commitments', async () => {
      const d = await deploy();
      // One byte of the bind data changed.
      await expect(
        bind(d, alice, await evidence(d, { editCommitted: (ci) => ((ci[ci.length - 1] ^= 1), ci) })),
      ).to.be.revertedWithCustomError(d.adapter, 'CommitmentMismatch');
      // A section added without its commitment.
      await expect(
        bind(d, alice, await evidence(d, { editCommitted: (ci) => ethers.getBytes(ethers.concat([ci, zkpSection(1, [18, 0])])) })),
      ).to.be.revertedWithCustomError(d.adapter, 'CommitmentMismatch');
      // A section dropped, leaving a commitment over.
      await expect(bind(d, alice, await evidence(d, { editCommitted: (ci) => ci.slice(5) }))).to.be.revertedWithCustomError(
        d.adapter,
        'CommitmentMismatch',
      );
      // A trailing partial header.
      await expect(
        bind(d, alice, await evidence(d, { editCommitted: (ci) => ethers.getBytes(ethers.concat([ci, '0x08'])) })),
      ).to.be.revertedWithCustomError(d.adapter, 'CommitmentMismatch');
      // A commitment edited before proving (the proof matches, the commitment does not).
      await expect(bind(d, alice, await evidence(d, { editInputs: (p) => (p[5] = ethers.id('x')) }))).to.be.revertedWithCustomError(
        d.adapter,
        'CommitmentMismatch',
      );
    });
  });

  describe('what the proof binds and proves', () => {
    it('refuses a proof made for another account, chain or digest', async () => {
      const d = await deploy();
      await expect(bind(d, bob, await evidence(d, { account: alice.address }))).to.be.revertedWithCustomError(
        d.adapter,
        'WrongBoundAccount',
      );
      await expect(bind(d, alice, await evidence(d, { chainId: 8453n }))).to.be.revertedWithCustomError(d.adapter, 'WrongBoundChain');
      await expect(bind(d, alice, await evidence(d, { action: 'rebind' }))).to.be.revertedWithCustomError(d.adapter, 'WrongBoundDigest');
    });

    it('a used proof never replays: its nonce is consumed', async () => {
      const d = await deploy();
      const ev = await evidence(d);
      await expect(bind(d, alice, ev)).to.emit(d.registry, 'Bound');
      await expect(d.registry.connect(alice).relink(d.adapter, ev)).to.be.revertedWithCustomError(d.adapter, 'WrongBoundDigest');
    });

    it('requires the minimum age and the expiry margin as exact lower bounds', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { age: 17 })))
        .to.be.revertedWithCustomError(d.adapter, 'AgeNotProven')
        .withArgs(MIN_AGE);
      const now = await time.latest();
      await expect(bind(d, alice, await evidence(d, { expiry: BigInt(now + DAY) }))).to.be.revertedWithCustomError(
        d.adapter,
        'ExpiryNotProven',
      );
      await expect(bind(d, alice, await evidence(d, { expiry: null }))).to.be.revertedWithCustomError(d.adapter, 'ExpiryNotProven');
    });

    it('admits only the age, expiry and bind sections, once each, with no upper bound', async () => {
      const d = await deploy();
      // Disclosure, inclusion and exclusion lists, sanctions, face match, attested ID.
      for (const t of [0, 2, 4, 5, 6, 7, 9, 10, 11, 12]) {
        await expect(bind(d, alice, await evidence(d, { extra: [zkpSection(t, [1, 2, 3])] })))
          .to.be.revertedWithCustomError(d.adapter, 'SectionRefused')
          .withArgs(t);
      }
      await expect(bind(d, alice, await evidence(d, { extra: [zkpSection(1, [18, 0])] })))
        .to.be.revertedWithCustomError(d.adapter, 'DuplicateSection')
        .withArgs(1);
      await expect(bind(d, alice, await evidence(d, { extra: [zkpExpirySection(2n ** 40n)] })))
        .to.be.revertedWithCustomError(d.adapter, 'DuplicateSection')
        .withArgs(3);
      const now = await time.latest();
      await expect(bind(d, alice, await evidence(d, { expiry: null, extra: [zkpExpirySection(BigInt(now + 365 * DAY), 2n ** 40n)] })))
        .to.be.revertedWithCustomError(d.adapter, 'DisclosureRefused')
        .withArgs(3);
    });

    it('refuses an age range', async () => {
      const d = await deploy();
      const account = alice.address;
      const digest = await d.registry.digest(IDENTITY_ACTIONS.bind, account);
      const now = await time.latest();
      const sections = [
        zkpSection(1, [18, 65]),
        zkpExpirySection(BigInt(now + 365 * DAY)),
        zkpBindSection({ userAddress: account, chainId, customData: zkpCustomData(digest) }),
      ];
      const pi = [
        CERT_ROOT,
        CIRCUIT_ROOT,
        ethers.toBeHex(now, 32),
        zkpScopeHash(ZKP_DOMAIN),
        zkpScopeHash(SCOPE),
        ...sections.map((s) => zkpParamCommitment(s)),
        ethers.toBeHex(1, 32),
        ID_A,
        KEY,
        ethers.toBeHex(ICAO_CHIP, 32),
      ];
      const proof = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32[]'], [ethers.id('salt-1'), pi]));
      const ev = encodeZkpEvidence({ vkeyHash: VK1, proof, publicInputs: pi, committedInputs: ethers.concat(sections) });
      await expect(bind(d, alice, ev)).to.be.revertedWithCustomError(d.adapter, 'DisclosureRefused').withArgs(1);
    });

    it('requires exactly one bind section', async () => {
      const d = await deploy();
      await expect(bind(d, alice, await evidence(d, { noBind: true })))
        .to.be.revertedWithCustomError(d.adapter, 'BindSectionCount')
        .withArgs(0);
      const digest = await d.registry.digest(IDENTITY_ACTIONS.bind, alice.address);
      const second = zkpBindSection({ userAddress: bob.address, chainId, customData: zkpCustomData(digest) });
      await expect(bind(d, alice, await evidence(d, { extra: [second] })))
        .to.be.revertedWithCustomError(d.adapter, 'BindSectionCount')
        .withArgs(2);
    });

    it('an adapter with no age or expiry check needs neither section', async () => {
      const d = await deploy({ minAge: 0, expiryMargin: 0 });
      await expect(bind(d, alice, await evidence(d, { expiry: null }))).to.emit(d.registry, 'Bound').withArgs(alice.address, ID_A, anyValue, 0);
    });
  });

  describe('construction', () => {
    it("refuses ZKPassport's global OPRF key, mainnet's or the live sub-verifier's, and a zero key", async () => {
      const z = await deployZkp();
      const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
      for (const key of [ZKP_GLOBAL_OPRF_KEY_HASH, LIVE_GLOBAL]) {
        await expect(F.deploy(...(await adapterArgs(z, { key }))))
          .to.be.revertedWithCustomError(F, 'GlobalOprfKeyRefused')
          .withArgs(key);
      }
      await expect(F.deploy(...(await adapterArgs(z, { key: ZERO32 })))).to.be.revertedWithCustomError(F, 'BadOprfKeyHash');
    });

    it('refuses a circuits version before 0.23.0 and one with no sub-verifier', async () => {
      const z = await deployZkp();
      const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
      const v22 = zkpCircuitsVersion('0.22.0');
      await z.root.setHelper(v22, z.helper);
      await expect(F.deploy(...(await adapterArgs(z, { version: v22 })))).to.be.revertedWithCustomError(F, 'UnsupportedVersion');
      const v24 = zkpCircuitsVersion('0.24.0');
      await z.root.setHelper(v24, z.helper);
      await expect(F.deploy(...(await adapterArgs(z, { version: v24 })))).to.be.revertedWithCustomError(F, 'NoSubVerifier');
    });

    it('refuses a helper the RootVerifier does not name, and a sub-verifier of another RootVerifier', async () => {
      const z = await deployZkp();
      const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
      await expect(F.deploy(...(await adapterArgs(z, { helper: bob.address })))).to.be.revertedWithCustomError(F, 'HelperMismatch');
      const foreign = await (await ethers.getContractFactory('MockZKPassportSubVerifier')).deploy(bob.address, LIVE_GLOBAL);
      await foreign.setProofVerifier(VK1, z.pv1);
      await z.root.setSubVerifier(V23, foreign);
      await expect(F.deploy(...(await adapterArgs(z)))).to.be.revertedWithCustomError(F, 'ForeignSubVerifier');
    });

    it('pins only verifiers the sub-verifier lists under their vkey hash, each once', async () => {
      const z = await deployZkp();
      const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
      const pv1 = await z.pv1.getAddress();
      const pv2 = await z.pv2.getAddress();
      await expect(F.deploy(...(await adapterArgs(z, { vkeyHashes: [VK1, VK2], verifiers: [pv2, pv1] }))))
        .to.be.revertedWithCustomError(F, 'OuterVerifierMismatch')
        .withArgs(VK1, pv2, pv1);
      await expect(F.deploy(...(await adapterArgs(z, { vkeyHashes: [VK1, VK1], verifiers: [pv1, pv1] }))))
        .to.be.revertedWithCustomError(F, 'DuplicateVerificationKey')
        .withArgs(VK1);
      await expect(F.deploy(...(await adapterArgs(z, { vkeyHashes: [], verifiers: [] })))).to.be.revertedWithCustomError(
        F,
        'NoOuterVerifiers',
      );
      await expect(F.deploy(...(await adapterArgs(z, { vkeyHashes: [VK1], verifiers: [pv1, pv2] })))).to.be.revertedWithCustomError(
        F,
        'LengthMismatch',
      );
      await expect(
        F.deploy(...(await adapterArgs(z, { vkeyHashes: [ethers.id('none')], verifiers: [ethers.ZeroAddress] }))),
      ).to.be.revertedWithCustomError(F, 'ZeroAddress');
    });

    it('refuses a zero RootVerifier, an empty scope, a bad validity, age or expiry margin', async () => {
      const z = await deployZkp();
      const F = await ethers.getContractFactory('CofferdamZKPassportPepperAdapter');
      await expect(F.deploy(...(await adapterArgs(z, { root: ethers.ZeroAddress })))).to.be.revertedWithCustomError(F, 'ZeroAddress');
      await expect(F.deploy(...(await adapterArgs(z, { scope: '' })))).to.be.revertedWithCustomError(F, 'EmptyScope');
      for (const validity of [0, DAY + 1]) {
        await expect(F.deploy(...(await adapterArgs(z, { validity })))).to.be.revertedWithCustomError(F, 'BadValidity');
      }
      await expect(F.deploy(...(await adapterArgs(z, { minAge: 101 })))).to.be.revertedWithCustomError(F, 'BadMinAge');
      await expect(F.deploy(...(await adapterArgs(z, { expiryMargin: 5 * 365 * DAY + 1 })))).to.be.revertedWithCustomError(
        F,
        'BadExpiryMargin',
      );
    });

    it('a registry of another kind refuses it: unsalted, or salted under another key', async () => {
      const z = await deployZkp();
      const adapter = await deployAdapter(z);
      const R = await ethers.getContractFactory('CofferdamIdentityRegistry');
      for (const kind of [zkpIdentifierKind(ZKP_IDENTIFIER_TYPE.nonSalted), zkpIdentifierKind(ZKP_IDENTIFIER_TYPE.salted, OTHER_KEY)]) {
        await expect(R.deploy(owner.address, kind, zkpScopeId(SCOPE), 0, 0, [await adapter.getAddress()], false, [])).to.be.revertedWithCustomError(
          R,
          'WrongIdentifierKind',
        );
      }
    });
  });
});
