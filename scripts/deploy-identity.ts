import { ethers, network } from 'hardhat';
import {
  assertMainnetOwner,
  assertMainnetSigner,
  chainId as nodeChainId,
  getDeployer,
  isBaseMainnetChain,
  isLocalFork,
  mainnetDelay,
} from './lib/chain';
import { readDeployments, refuseRecordedGeneration, writeDeployments } from './lib/deployments';
import { mainnetRegistryOwner } from './lib/devKeyException';
import {
  ZKP_DOMAIN,
  ZKP_GLOBAL_OPRF_KEY_HASH,
  ZKP_IDENTIFIER_TYPE,
  ZKP_ROOT_VERIFIER,
  identifierTypeFor,
  zkpCircuitsVersion,
  zkpIdentifierKind,
  zkpScopeId,
} from './lib/identity';
import { MOCK_OUTER_VKEY_HASH, outerVerifierPins } from './lib/zkpOuterPins';

// Deploys decision 0080's identity registry with its first evidence adapter:
// ZKPassport's RootVerifier checked on-chain (ruling T5), or, with
// ZKP_ADAPTER=pepper, CofferdamZKPassportPepperAdapter (the pepper, P1).
// Nothing else.
//
//   ZKP_ADAPTER             root-verifier (default) or pepper. The pepper
//                           adapter deploys on a local fork of Base mainnet
//                           or a testnet only, never on Base mainnet itself:
//                           no generation runs it yet. It is salted only,
//                           circuits 0.23.0 by default, and takes
//                           ZKP_OPRF_KEY_HASH, Cofferdam's OPRF key hash
//                           (never ZKPassport's global key)
//   ZKP_OUTER_VKEY_HASHES   pepper only: comma-separated vkey hashes of the
//                           outer verifiers to pin, read from the version's
//                           sub-verifier; default the 0.23.0 table in
//                           scripts/lib/identity.ts. Off mainnet with no
//                           ZKP_ROOT_VERIFIER, mocks pin one mock verifier
//
//   GENERATION              Base mainnet only: the deployments file, e.g. zkp-test-1
//   LEDGER_ADDRESS          Base mainnet only: the deployer (hardhat.config.ts)
//   MAINNET_DEV_KEY_EXCEPTION  zkp-test-1 only, with --network baseDevTest: the
//                           M2 dev-key exception, the CofferdamDev wallet
//                           deploys and owns the generation instead of the
//                           Ledger (scripts/lib/devKeyException.ts)
//   REGISTRY_OWNER          owner of the registry; required on mainnet (the
//                           Safe for production; for the test generation T3
//                           said the founder's Ledger, replaced by the M2
//                           dev-key exception below). Under the dev-key exception
//                           the CofferdamDev wallet by default, or a Safe v1.4.1
//                           it signs for (create-safe.ts), checked on chain
//   ZKP_SCOPE               required; T1's test scope is cofferdam-zkp-test-1
//   ZKP_CIRCUITS_VERSION    default 0.21.1
//   ZKP_VALIDITY_SECONDS    default 3600, at most 86400
//   ZKP_IDENTIFIER_TYPE     non-salted (default off chain 8453) or salted.
//                           Required on chain 8453, a fork included; Base
//                           mainnet itself refuses non-salted outright, since
//                           zkp-test-1, the one T2 accepted, is deployed
//                           (decision 0080, rule 4)
//   ZKP_OPRF_KEY_HASH       required for salted
//   ZKP_MIN_AGE             default 18; mainnet refuses less. The proof's age
//                           bound must be exactly this
//   ZKP_EXPIRY_MARGIN_SECONDS  how long the document must stay valid after the
//                           bind: default 30 days on mainnet (which refuses 0),
//                           0 (no check) elsewhere
//   REBIND_DELAY_SECONDS    default 72 h on mainnet (the least), 0 elsewhere
//   ADAPTER_DELAY_SECONDS   default 72 h on mainnet (the least), 0 elsewhere
//   IDENTITY_ALLOWLIST_ONLY default 1 on mainnet, 0 elsewhere
//   IDENTITY_TEST_ACCOUNTS  comma-separated accounts on the test allowlist
//
// Off mainnet, with no ZKP_ROOT_VERIFIER, it deploys the mock RootVerifier and
// helper (contracts/test/MockZKPassport.sol): Base Sepolia has no RootVerifier
// in sync, so testnets and the M5 rehearsal run on mocks.
async function main() {
  const deployer = await getDeployer();
  const chainId = await nodeChainId();
  const mainnet = await isBaseMainnetChain();
  console.log(`Deploying the identity registry on ${network.name} (chain ${chainId}) from ${deployer.address}`);
  const adapterKind = process.env.ZKP_ADAPTER?.trim() || 'root-verifier';
  if (adapterKind !== 'root-verifier' && adapterKind !== 'pepper') throw new Error('ZKP_ADAPTER is root-verifier or pepper');
  const pepper = adapterKind === 'pepper';
  // Before the signer check, so Base mainnet refuses before any Ledger prompt.
  if (pepper && mainnet && !(await isLocalFork())) {
    throw new Error('ZKP_ADAPTER=pepper deploys on a local fork of Base mainnet or a testnet only: no mainnet generation runs it yet');
  }
  await assertMainnetSigner(deployer.address);
  refuseRecordedGeneration(network.name, chainId, [
    'CofferdamIdentityRegistry',
    'ZKPassportEvidenceAdapter',
    'CofferdamZKPassportPepperAdapter',
  ]);

  const owner = mainnet ? mainnetRegistryOwner() : process.env.REGISTRY_OWNER?.trim() || deployer.address;
  if (!ethers.isAddress(owner)) throw new Error(`REGISTRY_OWNER ${owner} is not an address`);
  await assertMainnetOwner(owner, { deployer: deployer.address, recordedSafe: readDeployments(network.name, chainId).CofferdamSafe?.address });

  const scope = process.env.ZKP_SCOPE?.trim();
  if (!scope) throw new Error('ZKP_SCOPE is required (T1: cofferdam-zkp-test-1 for the test generation, never reused)');
  const versionLabel = process.env.ZKP_CIRCUITS_VERSION?.trim() || (pepper ? '0.23.0' : '0.21.1');
  const version = zkpCircuitsVersion(versionLabel);
  const validity = BigInt(process.env.ZKP_VALIDITY_SECONDS?.trim() || '3600');
  const typeName = identifierTypeFor(process.env, { mainnet, fork: await isLocalFork(), pepper });
  const identifierType = typeName === 'salted' ? ZKP_IDENTIFIER_TYPE.salted : ZKP_IDENTIFIER_TYPE.nonSalted;
  const oprfKeyHash = process.env.ZKP_OPRF_KEY_HASH?.trim() || ethers.ZeroHash;
  if (pepper) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(oprfKeyHash) || oprfKeyHash === ethers.ZeroHash) {
      throw new Error("ZKP_OPRF_KEY_HASH is required for the pepper: Cofferdam's OPRF public key hash, 32 bytes of hex");
    }
    if (oprfKeyHash.toLowerCase() === ZKP_GLOBAL_OPRF_KEY_HASH) {
      throw new Error("ZKP_OPRF_KEY_HASH is ZKPassport's global key: the pepper adapter pins Cofferdam's own");
    }
  }
  const minAge = Number(process.env.ZKP_MIN_AGE?.trim() || '18');
  if (mainnet && minAge < 18) throw new Error('ZKP_MIN_AGE must be at least 18 on Base mainnet (decision 0080, 6)');
  const expiryMargin = BigInt(process.env.ZKP_EXPIRY_MARGIN_SECONDS?.trim() || (mainnet ? '2592000' : '0'));
  if (mainnet && expiryMargin === 0n) throw new Error('ZKP_EXPIRY_MARGIN_SECONDS must be set on Base mainnet (decision 0080, 5)');
  const rebindDelay = await mainnetDelay('REBIND_DELAY_SECONDS', 0n);
  const adapterDelay = await mainnetDelay('ADAPTER_DELAY_SECONDS', 0n);
  const allowlistOnly = (process.env.IDENTITY_ALLOWLIST_ONLY?.trim() || (mainnet ? '1' : '0')) === '1';
  const testAccounts = (process.env.IDENTITY_TEST_ACCOUNTS || '')
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => ethers.getAddress(a));

  let rootVerifier = process.env.ZKP_ROOT_VERIFIER?.trim();
  let helper = '';
  const out: Record<string, string> = {};
  if (mainnet) {
    if (rootVerifier && rootVerifier.toLowerCase() !== ZKP_ROOT_VERIFIER.toLowerCase()) {
      throw new Error(`On Base mainnet the RootVerifier is ${ZKP_ROOT_VERIFIER}`);
    }
    rootVerifier = ZKP_ROOT_VERIFIER;
    // Pre-flight against ZKPassport's live contracts before spending gas.
    const root = await ethers.getContractAt('IZKPassportRootVerifier', rootVerifier);
    if ((await ethers.provider.getCode(rootVerifier)) === '0x') throw new Error('No RootVerifier on this chain');
    helper = await root.getHelper(version);
    if (helper === ethers.ZeroAddress) throw new Error(`RootVerifier has no helper for circuits ${versionLabel}`);
    console.log(`RootVerifier ${rootVerifier}, helper for ${versionLabel}: ${helper}`);
  } else if (!rootVerifier) {
    console.log('No ZKP_ROOT_VERIFIER: deploying the mock RootVerifier and helper (testnets only).');
    const mockHelper = await (await ethers.getContractFactory('MockZKPassportHelper', deployer)).deploy();
    await mockHelper.waitForDeployment();
    const root = await (await ethers.getContractFactory('MockZKPassportRootVerifier', deployer)).deploy();
    await root.waitForDeployment();
    helper = await mockHelper.getAddress();
    await (await root.setHelper(version, helper)).wait();
    await (await root.setExpected(version, validity, ZKP_DOMAIN, scope, false)).wait();
    rootVerifier = await root.getAddress();
    out.MockZKPassportRootVerifier = rootVerifier;
    out.MockZKPassportHelper = helper;
    if (pepper) {
      // What the pepper adapter reads instead of RootVerifier.verify: a
      // sub-verifier holding ZKPassport's global key, a root registry with
      // one mock certificate and circuit root, and one mock outer verifier.
      const rootRegistry = await (await ethers.getContractFactory('MockZKPassportRootRegistry', deployer)).deploy();
      await rootRegistry.waitForDeployment();
      const sub = await (await ethers.getContractFactory('MockZKPassportSubVerifier', deployer)).deploy(rootVerifier, ZKP_GLOBAL_OPRF_KEY_HASH);
      await sub.waitForDeployment();
      const outer = await (await ethers.getContractFactory('MockZKPassportProofVerifier', deployer)).deploy(ethers.id('mock-outer-verifier'));
      await outer.waitForDeployment();
      await (await sub.setProofVerifier(MOCK_OUTER_VKEY_HASH, outer)).wait();
      await (await root.setSubVerifier(version, sub)).wait();
      await (await root.setRootRegistry(rootRegistry)).wait();
      for (const [id, label] of [[1, 'certificate'], [2, 'circuit']] as const) {
        await (await rootRegistry.setRoot(ethers.toBeHex(id, 32), ethers.id(`mock-${label}-root`), 0, 2n ** 40n)).wait();
      }
      out.MockZKPassportRootRegistry = await rootRegistry.getAddress();
      out.MockZKPassportSubVerifier = await sub.getAddress();
      out.MockZKPassportProofVerifier = await outer.getAddress();
    }
  } else {
    helper = await (await ethers.getContractAt('IZKPassportRootVerifier', rootVerifier)).getHelper(version);
  }
  console.log('Helper (pinned):', helper);
  const pins = pepper ? await outerVerifierPins(rootVerifier, version, versionLabel, !!out.MockZKPassportSubVerifier) : [];
  for (const [h, v] of pins) console.log(`Outer verifier (pinned): ${h} -> ${v}`);

  console.log({
    owner,
    scope,
    circuits: `${versionLabel} (${version})`,
    validity: validity.toString(),
    adapter: adapterKind,
    identifierType: typeName,
    oprfKeyHash,
    minAge,
    expiryMargin: expiryMargin.toString(),
    rebindDelay: rebindDelay.toString(),
    adapterDelay: adapterDelay.toString(),
    allowlistOnly,
    testAccounts,
  });

  // From the deployer, never the node's first account (anvil's #0 on a fork).
  const adapterName = pepper ? 'CofferdamZKPassportPepperAdapter' : 'ZKPassportEvidenceAdapter';
  const adapter = pepper
    ? await (await ethers.getContractFactory('CofferdamZKPassportPepperAdapter', deployer)).deploy(
        rootVerifier,
        helper,
        version,
        scope,
        validity,
        oprfKeyHash,
        minAge,
        expiryMargin,
        pins.map(([h]) => h),
        pins.map(([, v]) => v),
      )
    : await (await ethers.getContractFactory('ZKPassportEvidenceAdapter', deployer)).deploy(
        rootVerifier,
        helper,
        version,
        scope,
        validity,
        identifierType,
        oprfKeyHash,
        minAge,
        expiryMargin,
      );
  await adapter.waitForDeployment();
  out[adapterName] = await adapter.getAddress();
  console.log(`${adapterName}:`, out[adapterName]);

  const kind = zkpIdentifierKind(identifierType, oprfKeyHash);
  const scopeId = zkpScopeId(scope);
  if ((await adapter.identifierKind()) !== kind || (await adapter.scopeId()) !== scopeId) {
    throw new Error('The adapter reports another kind or scope than scripts/lib/identity.ts computes');
  }
  const Registry = await ethers.getContractFactory('CofferdamIdentityRegistry', deployer);
  const registry = await Registry.deploy(
    owner,
    kind,
    scopeId,
    rebindDelay,
    adapterDelay,
    [out[adapterName]],
    allowlistOnly,
    testAccounts,
  );
  await registry.waitForDeployment();
  out.CofferdamIdentityRegistry = await registry.getAddress();
  console.log('CofferdamIdentityRegistry:', out.CofferdamIdentityRegistry);

  const file = writeDeployments(network.name, chainId, out);
  console.log('Wrote', file);
  if (mainnet) console.log('Next: the account layer pinned to this registry (deploy-auth.ts with the same GENERATION).');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
