import { ethers, network } from 'hardhat';
import { assertMainnetSigner, chainId as nodeChainId, getDeployer, isBaseMainnetChain, mainnetDelay } from './lib/chain';
import { refuseRecordedGeneration, writeDeployments } from './lib/deployments';
import {
  ZKP_DOMAIN,
  ZKP_IDENTIFIER_TYPE,
  ZKP_ROOT_VERIFIER,
  zkpCircuitsVersion,
  zkpIdentifierKind,
  zkpScopeId,
} from './lib/identity';

// Deploys decision 0080's identity registry with its first evidence adapter,
// ZKPassport's RootVerifier checked on-chain (ruling T5). Nothing else.
//
//   GENERATION              Base mainnet only: the deployments file, e.g. zkp-test-1
//   LEDGER_ADDRESS          Base mainnet only: the deployer (hardhat.config.ts)
//   REGISTRY_OWNER          owner of the registry; required on mainnet (the
//                           founder's Ledger for the test generation, T3; the
//                           Safe for production)
//   ZKP_SCOPE               required; T1's test scope is cofferdam-zkp-test-1
//   ZKP_CIRCUITS_VERSION    default 0.21.1
//   ZKP_VALIDITY_SECONDS    default 3600, at most 86400
//   ZKP_IDENTIFIER_TYPE     non-salted (default) or salted
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
  await assertMainnetSigner(deployer.address);
  refuseRecordedGeneration(network.name, chainId, ['CofferdamIdentityRegistry', 'ZKPassportEvidenceAdapter']);

  const owner = process.env.REGISTRY_OWNER?.trim() || (mainnet ? '' : deployer.address);
  if (!owner || !ethers.isAddress(owner)) throw new Error('REGISTRY_OWNER is required on Base mainnet');

  const scope = process.env.ZKP_SCOPE?.trim();
  if (!scope) throw new Error('ZKP_SCOPE is required (T1: cofferdam-zkp-test-1 for the test generation, never reused)');
  const versionLabel = process.env.ZKP_CIRCUITS_VERSION?.trim() || '0.21.1';
  const version = zkpCircuitsVersion(versionLabel);
  const validity = BigInt(process.env.ZKP_VALIDITY_SECONDS?.trim() || '3600');
  const typeName = process.env.ZKP_IDENTIFIER_TYPE?.trim() || 'non-salted';
  if (typeName !== 'non-salted' && typeName !== 'salted') throw new Error('ZKP_IDENTIFIER_TYPE is non-salted or salted');
  const identifierType = typeName === 'salted' ? ZKP_IDENTIFIER_TYPE.salted : ZKP_IDENTIFIER_TYPE.nonSalted;
  const oprfKeyHash = process.env.ZKP_OPRF_KEY_HASH?.trim() || ethers.ZeroHash;
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
    const mockHelper = await (await ethers.getContractFactory('MockZKPassportHelper')).deploy();
    await mockHelper.waitForDeployment();
    const root = await (await ethers.getContractFactory('MockZKPassportRootVerifier')).deploy();
    await root.waitForDeployment();
    helper = await mockHelper.getAddress();
    await (await root.setHelper(version, helper)).wait();
    await (await root.setExpected(version, validity, ZKP_DOMAIN, scope, false)).wait();
    rootVerifier = await root.getAddress();
    out.MockZKPassportRootVerifier = rootVerifier;
    out.MockZKPassportHelper = helper;
  } else {
    helper = await (await ethers.getContractAt('IZKPassportRootVerifier', rootVerifier)).getHelper(version);
  }
  console.log('Helper (pinned):', helper);

  console.log({
    owner,
    scope,
    circuits: `${versionLabel} (${version})`,
    validity: validity.toString(),
    identifierType: typeName,
    oprfKeyHash,
    minAge,
    expiryMargin: expiryMargin.toString(),
    rebindDelay: rebindDelay.toString(),
    adapterDelay: adapterDelay.toString(),
    allowlistOnly,
    testAccounts,
  });

  const Adapter = await ethers.getContractFactory('ZKPassportEvidenceAdapter');
  const adapter = await Adapter.deploy(rootVerifier, helper, version, scope, validity, identifierType, oprfKeyHash, minAge, expiryMargin);
  await adapter.waitForDeployment();
  out.ZKPassportEvidenceAdapter = await adapter.getAddress();
  console.log('ZKPassportEvidenceAdapter:', out.ZKPassportEvidenceAdapter);

  const kind = zkpIdentifierKind(identifierType, oprfKeyHash);
  const scopeId = zkpScopeId(scope);
  if ((await adapter.identifierKind()) !== kind || (await adapter.scopeId()) !== scopeId) {
    throw new Error('The adapter reports another kind or scope than scripts/lib/identity.ts computes');
  }
  const Registry = await ethers.getContractFactory('CofferdamIdentityRegistry');
  const registry = await Registry.deploy(
    owner,
    kind,
    scopeId,
    rebindDelay,
    adapterDelay,
    [out.ZKPassportEvidenceAdapter],
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
