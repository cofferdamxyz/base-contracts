import { ethers, network } from 'hardhat';
import { assertMainnetSigner, chainId as nodeChainId, getDeployer, mainnetDelay } from './chain';
import { readDeployments, refuseRecordedGeneration } from './deployments';
import { accountCodeFingerprint, paymasterRelayer } from './paymaster';

// ERC-4337 EntryPoint v0.7 — preinstalled on Base
export const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

/**
 * Deploy the account layer (decisions 0016, 0023): authority modules, the
 * module registry, the ceremony attester registry, the factory that pins them
 * with the nullifier registry and the hard-recovery delay, and the paymaster.
 *
 * - `REGISTRY_OWNER` owns both registries (the Cofferdam Safe on mainnet);
 *   defaults to the deployer off mainnet and is required on mainnet.
 * - `CEREMONY_ATTESTERS` is a comma-separated list of ceremony attester
 *   addresses; empty means first-High upgrades and Partner recoveries stay
 *   paused until the owner adds one.
 * - The raw P-256 `PasskeyAuthority` has no RP binding: it is deployed and
 *   listed only off mainnet.
 * - `nullifierRegistry` (or `NULLIFIER_REGISTRY`, else the `NullifierRegistry`
 *   entry in the deployments file) is pinned into every account for hard
 *   recovery; deploy it first (`deploy-self.ts`).
 * - On Base mainnet (chain 8453, a fork included) Self's registry never goes:
 *   the factory pins the generation's `CofferdamIdentityRegistry`
 *   (`IDENTITY_REGISTRY`, else the generation file's entry; `deploy-identity.ts`
 *   first). That is decision 0080's test generation: binds and rebinds work,
 *   `recoverHigh` reverts, since today's account calls Self's `provenNullifier`.
 *   The deployer must be the Ledger, and the generation's file must not
 *   already hold an account layer.
 * - `RECOVERY_DELAY_SECONDS` is the hard-recovery delay pinned into every
 *   account: 72 hours on mainnet, 0 elsewhere by default.
 * - `PROBATION_PERIOD_SECONDS` is the probation of a High added by a High:
 *   72 hours on mainnet, 600 seconds elsewhere by default.
 * - `RELAYER_ADDRESS` is the plane's relayer EOA, the only `tx.origin` the
 *   paymaster sponsors; required off the local networks. The paymaster is
 *   testnet only: mainnet deploys none (the CDP Paymaster, decision 0017).
 */
export async function deployAccountLayer(nullifierRegistry?: string): Promise<Record<string, string>> {
  const deployer = await getDeployer();
  const chainId = await nodeChainId();
  // By the chain id the node reports, so a fork of mainnet takes this path too.
  const isMainnet = chainId === 8453n;
  await assertMainnetSigner(deployer.address);
  const owner = process.env.REGISTRY_OWNER || (isMainnet ? '' : deployer.address);
  if (!owner) throw new Error('REGISTRY_OWNER (the Cofferdam Safe; the Ledger for the test generation) is required on mainnet');
  // The paymaster is testnet only.
  const skipPaymaster = isMainnet;
  const relayer = skipPaymaster ? '' : paymasterRelayer(deployer.address);
  const attesters = (process.env.CEREMONY_ATTESTERS || '')
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => ethers.getAddress(a));

  const recorded = readDeployments(network.name, chainId);
  let pinned: string | undefined;
  if (isMainnet) {
    refuseRecordedGeneration(network.name, chainId, ['CofferdamAccountFactory4337', 'CofferdamModuleRegistry']);
    if (nullifierRegistry || process.env.NULLIFIER_REGISTRY?.trim()) {
      throw new Error("Self's NullifierRegistry never goes to Base mainnet (decision 0080): set IDENTITY_REGISTRY");
    }
    // The generation's file is the record: an env value may only repeat it,
    // and the factory's registry is written to the same file below.
    const fromEnv = process.env.IDENTITY_REGISTRY?.trim();
    const fromFile = recorded.CofferdamIdentityRegistry?.address;
    if (fromEnv && fromFile && fromEnv.toLowerCase() !== fromFile.toLowerCase()) {
      throw new Error(`IDENTITY_REGISTRY ${fromEnv} differs from the generation's CofferdamIdentityRegistry ${fromFile}`);
    }
    pinned = fromEnv || fromFile;
    if (!pinned || !ethers.isAddress(pinned)) {
      throw new Error('No CofferdamIdentityRegistry: deploy it first (deploy-identity.ts) or set IDENTITY_REGISTRY');
    }
    const registry = await ethers.getContractAt('CofferdamIdentityRegistry', pinned);
    if ((await ethers.provider.getCode(pinned)) === '0x') throw new Error(`No contract at IDENTITY_REGISTRY ${pinned}`);
    if ((await registry.REBIND_DELAY()) < 259_200n) throw new Error('The identity registry rebinds in less than 72 hours');
  } else {
    pinned = nullifierRegistry || process.env.NULLIFIER_REGISTRY?.trim() || recorded.NullifierRegistry?.address;
    if (!pinned || !ethers.isAddress(pinned)) {
      throw new Error('No NullifierRegistry: deploy it first (deploy-self.ts) or set NULLIFIER_REGISTRY');
    }
    if ((await ethers.provider.getCode(pinned)) === '0x') throw new Error(`No contract at NULLIFIER_REGISTRY ${pinned}`);
  }
  const nullifier = pinned;
  const recoveryDelay = await mainnetDelay('RECOVERY_DELAY_SECONDS', 0n);
  console.log(isMainnet ? 'CofferdamIdentityRegistry (pinned):' : 'NullifierRegistry (pinned):', nullifier);
  console.log('recoveryDelay:', recoveryDelay.toString(), 'seconds');
  const probationPeriod = await mainnetDelay('PROBATION_PERIOD_SECONDS', 600n);
  if (probationPeriod >= 2n ** 48n) throw new Error('PROBATION_PERIOD_SECONDS does not fit uint48');
  console.log('probationPeriod:', probationPeriod.toString(), 'seconds');

  async function deploy(name: string, args: unknown[] = []): Promise<string> {
    const c = await (await ethers.getContractFactory(name)).deploy(...args);
    await c.waitForDeployment();
    const addr = await c.getAddress();
    console.log(`${name}:`, addr);
    return addr;
  }

  const out: Record<string, string> = { EntryPoint: ENTRYPOINT_V07 };
  // On mainnet the generation's file records the registry its factory pins.
  if (isMainnet) out.CofferdamIdentityRegistry = nullifier;
  if (!isMainnet) out.PasskeyAuthority = await deploy('PasskeyAuthority');
  out.WebAuthnPasskeyAuthority = await deploy('WebAuthnPasskeyAuthority');
  out.PartnerPasskeyAuthority = await deploy('PartnerPasskeyAuthority');
  out.SessionKeyAuthorityLowManaged = await deploy('SessionKeyAuthority');

  const modules = [
    out.PasskeyAuthority,
    out.WebAuthnPasskeyAuthority,
    out.PartnerPasskeyAuthority,
    out.SessionKeyAuthorityLowManaged,
  ].filter(Boolean);
  out.CofferdamModuleRegistry = await deploy('CofferdamModuleRegistry', [owner, modules]);
  out.CofferdamCeremonyAttesterRegistry = await deploy('CofferdamCeremonyAttesterRegistry', [owner, attesters]);
  out.CofferdamAccountFactory4337 = await deploy('CofferdamAccountFactory4337', [
    ENTRYPOINT_V07,
    out.CofferdamModuleRegistry,
    out.CofferdamCeremonyAttesterRegistry,
    nullifier,
    recoveryDelay,
    probationPeriod,
  ]);
  if (skipPaymaster) {
    console.log('No CofferdamPaymaster on mainnet: gas goes through the CDP Paymaster (decision 0017).');
  } else {
    const fp = await accountCodeFingerprint(out.CofferdamAccountFactory4337, out.WebAuthnPasskeyAuthority);
    console.log('Paymaster relayer:', relayer, '| account code hash:', fp.codeHash, `(${fp.codeSize} bytes, ${fp.maskOffsets.length} masked words)`);
    out.CofferdamPaymaster = await deploy('CofferdamPaymaster', [ENTRYPOINT_V07, relayer, fp.codeHash, fp.codeSize, fp.maskOffsets]);
  }
  if (attesters.length === 0) console.log('No CEREMONY_ATTESTERS: first-High upgrades are paused until one is added.');
  return out;
}
