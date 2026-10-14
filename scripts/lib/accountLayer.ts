import { ethers, network } from 'hardhat';

// ERC-4337 EntryPoint v0.7 — preinstalled on Base
export const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

/**
 * Deploy the account layer (decision 0016): authority modules, the module
 * registry, the ceremony attester registry, the factory that pins both, and
 * the paymaster.
 *
 * - `REGISTRY_OWNER` owns both registries (the Cofferdam Safe on mainnet);
 *   defaults to the deployer off mainnet and is required on mainnet.
 * - `CEREMONY_ATTESTERS` is a comma-separated list of ceremony attester
 *   addresses; empty means first-High upgrades and Partner recoveries stay
 *   paused until the owner adds one.
 * - The raw P-256 `PasskeyAuthority` has no RP binding: it is deployed and
 *   listed only off mainnet.
 */
export async function deployAccountLayer(): Promise<Record<string, string>> {
  const [deployer] = await ethers.getSigners();
  const isMainnet = network.name === 'base';
  const owner = process.env.REGISTRY_OWNER || (isMainnet ? '' : deployer.address);
  if (!owner) throw new Error('REGISTRY_OWNER (the Cofferdam Safe) is required on mainnet');
  const attesters = (process.env.CEREMONY_ATTESTERS || '')
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => ethers.getAddress(a));

  async function deploy(name: string, args: unknown[] = []): Promise<string> {
    const c = await (await ethers.getContractFactory(name)).deploy(...args);
    await c.waitForDeployment();
    const addr = await c.getAddress();
    console.log(`${name}:`, addr);
    return addr;
  }

  const out: Record<string, string> = { EntryPoint: ENTRYPOINT_V07 };
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
  ]);
  out.CofferdamPaymaster = await deploy('CofferdamPaymaster', [ENTRYPOINT_V07]);
  if (attesters.length === 0) console.log('No CEREMONY_ATTESTERS: first-High upgrades are paused until one is added.');
  return out;
}
