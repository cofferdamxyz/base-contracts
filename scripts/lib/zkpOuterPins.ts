import { ethers } from 'hardhat';
import { ZKP_OUTER_VERIFIERS_0_23_0 } from './identity';

// The outer verifiers a CofferdamZKPassportPepperAdapter pins (decision 0080,
// the pepper), read from ZKPassport's sub-verifier for the version. Shared by
// deploy-identity.ts and safe-exec.ts.

/** The vkey hash the mock sub-verifier lists its one mock outer verifier under. */
export const MOCK_OUTER_VKEY_HASH = ethers.id('mock-outer-vkey');

/**
 * The outer verifiers to pin: `listed` (ZKP_OUTER_VKEY_HASHES, comma-separated),
 * else the 0.23.0 table (scripts/lib/identity.ts), else the mock's one; each
 * verifier read from the version's sub-verifier, and a table entry checked
 * against it.
 */
export async function outerVerifierPins(
  rootVerifier: string,
  version: string,
  label: string,
  mocks: boolean,
  listedEnv = process.env.ZKP_OUTER_VKEY_HASHES,
): Promise<[string, string][]> {
  const root = await ethers.getContractAt('IZKPassportRootVerifierState', rootVerifier);
  const subAddress = await root.getSubVerifier(version);
  if (subAddress === ethers.ZeroAddress) throw new Error(`RootVerifier has no sub-verifier for circuits ${label}`);
  const sub = await ethers.getContractAt('IZKPassportSubVerifier', subAddress);
  const listed = listedEnv?.split(',').map((h) => h.trim()).filter(Boolean);
  const table = label === '0.23.0' ? ZKP_OUTER_VERIFIERS_0_23_0 : undefined;
  const hashes = listed?.length ? listed : mocks ? [MOCK_OUTER_VKEY_HASH] : table ? Object.keys(table) : [];
  if (hashes.length === 0) throw new Error(`Set ZKP_OUTER_VKEY_HASHES: no table of outer verifiers for circuits ${label}`);
  const pins: [string, string][] = [];
  for (const h of hashes) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(h)) throw new Error(`Not a vkey hash: ${h}`);
    const v = await sub.proofVerifiers(h);
    if (v === ethers.ZeroAddress) throw new Error(`The sub-verifier lists no outer verifier for ${h}`);
    const recorded = table?.[h.toLowerCase()];
    if (!mocks && recorded && recorded.toLowerCase() !== v.toLowerCase()) {
      throw new Error(`The sub-verifier lists ${v} for ${h}, the table ${recorded}: ZKPassport swapped it; check before pinning`);
    }
    pins.push([h, v]);
  }
  return pins;
}
