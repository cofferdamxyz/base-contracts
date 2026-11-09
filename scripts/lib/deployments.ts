import * as fs from 'fs';
import * as path from 'path';
import { BASE_MAINNET_CHAIN_ID } from './chain';

const DEPLOYMENTS_DIR = path.join(__dirname, '..', '..', 'deployments');
const ZERO = '0x0000000000000000000000000000000000000000';

/**
 * The deployments file a script reads and writes.
 *
 * - Off Base mainnet: `deployments/<network>.json`, one file per network, as
 *   before (Base Sepolia keeps its single file and its mirrors).
 * - On Base mainnet (chain 8453, a fork included): one file per generation,
 *   `deployments/<network>.<GENERATION>.json`, for example
 *   `base.zkp-test-1.json` (decision 0080). Accounts are immutable, so a
 *   generation's addresses never change once written; a redeploy is a new
 *   GENERATION. Fork dry runs write under their own network name
 *   (`baseFork.*`, `hardhat.*`), which git ignores.
 */
export function deploymentsPath(networkName: string, chainId: bigint): string {
  if (chainId !== BASE_MAINNET_CHAIN_ID) return path.join(DEPLOYMENTS_DIR, `${networkName}.json`);
  const generation = process.env.GENERATION?.trim();
  if (!generation || !/^[a-z0-9][a-z0-9-]{0,40}$/.test(generation)) {
    throw new Error('On Base mainnet set GENERATION (lowercase letters, digits and dashes, e.g. zkp-test-1): one deployments file per generation');
  }
  return path.join(DEPLOYMENTS_DIR, `${networkName}.${generation}.json`);
}

/** Read the deployments file, or `{}` when it does not exist yet. */
export function readDeployments(networkName: string, chainId: bigint): Record<string, { address: string }> {
  const file = deploymentsPath(networkName, chainId);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
}

/**
 * Before deploying on Base mainnet: refuse when the generation's file already
 * records any of `names`, so a rerun stops before it spends gas instead of
 * after. A no-op elsewhere.
 */
export function refuseRecordedGeneration(networkName: string, chainId: bigint, names: string[]): void {
  if (chainId !== BASE_MAINNET_CHAIN_ID) return;
  const recorded = readDeployments(networkName, chainId);
  const taken = names.filter((n) => recorded[n]?.address);
  if (taken.length > 0) {
    throw new Error(
      `${path.basename(deploymentsPath(networkName, chainId))} already records ${taken.join(', ')}: a mainnet generation is deployed once (use a new GENERATION)`,
    );
  }
}

/**
 * Merge a set of deployed contract addresses into the deployments file.
 *
 * Every deploy script calls this so the file stays current no matter which
 * script (full deploy, auth-only, paymaster-only, self-only, escrow-only,
 * identity) ran last. Existing entries are preserved; only the keys passed in
 * are written. Empty/zero addresses are skipped so a partial run never wipes a
 * good entry. On Base mainnet an entry is never overwritten with another
 * address: that would be a new generation.
 */
export function writeDeployments(
  networkName: string,
  chainId: bigint,
  entries: Record<string, string | undefined>,
): string {
  if (!fs.existsSync(DEPLOYMENTS_DIR)) fs.mkdirSync(DEPLOYMENTS_DIR, { recursive: true });

  const registryPath = deploymentsPath(networkName, chainId);
  const registry = fs.existsSync(registryPath) ? JSON.parse(fs.readFileSync(registryPath, 'utf8')) : {};

  for (const [name, address] of Object.entries(entries)) {
    if (!address || address === ZERO) continue;
    const previous: string | undefined = registry[name]?.address;
    if (chainId === BASE_MAINNET_CHAIN_ID && previous && previous.toLowerCase() !== address.toLowerCase()) {
      throw new Error(
        `${path.basename(registryPath)} already records ${name} at ${previous}; a mainnet generation never changes (use a new GENERATION)`,
      );
    }
    registry[name] = { address };
  }

  fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2) + '\n');
  return registryPath;
}
