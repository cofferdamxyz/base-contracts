import * as fs from 'fs';
import * as path from 'path';

/**
 * Merge a set of deployed contract addresses into deployments/<network>.json.
 *
 * Every deploy script calls this so the registry file stays current no matter
 * which script (full deploy, auth-only, paymaster-only, self-only, escrow-only)
 * was last run. Existing entries are preserved; only the keys passed in are
 * overwritten. Empty/zero addresses are skipped so a partial run never wipes a
 * good entry.
 */
export function writeDeployments(
  networkName: string,
  entries: Record<string, string | undefined>,
): string {
  const deploymentsDir = path.join(__dirname, '..', '..', 'deployments');
  if (!fs.existsSync(deploymentsDir)) fs.mkdirSync(deploymentsDir, { recursive: true });

  const registryPath = path.join(deploymentsDir, `${networkName}.json`);
  const registry = fs.existsSync(registryPath)
    ? JSON.parse(fs.readFileSync(registryPath, 'utf8'))
    : {};

  for (const [name, address] of Object.entries(entries)) {
    if (address && address !== '0x0000000000000000000000000000000000000000') {
      registry[name] = { address };
    }
  }

  fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2) + '\n');
  return registryPath;
}
