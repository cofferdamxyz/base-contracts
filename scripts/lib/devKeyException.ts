// The M2 dev-key exception (the founder, 2026-11-14; workspace
// docs/runbooks/mainnet-deploys.md, "The M2 dev-key exception"). A temporary
// development exception, not a decision, for the MVP only and never for
// production: until Cofferdam Inc.'s Ledger is funded, the test generation
// `zkp-test-1` is deployed and owned by the CofferdamDev hot wallet. It departs
// from decision 0080 T3 and T4 and from decision 0017 (1) for that generation
// alone.
//
// The `base` network stays Ledger-only. The dev key reaches chain 8453 only on
// the `baseDevTest` network, only when MAINNET_DEV_KEY_EXCEPTION and
// GENERATION both name `zkp-test-1`, and only when the key is the CofferdamDev
// wallet's. Every other generation and signer on chain 8453 is refused.
//
// This module imports nothing from Hardhat, so hardhat.config.ts can use it
// and the tests can call it without a network. No function here prints or
// returns a key.

type Env = Record<string, string | undefined>;

export const DEV_KEY_EXCEPTION = {
  /** The variable that opts in; its value must be the generation. */
  env: 'MAINNET_DEV_KEY_EXCEPTION',
  /** The only generation the exception covers. */
  generation: 'zkp-test-1',
  /** The CofferdamDev hot wallet (Base Sepolia's deployer). */
  signer: '0x2c8A01e971d7C51B3B78f9F08c57c45584D96AB2',
  /** The only network that may carry the dev key on chain 8453. */
  network: 'baseDevTest',
  runbook: 'docs/runbooks/mainnet-deploys.md (workspace), "The M2 dev-key exception"',
} as const;

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** MAINNET_DEV_KEY_EXCEPTION is set (to anything). */
export function devKeyExceptionRequested(env: Env = process.env): boolean {
  return !!env[DEV_KEY_EXCEPTION.env]?.trim();
}

/**
 * Why a requested exception is refused, or null when it is well formed (or not
 * requested). It names `zkp-test-1` in MAINNET_DEV_KEY_EXCEPTION and in
 * GENERATION, and LEDGER_ADDRESS is not set alongside it.
 */
export function devKeyExceptionRefusal(env: Env = process.env): string | null {
  if (!devKeyExceptionRequested(env)) return null;
  const value = env[DEV_KEY_EXCEPTION.env]!.trim();
  if (value !== DEV_KEY_EXCEPTION.generation) {
    return `${DEV_KEY_EXCEPTION.env}=${value}: the dev-key exception covers ${DEV_KEY_EXCEPTION.generation} only`;
  }
  const generation = env.GENERATION?.trim();
  if (generation !== DEV_KEY_EXCEPTION.generation) {
    return `The dev-key exception needs GENERATION=${DEV_KEY_EXCEPTION.generation}; got ${generation || 'nothing'}. Every other generation on Base mainnet is the Ledger's`;
  }
  if (env.LEDGER_ADDRESS?.trim()) {
    return `Set LEDGER_ADDRESS or ${DEV_KEY_EXCEPTION.env}, not both`;
  }
  return null;
}

/**
 * The `baseDevTest` network's accounts: the dev key when the exception holds
 * and the key is the CofferdamDev wallet's, else none. Throws when the
 * exception is requested but malformed, or the key is another wallet's.
 * `deriveAddress` turns a private key into its address (ethers'
 * `computeAddress` in hardhat.config.ts).
 */
export function devKeyAccounts(env: Env, deriveAddress: (key: string) => string): string[] {
  if (!devKeyExceptionRequested(env)) return [];
  const refusal = devKeyExceptionRefusal(env);
  if (refusal) throw new Error(`hardhat.config.ts: ${refusal}`);
  const key = env.DEPLOYER_PRIVATE_KEY?.trim();
  if (!key) return [];
  let address: string;
  try {
    address = deriveAddress(key);
  } catch {
    throw new Error('hardhat.config.ts: DEPLOYER_PRIVATE_KEY is not a valid private key');
  }
  if (!same(address, DEV_KEY_EXCEPTION.signer)) {
    throw new Error(
      `hardhat.config.ts: DEPLOYER_PRIVATE_KEY is ${address}, not the CofferdamDev wallet ${DEV_KEY_EXCEPTION.signer}; the dev-key exception takes that wallet only`,
    );
  }
  return [key];
}

/**
 * hardhat.config.ts's last check: no network on chain 8453 lists a private
 * key, except `baseDevTest` while the exception holds. The in-process network
 * is local by construction and exempt.
 */
export function assertNoMainnetKeys(
  networks: Record<string, { chainId?: number; accounts?: unknown } | undefined>,
  env: Env = process.env,
): void {
  const exception = devKeyExceptionRequested(env) && devKeyExceptionRefusal(env) === null;
  for (const [name, net] of Object.entries(networks)) {
    if (name === 'hardhat' || !net || net.chainId !== 8453) continue;
    if (!Array.isArray(net.accounts) || net.accounts.length === 0) continue;
    if (name === DEV_KEY_EXCEPTION.network && exception && net.accounts.length === 1) continue;
    throw new Error(
      `hardhat.config.ts: network ${name} is chain 8453 and lists private keys; Base mainnet signs with the Ledger only (the dev-key exception: ${DEV_KEY_EXCEPTION.network} and ${DEV_KEY_EXCEPTION.env}=${DEV_KEY_EXCEPTION.generation} only)`,
    );
  }
}

export interface MainnetSignerContext {
  /** The node is a development node (a dry run). */
  fork: boolean;
  networkName: string;
  /** The network config lists private keys. */
  hasKeys: boolean;
  ledgerAccounts: string[];
  signer: string;
  env?: Env;
}

/**
 * Why `signer` may not deploy on chain 8453, or null when it may.
 *
 * - With the exception: GENERATION and the variable name zkp-test-1, the
 *   signer is the CofferdamDev wallet, and live runs go through `baseDevTest`
 *   only. A fork dry run checks the same, on any network.
 * - Without it: a dry run passes; live, no private key and a Ledger signer.
 */
export function mainnetSignerRefusal(ctx: MainnetSignerContext): string | null {
  const env = ctx.env ?? process.env;
  if (devKeyExceptionRequested(env)) {
    const refusal = devKeyExceptionRefusal(env);
    if (refusal) return refusal;
    if (!same(ctx.signer, DEV_KEY_EXCEPTION.signer)) {
      return `Under the dev-key exception the deployer must be the CofferdamDev wallet ${DEV_KEY_EXCEPTION.signer}; got ${ctx.signer}`;
    }
    if (!ctx.fork && ctx.networkName !== DEV_KEY_EXCEPTION.network) {
      return `The dev-key exception runs on the ${DEV_KEY_EXCEPTION.network} network only; ${ctx.networkName} stays Ledger-only`;
    }
    return null;
  }
  if (ctx.fork) return null;
  if (ctx.networkName === DEV_KEY_EXCEPTION.network) {
    return `${DEV_KEY_EXCEPTION.network} deploys only under the dev-key exception (${DEV_KEY_EXCEPTION.env}=${DEV_KEY_EXCEPTION.generation})`;
  }
  if (ctx.hasKeys) {
    return `Network ${ctx.networkName} reaches Base mainnet with private keys configured: refused (decision 0080)`;
  }
  if (!ctx.ledgerAccounts.some((a) => same(a, ctx.signer))) {
    return `On Base mainnet the deployer must be a Ledger account (LEDGER_ADDRESS); got ${ctx.signer}`;
  }
  return null;
}

/** Safe v1.4.1 on Base (canonical deployments; checked on chain by create-safe.ts). */
export const SAFE_V141 = {
  proxyFactory: '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67',
  singletonL2: '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762',
  singleton: '0x41675C099F32341bf84BFc5382aF534df5C7461a',
  fallbackHandler: '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99',
} as const;

/**
 * keccak256 of the runtime code every SafeProxy from the v1.4.1 factory runs
 * (171 bytes; the singleton sits in storage slot 0, so the code is the same
 * for every Safe; read from zkp-test-1's Safe on Base on 2026-11-26).
 */
export const SAFE_V141_PROXY_CODE_HASH = '0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c';

/**
 * The owner of the generation's registries on chain 8453. Under the exception
 * it is the CofferdamDev wallet by default, or REGISTRY_OWNER when that names
 * a Safe the wallet signs for (the founder, 2026-11-14: a Safe owns the
 * registries from their first block, as in production; `assertMainnetOwner`
 * in chain.ts checks it on chain). Otherwise REGISTRY_OWNER is required.
 */
export function mainnetRegistryOwner(env: Env = process.env): string {
  const fromEnv = env.REGISTRY_OWNER?.trim();
  if (devKeyExceptionRequested(env)) return fromEnv || DEV_KEY_EXCEPTION.signer;
  if (!fromEnv) throw new Error('REGISTRY_OWNER is required on Base mainnet: the company Safe (2-of-3)');
  return fromEnv;
}

export interface SafeFacts {
  /** The proxy's storage slot 0: its singleton (master copy). */
  singleton: string;
  owners: string[];
  threshold: bigint;
  /** Enabled modules (the first page of `getModulesPaginated`), when read. */
  modules?: string[];
  /** keccak256 of the address's runtime code, when read. */
  codeHash?: string;
}

/**
 * Why `owner` may not own the generation under the exception, or null. The
 * dev wallet itself may; anything else must be a Safe v1.4.1 proxy (code on
 * chain, `safe` read from it) with the dev wallet among its owners.
 */
export function exceptionOwnerRefusal(owner: string, safe: SafeFacts | null): string | null {
  if (same(owner, DEV_KEY_EXCEPTION.signer)) return null;
  if (!safe) return `REGISTRY_OWNER ${owner} is neither the CofferdamDev wallet nor a Safe on this chain`;
  if (!same(safe.singleton, SAFE_V141.singletonL2) && !same(safe.singleton, SAFE_V141.singleton)) {
    return `REGISTRY_OWNER ${owner} is not a Safe v1.4.1 proxy (singleton ${safe.singleton})`;
  }
  if (!safe.owners.some((o) => same(o, DEV_KEY_EXCEPTION.signer))) {
    return `The Safe ${owner} does not list the CofferdamDev wallet ${DEV_KEY_EXCEPTION.signer} among its owners`;
  }
  if (safe.threshold < 1n || safe.threshold > BigInt(safe.owners.length)) {
    return `The Safe ${owner} has threshold ${safe.threshold} over ${safe.owners.length} owners`;
  }
  return null;
}

/** What the generation's deployments file records about the exception. */
export function devKeyExceptionRecord(env: Env = process.env) {
  const owner = mainnetRegistryOwner(env);
  const safe = !same(owner, DEV_KEY_EXCEPTION.signer);
  return {
    name: 'M2 dev-key exception',
    generation: DEV_KEY_EXCEPTION.generation,
    deployer: DEV_KEY_EXCEPTION.signer,
    owner,
    note: safe
      ? "Deployed by the CofferdamDev hot wallet under the founder's temporary MVP exception (2026-11-14), not the Ledger; owned from the first block by a Safe the wallet signs for (the Ledger joins it once funded). Departs from decision 0080 T3/T4 and decision 0017 (1) for this generation only; never production. Paused and abandoned after the end-to-end bind test."
      : "Deployed and owned by the CofferdamDev hot wallet under the founder's temporary MVP exception (2026-11-14), not the Ledger. Departs from decision 0080 T3/T4 and decision 0017 (1) for this generation only; never production. Paused and abandoned after the end-to-end bind test.",
    runbook: DEV_KEY_EXCEPTION.runbook,
  };
}
