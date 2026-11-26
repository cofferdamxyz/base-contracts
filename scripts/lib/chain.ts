import { ethers, network } from 'hardhat';
import { productionOwnerRefusal } from './productionSafe';
import { readSafeFacts } from './safeFacts';
import {
  DEV_KEY_EXCEPTION,
  SafeFacts,
  devKeyExceptionRefusal,
  devKeyExceptionRequested,
  exceptionOwnerRefusal,
  mainnetSignerRefusal,
} from './devKeyException';

// Guards for deploy scripts (decision 0080, 9). They read the chain id from
// the node, never the network's name, so a dry run on a fork of Base mainnet
// (`yarn node:start:base` plus `--network baseFork`, or `BASE_FORK=1` on the
// in-process network) runs every mainnet guard.

export const BASE_MAINNET_CHAIN_ID = 8453n;
/** The least delay a mainnet generation pins (decisions 0022, 0023, 0080). */
export const MIN_MAINNET_DELAY_SECONDS = 259_200n;

/** The chain id the node reports. */
export async function chainId(): Promise<bigint> {
  return (await ethers.provider.getNetwork()).chainId;
}

export async function isBaseMainnetChain(): Promise<boolean> {
  return (await chainId()) === BASE_MAINNET_CHAIN_ID;
}

/**
 * The node is a development node (the in-process Hardhat network, anvil or a
 * Hardhat node), so nothing it signs reaches a public chain. Asked of the node
 * itself, never read from the URL: a real Base node or an RPC tunnel can
 * listen on 127.0.0.1 too.
 */
export async function isLocalFork(): Promise<boolean> {
  if (network.name === 'hardhat') return true;
  for (const method of ['anvil_nodeInfo', 'hardhat_metadata']) {
    try {
      await ethers.provider.send(method, []);
      return true;
    } catch {
      // not a development node, or not this kind
    }
  }
  return false;
}

/**
 * A fork's receipt, waited for through the forked RPC's refusals. anvil can
 * answer `eth_sendTransaction` before the block that holds the transaction is
 * in its store, and asks the forked RPC for a receipt it does not hold yet; an
 * RPC that serves recent state only refuses that (publicnode on 2026-11-16:
 * "Archive requests require a personal token"), and the wait throws although
 * the transaction mines. `wait` is retried on that refusal only, `attempts`
 * times, `delayMs` apart; a revert or any other error throws at once.
 */
export async function forkReceipt<T>(wait: () => Promise<T>, attempts = 10, delayMs = 1000): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await wait();
    } catch (error) {
      if (attempt >= attempts || !isForkTransportError(error)) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

/** anvil's error for a request it passed to the forked RPC, which refused or failed it. */
export function isForkTransportError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('Fork Error: Transport');
}

/** Throw on Base mainnet (or a fork of it): for scripts whose contracts never go there. */
export async function refuseMainnet(what: string): Promise<void> {
  if (await isBaseMainnetChain()) {
    throw new Error(`${what} never deploys to Base mainnet (chain 8453), a fork of it included (decision 0080)`);
  }
}

/**
 * On Base mainnet the deployer is the Ledger (decision 0017; the founder's
 * Ledger for the test generation, T3). The `base` network has no private keys
 * (hardhat.config.ts), so a signer there can only come from `ledgerAccounts`;
 * this checks it once more against the network the script actually reached.
 *
 * The one departure is the M2 dev-key exception (./devKeyException.ts): with
 * MAINNET_DEV_KEY_EXCEPTION=zkp-test-1 the deployer must be the CofferdamDev
 * wallet, GENERATION zkp-test-1 and the network `baseDevTest`. A local fork
 * runs the same checks, then says that this is a dry run.
 */
export async function assertMainnetSigner(signer: string): Promise<void> {
  if (!(await isBaseMainnetChain())) {
    if (devKeyExceptionRequested()) {
      throw new Error(`${DEV_KEY_EXCEPTION.env} is for Base mainnet (chain 8453) only; unset it`);
    }
    return;
  }
  const fork = await isLocalFork();
  const cfg = network.config as { accounts?: unknown; ledgerAccounts?: string[] };
  const refusal = mainnetSignerRefusal({
    fork,
    networkName: network.name,
    hasKeys: Array.isArray(cfg.accounts) && cfg.accounts.length > 0,
    ledgerAccounts: cfg.ledgerAccounts ?? [],
    signer,
  });
  if (refusal) throw new Error(refusal);
  if (devKeyExceptionRequested()) {
    console.log(
      `M2 DEV-KEY EXCEPTION: ${DEV_KEY_EXCEPTION.generation} deployed by the CofferdamDev wallet ${DEV_KEY_EXCEPTION.signer}, not the Ledger. MVP only, never production.`,
    );
  }
  if (fork) console.log(`DRY RUN: chain 8453 on a local fork (${network.name}); nothing reaches Base mainnet.`);
}

/**
 * The deployer: the Ledger when LEDGER_ADDRESS is set (the plugin lists it
 * after the node's own accounts, so it must be picked by address), else the
 * first signer. On a local fork an unfunded Ledger gets test ETH, so the
 * Ledger dry run needs no faucet. On `base` the only signer is LEDGER_ADDRESS.
 *
 * Under the dev-key exception it is the CofferdamDev wallet: on `baseDevTest`
 * the configured key, and on a local fork the wallet impersonated (no key
 * needed), given test ETH only when it holds none, so a funded wallet's real
 * balance is what the dry run spends.
 */
export async function getDeployer() {
  if (devKeyExceptionRequested()) {
    const refusal = devKeyExceptionRefusal();
    if (refusal) throw new Error(refusal);
    const dev = DEV_KEY_EXCEPTION.signer;
    if ((await isBaseMainnetChain()) && (await isLocalFork())) {
      for (const method of ['anvil_impersonateAccount', 'hardhat_impersonateAccount']) {
        try {
          await ethers.provider.send(method, [dev]);
          break;
        } catch {
          // the other kind of node
        }
      }
      if ((await ethers.provider.getBalance(dev)) === 0n) {
        await ethers.provider.send('hardhat_setBalance', [dev, ethers.toBeHex(ethers.parseEther('10'))]);
      }
      return ethers.getSigner(dev);
    }
    const [deployer] = await ethers.getSigners();
    if (!deployer) {
      throw new Error(`No signer on ${network.name}: the dev-key exception needs DEPLOYER_PRIVATE_KEY (the CofferdamDev wallet) in .env`);
    }
    return deployer;
  }
  const ledger = process.env.LEDGER_ADDRESS?.trim();
  const listed = ((network.config as { ledgerAccounts?: string[] }).ledgerAccounts ?? []).map((a) => a.toLowerCase());
  if (ledger && listed.includes(ledger.toLowerCase())) {
    const signer = await ethers.getSigner(ledger);
    if ((await isLocalFork()) && (await ethers.provider.getBalance(ledger)) < ethers.parseEther('1')) {
      await ethers.provider.send('hardhat_setBalance', [ledger, ethers.toBeHex(ethers.parseEther('10'))]);
    }
    return signer;
  }
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(`No signer on ${network.name}: Base mainnet signs with the Ledger only; set LEDGER_ADDRESS (decision 0080)`);
  }
  return deployer;
}

/** The Safe facts of `address`, or null when it has no code or does not answer as a Safe (./safeFacts.ts). */
export async function readSafe(address: string): Promise<SafeFacts | null> {
  return readSafeFacts(ethers.provider, address);
}

/**
 * The owner of a contract on chain 8453 (a fork included), read from the
 * chain. Under the dev-key exception: the CofferdamDev wallet or a Safe v1.4.1
 * it signs for (./devKeyException.ts). Otherwise the company Safe: a Safe
 * v1.4.1 with at least three owners, threshold 2 or more and no module
 * (./productionSafe.ts; the founder's ruling of 2026-11-26). A no-op off
 * chain 8453.
 */
export async function assertMainnetOwner(owner: string): Promise<void> {
  if (!(await isBaseMainnetChain())) return;
  const facts = await readSafe(owner);
  const refusal = devKeyExceptionRequested() ? exceptionOwnerRefusal(owner, facts) : productionOwnerRefusal(owner, facts);
  if (refusal) throw new Error(refusal);
}

/** A delay from the environment, at least 72 hours on Base mainnet. */
export async function mainnetDelay(name: string, offMainnetDefault: bigint): Promise<bigint> {
  const raw = process.env[name]?.trim();
  const mainnet = await isBaseMainnetChain();
  const value = raw ? BigInt(raw) : mainnet ? MIN_MAINNET_DELAY_SECONDS : offMainnetDefault;
  if (mainnet && value < MIN_MAINNET_DELAY_SECONDS) throw new Error(`${name} must be at least 72 hours on Base mainnet`);
  return value;
}
