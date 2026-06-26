import { ethers, network } from 'hardhat';
import * as fs from 'fs';
import * as path from 'path';

// ─────────────────────────────────────────────────────────────────────────────
// Account Inspector — reads on-chain state of a deployed CofferdamAccount4337
// and prints a human-readable summary: authorities, tiers, kinds, config blobs,
// ratchet status, EntryPoint binding, balance, nonce, and code presence.
//
// Usage:
//   hardhat run scripts/inspect-account.ts --network baseSepolia -- <address>
//   hardhat run scripts/inspect-account.ts --network baseSepolia -- <address> --tx <txhash>
// ─────────────────────────────────────────────────────────────────────────────

const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

const TIER_NAMES = ['None', 'LowUntrusted', 'LowManaged', 'High'] as const;

// Known kind hashes (keccak256 of the kind string)
const KIND_HASHES: Record<string, string> = {
  [ethers.id('passkey')]: 'passkey',
  [ethers.id('session')]: 'session',
  [ethers.id('polis_sso')]: 'polis_sso',
};

// Minimal ABIs (no Typechain needed — raw ethers.Interface)
const ACCOUNT_ABI = [
  'function ENTRY_POINT() view returns (address)',
  'function authorityCount() view returns (uint256)',
  'function passkeyCount() view returns (uint8)',
  'function upgradeLocked() view returns (bool)',
  'function getAuthority(uint256 authorityId) view returns (address module, uint8 tier, bool active, bytes config)',
  'function isValidSignature(bytes32 digest, bytes sig) view returns (bytes4)',
] as const;

const MODULE_ABI = [
  'function tier() view returns (uint8)',
  'function kind() pure returns (bytes32)',
] as const;

const FACTORY_ABI = [
  'function ENTRY_POINT() view returns (address)',
  'function getAddress(address initialModule, bytes initialConfig, bytes32 salt) view returns (address)',
  'event AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt)',
] as const;

interface AuthorityInfo {
  id: number;
  module: string;
  tierName: string;
  tierNum: number;
  active: boolean;
  kindHash: string;
  kindLabel: string;
  configRaw: string;
  configDecoded: string | null;
}

function decodeConfig(module: string, config: string): string | null {
  const configBytes = ethers.getBytes(config);
  if (configBytes.length === 64) {
    // PasskeyAuthority / WebAuthnPasskeyAuthority: abi.encode(bytes32 qx, bytes32 qy)
    const qx = ethers.hexlify(configBytes.slice(0, 32));
    const qy = ethers.hexlify(configBytes.slice(32, 64));
    return `P-256 public key:\n    qx: ${qx}\n    qy: ${qy}`;
  }
  if (configBytes.length === 32) {
    // SessionKeyAuthority: abi.encode(address sessionSigner)
    const signer = ethers.getAddress(ethers.hexlify(configBytes));
    return `Session signer: ${signer}`;
  }
  return null;
}

function loadDeployments(networkName: string): Record<string, { address: string }> {
  const depPath = path.join(__dirname, '..', 'deployments', `${networkName}.json`);
  if (fs.existsSync(depPath)) {
    return JSON.parse(fs.readFileSync(depPath, 'utf8'));
  }
  return {};
}

function resolveKnownModule(
  moduleAddr: string,
  deployments: Record<string, { address: string }>,
): string | null {
  const lower = moduleAddr.toLowerCase();
  for (const [name, info] of Object.entries(deployments)) {
    if (info.address.toLowerCase() === lower) return name;
  }
  return null;
}

async function inspectAccount(accountAddress: string, txHash?: string) {
  const provider = ethers.provider;
  const deployments = loadDeployments(network.name);

  console.log('═'.repeat(72));
  console.log('  Cofferdam Account Inspector');
  console.log(`  Network: ${network.name} (chainId ${network.config.chainId ?? '?'})`);
  console.log(`  Account: ${accountAddress}`);
  console.log('═'.repeat(72));

  // ── Basic checks ──────────────────────────────────────────────────────────
  const code = await provider.getCode(accountAddress);
  const isDeployed = code !== '0x';
  const balance = await provider.getBalance(accountAddress);
  const nonce = await provider.getTransactionCount(accountAddress);

  console.log('\n── Basic ────────────────────────────────────────────────────────────');
  console.log(`  Deployed:     ${isDeployed ? 'YES' : 'NO (counterfactual — not yet on-chain)'}`);
  console.log(`  Balance:      ${ethers.formatEther(balance)} ETH`);
  console.log(`  Nonce:        ${nonce}`);
  console.log(`  Code size:    ${isDeployed ? ethers.getBytes(code).length : 0} bytes`);

  if (!isDeployed) {
    console.log('\n  ⚠ Account not deployed. No on-chain state to inspect.');
    return;
  }

  // ── Account contract reads ────────────────────────────────────────────────
  const account = new ethers.Contract(accountAddress, ACCOUNT_ABI, provider);

  let entryPointAddr: string;
  try {
    entryPointAddr = await account.ENTRY_POINT();
  } catch {
    // ENTRY_POINT is immutable — read from bytecode if the getter isn't exposed
    entryPointAddr = '(immutable — read from bytecode)';
  }
  const authorityCount = await account.authorityCount();
  const passkeyCount = await account.passkeyCount();
  const upgradeLocked = await account.upgradeLocked();

  console.log('\n── Account Config ──────────────────────────────────────────────────');
  console.log(`  EntryPoint:   ${entryPointAddr}`);
  console.log(`  EP correct:   ${entryPointAddr.toLowerCase() === ENTRYPOINT_V07.toLowerCase() ? 'YES ✓' : 'NO ✗ (expected ' + ENTRYPOINT_V07 + ')'}`);
  console.log(`  Auth count:   ${authorityCount}`);
  console.log(`  Passkey count:${passkeyCount}`);
  console.log(`  Upgrade locked (ratchet fired): ${upgradeLocked ? 'YES ✓' : 'NO'}`);
  console.log(`  Max passkeys: 3`);

  // ── Authority inspection ──────────────────────────────────────────────────
  console.log('\n── Authorities ─────────────────────────────────────────────────────');

  const authorities: AuthorityInfo[] = [];

  for (let i = 0; i < Number(authorityCount); i++) {
    const [module, tierNum, active, config] = await account.getAuthority(i);
    const tierName = TIER_NAMES[Number(tierNum)] ?? `Unknown(${tierNum})`;

    // Read kind from the module contract
    let kindHash = '0x';
    let kindLabel = 'unknown';
    try {
      const moduleContract = new ethers.Contract(module, MODULE_ABI, provider);
      kindHash = await moduleContract.kind();
      kindLabel = KIND_HASHES[kindHash] ?? kindHash;
    } catch {
      // Module may not be reachable
    }

    const knownName = resolveKnownModule(module, deployments);
    const configDecoded = decodeConfig(module, config);

    const info: AuthorityInfo = {
      id: i,
      module,
      tierName,
      tierNum: Number(tierNum),
      active,
      kindHash,
      kindLabel,
      configRaw: config,
      configDecoded,
    };

    authorities.push(info);

    console.log(`\n  [${i}] ${active ? '● ACTIVE' : '○ REVOKED'}`);
    console.log(`      Module:    ${module}${knownName ? ` (${knownName})` : ''}`);
    console.log(`      Tier:      ${tierName} (${tierNum})`);
    console.log(`      Kind:      ${kindLabel}`);
    if (configDecoded) {
      console.log(`      Config:    ${configDecoded}`);
    } else {
      console.log(`      Config:    ${config} (raw, ${ethers.getBytes(config).length} bytes)`);
    }
  }

  // ── Ratchet / security summary ────────────────────────────────────────────
  console.log('\n── Security Summary ────────────────────────────────────────────────');

  const activePasskeys = authorities.filter((a) => a.active && a.tierName === 'High');
  const activeLowUntrusted = authorities.filter((a) => a.active && a.tierName === 'LowUntrusted');
  const activeLowManaged = authorities.filter((a) => a.active && a.tierName === 'LowManaged');
  const revoked = authorities.filter((a) => !a.active);

  console.log(`  Active passkeys:     ${activePasskeys.length} / 3 max`);
  console.log(`  Active LowUntrusted: ${activeLowUntrusted.length}`);
  console.log(`  Active LowManaged:   ${activeLowManaged.length}`);
  console.log(`  Revoked authorities: ${revoked.length}`);

  if (upgradeLocked && activePasskeys.length > 0) {
    console.log('  Ratchet:             FIRED ✓ (passkey-first, untrusted locked out)');
  } else if (!upgradeLocked && activeLowUntrusted.length > 0 && activePasskeys.length === 0) {
    console.log('  Ratchet:             NOT FIRED (legacy-first, awaiting passkey enrolment)');
  } else if (!upgradeLocked && activePasskeys.length === 0 && activeLowUntrusted.length === 0) {
    console.log('  Ratchet:             NOT FIRED (no passkey, no untrusted — unusual state)');
  } else {
    console.log('  Ratchet:             UNKNOWN STATE — review manually');
  }

  if (activeLowUntrusted.length > 0 && upgradeLocked) {
    console.log('  ⚠ WARNING: Active LowUntrusted authority with ratchet fired — unexpected!');
  }

  // ── Transaction analysis (if tx hash provided) ────────────────────────────
  if (txHash) {
    console.log('\n── Deployment Transaction ──────────────────────────────────────────');
    try {
      const tx = await provider.getTransaction(txHash);
      const receipt = await provider.getTransactionReceipt(txHash);

      if (tx) {
        console.log(`  Hash:        ${txHash}`);
        console.log(`  Block:       ${receipt?.blockNumber ?? 'pending'}`);
        console.log(`  From:        ${tx.from}`);
        console.log(`  To:          ${tx.to}`);
        console.log(`  Gas used:    ${receipt?.gasUsed?.toString() ?? '?'}`);
        console.log(`  Gas price:   ${tx.gasPrice?.toString() ?? '?'} wei`);
        console.log(`  Status:      ${receipt?.status === 1 ? 'SUCCESS ✓' : 'FAILED ✗'}`);
        console.log(`  Value:       ${ethers.formatEther(tx.value)} ETH`);

        // Check if 'to' is the factory
        const factoryName = tx.to ? resolveKnownModule(tx.to, deployments) : null;
        if (factoryName) {
          console.log(`  Factory:     ${tx.to} (${factoryName})`);
        }

        // Decode logs
        if (receipt?.logs?.length) {
          console.log(`\n  Events (${receipt.logs.length}):`);
          for (const log of receipt.logs) {
            const knownFactory = resolveKnownModule(log.address, deployments);
            const topic0 = log.topics[0];
            if (topic0 === ethers.id('AccountDeployed(address,address,bytes32)')) {
              // account and initialModule are indexed (topics 1,2); salt is in data
              const account = ethers.getAddress('0x' + log.topics[1].slice(26));
              const initialModule = ethers.getAddress('0x' + log.topics[2].slice(26));
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ['bytes32'],
                log.data,
              );
              const salt = decoded[0];
              console.log(`    [${log.index}] AccountDeployed from ${knownFactory ?? log.address}`);
              console.log(`         account:  ${account}`);
              console.log(`         module:   ${initialModule}`);
              console.log(`         salt:     ${salt}`);
            } else if (topic0 === ethers.id('AuthorityAdded(uint256,address,uint8,bytes32)')) {
              const authId = BigInt(log.topics[1]);
              const moduleAddr = ethers.getAddress('0x' + log.topics[2].slice(26));
              // tier and kind are NOT indexed — decoded from log.data
              const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
                ['uint8', 'bytes32'],
                log.data,
              );
              const tier = Number(decoded[0]);
              const kindHash = decoded[1];
              console.log(`    [${log.index}] AuthorityAdded from ${knownFactory ?? log.address}`);
              console.log(`         authorityId: ${authId}`);
              console.log(`         module:      ${moduleAddr}`);
              console.log(`         tier:        ${TIER_NAMES[tier] ?? tier} (${tier})`);
              console.log(`         kind:        ${KIND_HASHES[kindHash] ?? kindHash}`);
            } else {
              console.log(`    [${log.index}] Unknown event from ${knownFactory ?? log.address}`);
              console.log(`         topic0: ${topic0}`);
            }
          }
        }
      } else {
        console.log(`  ⚠ Transaction not found: ${txHash}`);
      }
    } catch (e) {
      console.log(`  ⚠ Error fetching transaction: ${(e as Error).message}`);
    }
  }

  // ── Interpretation ────────────────────────────────────────────────────────
  console.log('\n── Interpretation ──────────────────────────────────────────────────');

  if (activePasskeys.length > 0 && upgradeLocked && activeLowUntrusted.length === 0) {
    console.log('  ✓ Healthy passkey-first account.');
    console.log('    The account was bootstrapped with a hardware passkey (High tier).');
    console.log('    The one-way ratchet has fired — no untrusted authority can ever');
    console.log('    be added. This is the sovereign-first onboarding path.');
  } else if (activeLowUntrusted.length > 0 && !upgradeLocked && activePasskeys.length === 0) {
    console.log('  ⚠ Legacy-first account (pre-passkey).');
    console.log('    Bootstrapped with a LowUntrusted session key. The ratchet has NOT');
    console.log('    fired — a passkey can still be enrolled via enrollFirstPasskey.');
    console.log('    Once enrolled, the LowUntrusted authority will be permanently');
    console.log('    deactivated.');
  } else if (activeLowManaged.length > 0 && activePasskeys.length > 0) {
    console.log('  ✓ Enterprise account (OR semantics).');
    console.log('    Has both a managed (Polis SSO) authority and a passkey.');
    console.log('    The managed authority is NOT ratchet-locked and coexists with');
    console.log('    the passkey for enterprise-managed access.');
  } else {
    console.log('  ⚠ Unusual state — review authority configuration manually.');
  }

  if (balance === 0n) {
    console.log('  ℹ Account has 0 ETH — gas must be sponsored by paymaster or');
    console.log('    the account must be funded via EntryPoint.depositTo().');
  }

  console.log('\n' + '═'.repeat(72));
}

// ── CLI entry ────────────────────────────────────────────────────────────────
// Hardhat's `run` command doesn't accept extra CLI args, so we use env vars:
//   ACCOUNT=0x... TX=0x... yarn inspect:account --network baseSepolia
async function main() {
  const addressArg = process.env.ACCOUNT;
  const txHash = process.env.TX;

  if (!addressArg || !ethers.isAddress(addressArg)) {
    console.error('Usage: ACCOUNT=0x... [TX=0x...] yarn inspect:account --network <network>');
    console.error('  Example: ACCOUNT=0xABf27176feCB5f1Be3acB40c235D26fEea504E98 \\\n           TX=0x7afa2ffd... yarn inspect:account --network baseSepolia');
    process.exit(1);
  }

  await inspectAccount(addressArg, txHash);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
