import { ethers, network } from 'hardhat';
import { chainId as nodeChainId, getDeployer, isLocalFork, readSafe } from './lib/chain';
import { deploymentsPath, readDeployments } from './lib/deployments';
import { chainRefusal, deployHandleAnchor, planeEnvLines, recordHandleAnchor } from './lib/handleAnchorDeploy';

// Deploys CofferdamHandleAnchor (workspace decision 0086, rule 3; runbook
// docs/runbooks/handles-build.md step 2) on Base Sepolia, owned from its first
// block by a Safe v1.4.1, with the plane's registrar key listed and Sepolia's
// short delays. Base mainnet is refused, a fork of it included (ruling I: the
// mainnet anchor waits on the Ledger and the production Safe). Every check runs
// before anything is sent (scripts/lib/handleAnchorDeploy.ts), and the anchor
// is read back at the block that mined it.
//
//   HANDLE_REGISTRAR_ADDRESS     required: the plane's own registrar hot key (ruling P);
//                                never the relayer, the deployer, the CofferdamDev
//                                wallet, the Safe or one of its signers
//   HANDLE_ANCHOR_SAFE           the owning Safe; default the recorded
//                                CofferdamHandleAnchorSafe, else CofferdamSafe
//                                (yarn safe:create:sepolia makes one)
//   HANDLE_CHANGE_DELAY_SECONDS  default 600 (owner changes; 72 h on mainnet)
//   HANDLE_FREEZE_SECONDS        default 1800 (a hold or veto; 14 d on mainnet; never 0)
//   HANDLE_QUARANTINE_SECONDS    default 86400 (a released label; 365 d on mainnet)
//   HANDLE_SAFE_DELAY_SECONDS    default 600 (the Safe's timelock; 72 h on mainnet)
//   RELAYER_ADDRESS              optional: refused as registrar, beside the
//                                recorded paymaster's relayer read on chain
//   HANDLE_ANCHOR_REDEPLOY=1     replace an anchor the deployments file records
//                                (it strands every handle claimed on it)
//   DRY_RUN=1                    the checks and a gas estimate; nothing sent
//
// Writes CofferdamHandleAnchor (address, txHash, blockNumber, deployer) and
// CofferdamHandleAnchorSafe into deployments/<network>.json, and prints the
// plane's HANDLE_ANCHOR_ADDRESS and HANDLE_ANCHOR_FROM_BLOCK.
async function main() {
  const chainId = await nodeChainId();
  const localDevNode = await isLocalFork();
  const refusal = chainRefusal(chainId, localDevNode);
  if (refusal) throw new Error(refusal);
  const deployer = await getDeployer();
  const dryRun = process.env.DRY_RUN?.trim() === '1';
  console.log(`Deploying CofferdamHandleAnchor on ${network.name} (chain ${chainId}) from ${deployer.address}${dryRun ? ' (DRY RUN)' : ''}`);

  const recorded = readDeployments(network.name, chainId);
  const safe = process.env.HANDLE_ANCHOR_SAFE?.trim() || recorded.CofferdamHandleAnchorSafe?.address || recorded.CofferdamSafe?.address;
  if (!safe) throw new Error(`No Safe: set HANDLE_ANCHOR_SAFE, or create one with yarn safe:create:sepolia (records CofferdamSafe in deployments/${network.name}.json)`);

  // The plane's relayer may never be the registrar: the recorded paymaster's, and RELAYER_ADDRESS.
  const relayers: string[] = [];
  const paymaster = recorded.CofferdamPaymaster?.address;
  if (paymaster && (await ethers.provider.getCode(paymaster)) !== '0x') {
    const relayer: string = await new ethers.Contract(paymaster, ['function relayer() view returns (address)'], ethers.provider).relayer();
    console.log(`  the recorded paymaster's relayer: ${relayer}`);
    relayers.push(relayer);
  }
  const relayerEnv = process.env.RELAYER_ADDRESS?.trim();
  if (relayerEnv) {
    if (!ethers.isAddress(relayerEnv)) throw new Error(`RELAYER_ADDRESS ${relayerEnv} is not an address`);
    relayers.push(relayerEnv);
  }

  const factory = await ethers.getContractFactory('CofferdamHandleAnchor', deployer);
  const deployed = await deployHandleAnchor({
    factory,
    deployer,
    provider: ethers.provider,
    localDevNode,
    env: process.env,
    safe,
    readSafe,
    relayers,
    recordedAnchor: recorded.CofferdamHandleAnchor?.address,
    dryRun,
    // Recorded as soon as it mines, before the read-back.
    onMined: (d) => {
      const file = deploymentsPath(network.name, chainId);
      recordHandleAnchor(file, d);
      console.log('Wrote', file);
      console.log('The plane (cofferdam-api, the Sepolia vars):');
      for (const line of planeEnvLines(d)) console.log(`  ${line}`);
    },
    log: (line) => console.log(line),
  });
  if (!deployed) return;

  console.log(
    [
      '\nNext:',
      `  verify:   DEPLOYER=${deployed.deployer} VERIFY_KEYS=CofferdamHandleAnchor yarn verify:sepolia`,
      `  drill:    SAFE_ACTION=anchor-registrar-schedule REGISTRAR=<a throwaway EOA, never the relayer, the deployer or a Safe signer> yarn safe:exec:sepolia, then anchor-registrar-add after ${deployed.delays.safeDelay} s, then anchor-registrar-remove`,
      '  mirrors:  cofferdam-api src/chain/deployments.ts, docs/architecture/contracts.md (deployments table), the app env when it reads the anchor',
    ].join('\n'),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
