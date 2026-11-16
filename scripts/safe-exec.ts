import { ethers, network } from 'hardhat';
import { assertMainnetSigner, chainId as nodeChainId, getDeployer, isLocalFork, readSafe } from './lib/chain';
import { readDeployments, writeDeployments } from './lib/deployments';
import { SAFE_EXEC_ABI, activationRefusal, adapterKeyForVersion, parseSafeAction, safeExecRefusal, senderOwnerSignature } from './lib/safe';
import { zkpCircuitsVersion } from './lib/identity';

// Owner actions on a generation's identity registry, sent through the Safe that
// owns it, as production's will be (decision 0017; for zkp-test-1, the
// throwaway Safe of the M2 dev-key exception, signed by the CofferdamDev
// wallet alone, threshold 1). Each call is pre-flighted from the Safe's address,
// simulated, sent as `execTransaction` with the sender's pre-validated
// signature, and its effect read back.
//
//   SAFE_ACTION        pause-drill    setPaused(true), then setPaused(false)
//                      adapter-drill  proposeAdapter, then cancelAdapterProposal, on a
//                                     second copy of the live adapter (deployed once,
//                                     recorded as ZKPassportEvidenceAdapterDrill); it
//                                     never becomes active
//                      adapter-propose   ZKP_CIRCUITS_VERSION (e.g. 0.22.0): deploys once a copy of
//                                     the live adapter pinned to that version and RootVerifier's
//                                     helper for it (recorded as ZKPassportEvidenceAdapterV0_22_0),
//                                     then proposeAdapter; the timelock starts
//                      adapter-activate  ZKP_CIRCUITS_VERSION: activateAdapter, after the timelock
//                                     and within ADAPTER_GRACE
//                      set-test-account  setTestAccount(ACCOUNT, ALLOWED)
//                      pause / unpause   setPaused(true / false), for an incident
//   ACCOUNT, ALLOWED   set-test-account: the account; ALLOWED 1 (default) or 0
//   SAFE_ADDRESS       default the generation's recorded CofferdamSafe
//   IDENTITY_REGISTRY  default the generation's recorded CofferdamIdentityRegistry
//   IDENTITY_ADAPTER   the adapter copied, default the generation's recorded ZKPassportEvidenceAdapter
//
// On Base mainnet the generation's variables are the deploy's
// (MAINNET_DEV_KEY_EXCEPTION, GENERATION); a fork dry run passes SAFE_ADDRESS
// and IDENTITY_REGISTRY, since the fork's own deployments file is empty.


function pick(name: string, fromEnv: string | undefined, recorded: string | undefined): string {
  const env = fromEnv?.trim();
  if (env && recorded && env.toLowerCase() !== recorded.toLowerCase()) {
    throw new Error(`${name} ${env} differs from the generation's recorded ${recorded}`);
  }
  const address = env || recorded;
  if (!address || !ethers.isAddress(address)) throw new Error(`No ${name}: set it, or run with the generation's GENERATION`);
  return ethers.getAddress(address);
}

async function main() {
  const action = parseSafeAction(process.env.SAFE_ACTION);
  const signer = await getDeployer();
  const chainId = await nodeChainId();
  console.log(`Safe action ${action} on ${network.name} (chain ${chainId}) from ${signer.address}`);
  await assertMainnetSigner(signer.address);

  const recorded = readDeployments(network.name, chainId);
  const safeAddress = pick('SAFE_ADDRESS', process.env.SAFE_ADDRESS, recorded.CofferdamSafe?.address);
  const registryAddress = pick('IDENTITY_REGISTRY', process.env.IDENTITY_REGISTRY, recorded.CofferdamIdentityRegistry?.address);
  const refusal = safeExecRefusal(safeAddress, await readSafe(safeAddress), signer.address, recorded.CofferdamSafe?.address);
  if (refusal) throw new Error(refusal);
  // writeDeployments re-records the exception with REGISTRY_OWNER as the owner.
  const owner = process.env.REGISTRY_OWNER?.trim();
  if (owner && owner.toLowerCase() !== safeAddress.toLowerCase()) throw new Error(`REGISTRY_OWNER ${owner} is not the Safe ${safeAddress}`);
  process.env.REGISTRY_OWNER = safeAddress;

  const safe = new ethers.Contract(safeAddress, SAFE_EXEC_ABI, signer);
  // The full artifact, so a refusal decodes to the registry's own error name.
  const registry = await ethers.getContractAt('CofferdamIdentityRegistry', registryAddress);
  const registryOwner: string = await registry.owner();
  if (registryOwner.toLowerCase() !== safeAddress.toLowerCase()) {
    throw new Error(`The registry ${registryAddress} is owned by ${registryOwner}, not the Safe ${safeAddress}`);
  }
  console.log({ safe: safeAddress, registry: registryAddress, safeNonce: (await safe.nonce()).toString() });
  // base-anvil charges an eth_call's gas to its sender even at gas price 0, and
  // the Safe holds no ETH; Base's own nodes do not. On a fork only, give the
  // Safe a little test ETH so the pre-flight below runs as it does live.
  if ((await isLocalFork()) && (await ethers.provider.getBalance(safeAddress)) === 0n) {
    await ethers.provider.send('hardhat_setBalance', [safeAddress, ethers.toBeHex(ethers.parseEther('0.01'))]);
  }

  /** One call from the Safe to the registry. */
  async function exec(label: string, data: string) {
    // Pre-flight as the Safe, so a refusal comes back with the registry's own error.
    try {
      await ethers.provider.call({ from: safeAddress, to: registryAddress, data });
    } catch (e) {
      const raw = (e as { data?: string }).data;
      let reason = (e as Error).message;
      try {
        const parsed = raw ? registry.interface.parseError(raw) : null;
        if (parsed) reason = `${parsed.name}(${parsed.args.join(', ')})`;
      } catch {
        // not one of the listed errors
      }
      throw new Error(`${label}: the registry refuses it: ${reason}`);
    }
    const args = [registryAddress, 0, data, 0, 0, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, senderOwnerSignature(signer.address)] as const;
    await safe.execTransaction.staticCall(...args);
    const receipt = await (await safe.execTransaction(...args)).wait();
    const ok = receipt?.logs.some((log: { address: string; topics: readonly string[]; data: string }) => {
      if (log.address.toLowerCase() !== safeAddress.toLowerCase()) return false;
      try {
        return safe.interface.parseLog(log)?.name === 'ExecutionSuccess';
      } catch {
        return false;
      }
    });
    if (!ok) throw new Error(`${label}: no ExecutionSuccess from the Safe in ${receipt?.hash}`);
    console.log(`${label}: ${receipt?.hash} (gas ${receipt?.gasUsed})`);
  }

  const expect = (what: string, actual: unknown, wanted: unknown) => {
    if (actual !== wanted) throw new Error(`${what}: read ${actual}, expected ${wanted}`);
    console.log(`  ${what}: ${actual}`);
  };
  const iface = registry.interface;

  if (action === 'pause' || action === 'unpause' || action === 'pause-drill') {
    const steps = action === 'pause-drill' ? [true, false] : [action === 'pause'];
    if (action === 'pause-drill' && (await registry.paused())) throw new Error('The registry is paused already: unpause it first, or skip the drill');
    for (const paused of steps) {
      await exec(`setPaused(${paused})`, iface.encodeFunctionData('setPaused', [paused]));
      expect('paused', await registry.paused(), paused);
    }
  } else if (action === 'set-test-account') {
    const account = process.env.ACCOUNT?.trim();
    if (!account || !ethers.isAddress(account)) throw new Error('ACCOUNT is required: the test account address');
    const allowed = (process.env.ALLOWED?.trim() || '1') === '1';
    await exec(`setTestAccount(${ethers.getAddress(account)}, ${allowed})`, iface.encodeFunctionData('setTestAccount', [account, allowed]));
    expect('isTestAccount', await registry.isTestAccount(account), allowed);
  } else {
    // A second adapter built from what the live one reports: the same kind,
    // scope, validity, identifier type, minimum age and expiry margin, so the
    // registry takes the proposal; only the circuits version and its helper
    // may differ.
    const live = process.env.IDENTITY_ADAPTER?.trim() || recorded.ZKPassportEvidenceAdapter?.address;
    if (!live) throw new Error('No live adapter to copy: set IDENTITY_ADAPTER');
    if (!(await registry.isAdapter(live))) throw new Error(`${live} is not an active adapter of ${registryAddress}`);
    const a = await ethers.getContractAt('ZKPassportEvidenceAdapter', live);
    const label = (v: string) => [2, 6, 10].map((i) => parseInt(v.slice(i, i + 4), 16)).join('.');
    const deployCopy = async (version: string, helper: string): Promise<string> => {
      const Adapter = await ethers.getContractFactory('ZKPassportEvidenceAdapter', signer);
      const copy = await Adapter.deploy(
        await a.ROOT_VERIFIER(),
        helper,
        version,
        await a.scope(),
        await a.VALIDITY(),
        await a.IDENTIFIER_TYPE(),
        await a.OPRF_KEY_HASH(),
        await a.MIN_AGE(),
        await a.EXPIRY_MARGIN(),
      );
      await copy.waitForDeployment();
      const address = await copy.getAddress();
      if ((await copy.identifierKind()) !== (await registry.IDENTIFIER_KIND()) || (await copy.scopeId()) !== (await registry.SCOPE_ID())) {
        throw new Error(`The adapter ${address} reports another kind or scope than the registry`);
      }
      return address;
    };
    const delay: bigint = await registry.ADAPTER_DELAY();
    const grace: bigint = await registry.ADAPTER_GRACE();
    const now = async () => BigInt((await ethers.provider.getBlock('latest'))!.timestamp);
    const iso = (t: bigint) => new Date(Number(t) * 1000).toISOString();

    if (action === 'adapter-drill') {
      let drill = recorded.ZKPassportEvidenceAdapterDrill?.address;
      if (!drill) {
        drill = await deployCopy(await a.VERSION(), await a.HELPER());
        console.log('ZKPassportEvidenceAdapterDrill:', drill, '(deployed; never activated)');
        console.log('Wrote', writeDeployments(network.name, chainId, { ZKPassportEvidenceAdapterDrill: drill }));
      }
      if (await registry.isAdapter(drill)) throw new Error(`The drill adapter ${drill} is active: remove it through the Safe, not with this drill`);
      if ((await registry.adapterReadyAt(drill)) !== 0n) throw new Error(`The drill adapter ${drill} is proposed already: cancel it first`);
      await exec(`proposeAdapter(${drill})`, iface.encodeFunctionData('proposeAdapter', [drill]));
      const readyAt: bigint = await registry.adapterReadyAt(drill);
      const t = await now();
      if (readyAt < t || readyAt > t + delay) throw new Error(`adapterReadyAt ${readyAt} is not within the delay ${delay} of ${t}`);
      console.log(`  adapterReadyAt: ${readyAt} (${iso(readyAt)}, the ${delay}-second timelock)`);
      expect('isAdapter', await registry.isAdapter(drill), false);
      await exec(`cancelAdapterProposal(${drill})`, iface.encodeFunctionData('cancelAdapterProposal', [drill]));
      expect('adapterReadyAt after cancel', await registry.adapterReadyAt(drill), 0n);
      expect('isAdapter', await registry.isAdapter(drill), false);
    } else {
      // One adapter per ZKPassport circuits version: ZKPassport's app chooses
      // the version it proves in, and RootVerifier checks a proof under its own.
      const versionLabel = process.env.ZKP_CIRCUITS_VERSION?.trim();
      const key = adapterKeyForVersion(versionLabel);
      const version = zkpCircuitsVersion(versionLabel!);
      let adapterAddr = recorded[key]?.address;

      if (action === 'adapter-propose') {
        if ((await a.VERSION()) === version) throw new Error(`The live adapter ${live} pins circuits ${versionLabel} already`);
        const root = await ethers.getContractAt('IZKPassportRootVerifier', await a.ROOT_VERIFIER());
        const helper: string = await root.getHelper(version);
        if (helper === ethers.ZeroAddress) throw new Error(`ZKPassport's RootVerifier has no helper for circuits ${versionLabel}: it does not verify that version yet`);
        if (!adapterAddr) {
          adapterAddr = await deployCopy(version, helper);
          console.log(`${key}: ${adapterAddr} (circuits ${versionLabel}, helper ${helper})`);
          console.log('Wrote', writeDeployments(network.name, chainId, { [key]: adapterAddr }));
        } else {
          const recordedVersion: string = await (await ethers.getContractAt('ZKPassportEvidenceAdapter', adapterAddr)).VERSION();
          if (recordedVersion !== version) throw new Error(`${key} ${adapterAddr} pins circuits ${label(recordedVersion)}, not ${versionLabel}`);
          console.log(`${key}: ${adapterAddr} (recorded; not deployed again)`);
        }
        if (await registry.isAdapter(adapterAddr)) throw new Error(`${key} ${adapterAddr} is active already`);
        const pending: bigint = await registry.adapterReadyAt(adapterAddr);
        if (pending !== 0n) throw new Error(`${key} ${adapterAddr} is proposed already: activate it from ${iso(pending)} to ${iso(pending + grace)}`);
        await exec(`proposeAdapter(${adapterAddr})`, iface.encodeFunctionData('proposeAdapter', [adapterAddr]));
        const readyAt: bigint = await registry.adapterReadyAt(adapterAddr);
        const t = await now();
        if (readyAt < t || readyAt > t + delay) throw new Error(`adapterReadyAt ${readyAt} is not within the delay ${delay} of ${t}`);
        expect('isAdapter', await registry.isAdapter(adapterAddr), false);
        console.log(`  Activate with SAFE_ACTION=adapter-activate ZKP_CIRCUITS_VERSION=${versionLabel} from ${iso(readyAt)} until ${iso(readyAt + grace)}`);
      } else {
        if (!adapterAddr) throw new Error(`No ${key} recorded: propose it first (SAFE_ACTION=adapter-propose)`);
        const refusal = activationRefusal(await registry.adapterReadyAt(adapterAddr), await now(), grace);
        if (refusal) throw new Error(`${key} ${adapterAddr} cannot be activated: ${refusal}`);
        await exec(`activateAdapter(${adapterAddr})`, iface.encodeFunctionData('activateAdapter', [adapterAddr]));
        expect('isAdapter', await registry.isAdapter(adapterAddr), true);
        expect('adapterReadyAt', await registry.adapterReadyAt(adapterAddr), 0n);
      }
    }
  }
  console.log('Safe nonce now', (await safe.nonce()).toString());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
