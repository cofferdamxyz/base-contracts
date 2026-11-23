import { ethers, network } from 'hardhat';
import { assertMainnetSigner, chainId as nodeChainId, getDeployer, isLocalFork, readSafe } from './lib/chain';
import { readDeployments, writeDeployments } from './lib/deployments';
import {
  ADAPTER_CONTRACT,
  SAFE_EXEC_ABI,
  type AdapterKind,
  activationRefusal,
  adapterDrillKey,
  adapterKeyForVersion,
  liveAdapterAddress,
  parseAllowed,
  parseSafeAction,
  reproposalRefusal,
  safeExecRefusal,
  senderOwnerSignature,
} from './lib/safe';
import { zkpCircuitsVersion } from './lib/identity';
import { outerVerifierPins } from './lib/zkpOuterPins';
import { CofferdamZKPassportPepperAdapter__factory, ZKPassportEvidenceAdapter__factory, type ZKPassportEvidenceAdapter } from '../typechain-types';
import { isAnchorSafeAction } from './lib/handleAnchor';
import { runAnchorSafeAction } from './lib/handleAnchorExec';

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
//                                     recorded as ZKPassportEvidenceAdapterDrill, or
//                                     CofferdamZKPassportPepperAdapterDrill for the pepper's);
//                                     it never becomes active
//                      adapter-propose   ZKP_CIRCUITS_VERSION (e.g. 0.22.0): deploys once a copy of
//                                     the live adapter pinned to that version and RootVerifier's
//                                     helper for it (recorded as ZKPassportEvidenceAdapterV0_22_0,
//                                     or CofferdamZKPassportPepperAdapterV0_24_0 for the pepper's),
//                                     then proposeAdapter; the timelock starts. A live proposal
//                                     is refused; an expired one is proposed again (the clock restarts)
//                      adapter-activate  ZKP_CIRCUITS_VERSION: activateAdapter, after the timelock
//                                     and within ADAPTER_GRACE
//                      adapter-cancel    ZKP_CIRCUITS_VERSION: cancelAdapterProposal
//                      set-test-account  setTestAccount(ACCOUNT, ALLOWED)
//                      pause / unpause   setPaused(true / false), for an incident
//   ACCOUNT, ALLOWED   set-test-account: the account; ALLOWED 1 (add, the default) or 0 (remove)
//   DRILL_CANCEL_LEFTOVER  adapter-drill: 1 cancels a drill proposal an earlier run left, then drills
//   SAFE_ADDRESS       default the generation's recorded CofferdamSafe
//   IDENTITY_REGISTRY  default the generation's recorded CofferdamIdentityRegistry
//   IDENTITY_ADAPTER   the adapter copied, default the one the generation recorded
//                      (ZKPassportEvidenceAdapter or CofferdamZKPassportPepperAdapter;
//                      a generation that records both must set it)
//   ZKP_OUTER_VKEY_HASHES  adapter-propose of a pepper adapter: the new version's outer
//                      verification-key hashes to pin, comma-separated (0.23.0 has a
//                      table in scripts/lib/identity.ts); each verifier is read from
//                      ZKPassport's sub-verifier for that version
//
// A copy is of the live adapter's own kind: a pepper generation's copies are
// CofferdamZKPassportPepperAdapter (decision 0080, P1), with the same OPRF key
// hash, scope, validity, minimum age and expiry margin. The drill's copy pins
// the live adapter's outer verifiers; a per-version copy pins the new version's.
//
// A per-version adapter is proposed or activated only while it pins that
// version and the helper RootVerifier names for it now, and, for the pepper's,
// only while ZKPassport's sub-verifier for that version still lists every
// outer verifier it pinned: after a swap it would refuse those proofs.
// adapter-cancel checks none of this, so it withdraws such an adapter.
//
// On Base mainnet the generation's variables are the deploy's
// (MAINNET_DEV_KEY_EXCEPTION, GENERATION); a fork dry run passes SAFE_ADDRESS
// and IDENTITY_REGISTRY and starts from no fork deployments file
// (rm deployments/baseFork.<GENERATION>.json), since adapter-drill and
// adapter-propose record what they deploy there.
//
// Effects are read back at the block that mined the transaction, so a public
// endpoint's lagging backend cannot report the state before it.
//
// The handle anchor's actions (workspace decision 0086, rule 3), sent to
// CofferdamHandleAnchor instead of the registry. Timelocked ones are scheduled,
// then executed after its SAFE_DELAY and within SAFE_OP_GRACE:
//
//   SAFE_ACTION        anchor-registrar-schedule, anchor-registrar-add   REGISTRAR (timelocked)
//                      anchor-registrar-remove                           REGISTRAR (immediate)
//                      anchor-rekey-schedule, anchor-rekey               HANDLE_LABEL or HANDLE_ID, NEW_OWNER,
//                                                                        META_ADDRESS (timelocked; also on a
//                                                                        frozen or released record)
//                      anchor-force-release-schedule, anchor-force-release
//                                                                        HANDLE_LABEL or HANDLE_ID, QUARANTINE
//                                                                        1 (default) or 0 (timelocked)
//                      anchor-cancel-op                                  SAFE_OP_ID (a scheduled operation)
//                      anchor-lift-freeze                                HANDLE_LABEL or HANDLE_ID (immediate)
//                      anchor-transfer-ownership                         NEW_SAFE (two-step, timelocked)
//                      anchor-cancel-ownership-transfer                  withdraws the nomination
//                      anchor-accept-ownership                           SAFE_ADDRESS the new Safe, which
//                                                                        must be the anchor's pendingOwner;
//                                                                        after the SAFE_DELAY timelock
//   HANDLE_ANCHOR      default the generation's recorded CofferdamHandleAnchor
//   SAFE_ADDRESS       for anchor-* actions, default the recorded CofferdamHandleAnchorSafe, else
//                      CofferdamSafe. After anchor-accept-ownership, record the new Safe as
//                      CofferdamHandleAnchorSafe in the generation's deployments file (never by
//                      editing CofferdamSafe, which is the identity registry's Safe too)


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
  if (isAnchorSafeAction(action)) {
    const anchorAddress = pick('HANDLE_ANCHOR', process.env.HANDLE_ANCHOR, recorded.CofferdamHandleAnchor?.address);
    // anchor-accept-ownership is sent by the NEW Safe, which is not the
    // recorded one yet: it is taken from SAFE_ADDRESS, and runAnchorSafeAction
    // checks it is the anchor's pendingOwner. Every other action is the
    // recorded Safe's.
    // The anchor's Safe is recorded as CofferdamHandleAnchorSafe once it differs
    // from the generation's CofferdamSafe (after a handover), so the identity
    // registry's Safe record is never re-pointed for it.
    const accepting = action === 'anchor-accept-ownership';
    const anchorSafe = recorded.CofferdamHandleAnchorSafe?.address ?? recorded.CofferdamSafe?.address;
    const safeAddress = accepting
      ? pick('SAFE_ADDRESS', process.env.SAFE_ADDRESS, undefined)
      : pick('SAFE_ADDRESS', process.env.SAFE_ADDRESS, anchorSafe);
    const refused = safeExecRefusal(safeAddress, await readSafe(safeAddress), signer.address, accepting ? undefined : anchorSafe);
    if (refused) throw new Error(refused);
    if ((await isLocalFork()) && (await ethers.provider.getBalance(safeAddress)) === 0n) {
      await ethers.provider.send('hardhat_setBalance', [safeAddress, ethers.toBeHex(ethers.parseEther('0.01'))]);
    }
    const artifact = await ethers.getContractFactory('CofferdamHandleAnchor');
    await runAnchorSafeAction({
      action,
      env: process.env,
      provider: ethers.provider,
      signer,
      safeAddress,
      anchorAddress,
      errorInterface: artifact.interface,
      log: (line) => console.log(line),
    });
    return;
  }
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

  /** One call from the Safe to the registry; returns the block that mined it. */
  async function exec(label: string, data: string): Promise<number> {
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
    return receipt!.blockNumber;
  }

  /**
   * A read at `blockTag`, retried while a lagging backend does not have that
   * block yet (the node's head is below it); any other error is thrown at once.
   */
  async function at<T>(blockTag: number, read: (o: { blockTag: number }) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await read({ blockTag });
      } catch (e) {
        if (attempt === 10 || (await ethers.provider.getBlockNumber().catch(() => -1)) >= blockTag) throw e;
        await new Promise((r) => setTimeout(r, 3_000));
      }
    }
  }
  const blockTime = async (blockTag: number): Promise<bigint> => {
    const block = await at(blockTag, async () => {
      const b = await ethers.provider.getBlock(blockTag);
      if (!b) throw new Error(`No block ${blockTag} yet`);
      return b;
    });
    return BigInt(block.timestamp);
  };

  const expect = (what: string, actual: unknown, wanted: unknown) => {
    if (actual !== wanted) throw new Error(`${what}: read ${actual}, expected ${wanted}`);
    console.log(`  ${what}: ${actual}`);
  };
  const iface = registry.interface;

  if (action === 'pause' || action === 'unpause' || action === 'pause-drill') {
    const steps = action === 'pause-drill' ? [true, false] : [action === 'pause'];
    if (action === 'pause-drill' && (await registry.paused())) throw new Error('The registry is paused already: unpause it first, or skip the drill');
    let mined: number | undefined;
    try {
      for (const paused of steps) {
        mined = await exec(`setPaused(${paused})`, iface.encodeFunctionData('setPaused', [paused]));
        expect('paused', await at(mined, (o) => registry.paused(o)), paused);
      }
    } catch (e) {
      // A drill stopped after its pause leaves binds refused: say so, loudly,
      // read no earlier than its last mined transaction.
      if (action === 'pause-drill') {
        const state = await (mined === undefined ? registry.paused() : at(mined, (o) => registry.paused(o))).then(
          (p: boolean) => (p ? 'The registry is PAUSED: binds are refused until SAFE_ACTION=unpause' : 'The registry reads unpaused'),
          () => 'paused() could not be read: check it, and run SAFE_ACTION=unpause if it is true',
        );
        console.error(`\nThe pause drill stopped part-way. ${state}.\n`);
      }
      throw e;
    }
  } else if (action === 'set-test-account') {
    const account = process.env.ACCOUNT?.trim();
    if (!account || !ethers.isAddress(account)) throw new Error('ACCOUNT is required: the test account address');
    const allowed = parseAllowed(process.env.ALLOWED);
    console.log(`${allowed ? 'ADD' : 'REMOVE'} test account ${ethers.getAddress(account)}`);
    const block = await exec(`setTestAccount(${ethers.getAddress(account)}, ${allowed})`, iface.encodeFunctionData('setTestAccount', [account, allowed]));
    expect('isTestAccount', await at(block, (o) => registry.isTestAccount(account, o)), allowed);
  } else {
    // A second adapter built from what the live one reports: the same kind,
    // scope, validity, identifier type, minimum age and expiry margin, so the
    // registry takes the proposal; only the circuits version and its helper
    // (and, for the pepper's, the outer verifiers pinned) may differ.
    const live = ethers.getAddress(liveAdapterAddress(process.env.IDENTITY_ADAPTER, recorded));
    if (!(await registry.isAdapter(live))) throw new Error(`${live} is not an active adapter of ${registryAddress}`);
    const kind = await adapterKindOf(live);
    for (const k of ['root-verifier', 'pepper'] as const) {
      if (k !== kind && recorded[ADAPTER_CONTRACT[k]]?.address?.toLowerCase() === live.toLowerCase()) {
        throw new Error(`${live} is recorded as ${ADAPTER_CONTRACT[k]} but is a ${ADAPTER_CONTRACT[kind]}`);
      }
    }
    console.log(`Live adapter ${live} (${ADAPTER_CONTRACT[kind]})`);
    const a = adapterAt(kind, live);
    const label = (v: string) => [2, 6, 10].map((i) => parseInt(v.slice(i, i + 4), 16)).join('.');
    /** The live pepper adapter's own pins, as the drill's copy takes them. */
    const livePins = async (): Promise<[string, string][]> => {
      const p = pepperAt(live);
      return Promise.all((await p.vkeyHashes()).map(async (h: string): Promise<[string, string]> => [h, await p.outerVerifier(h)]));
    };
    const deployCopy = async (version: string, helper: string, pins: [string, string][]): Promise<string> => {
      const common = [await a.ROOT_VERIFIER(), helper, version, await a.scope(), await a.VALIDITY()] as const;
      const copy =
        kind === 'pepper'
          ? await (await ethers.getContractFactory('CofferdamZKPassportPepperAdapter', signer)).deploy(
              ...common,
              await a.OPRF_KEY_HASH(),
              await a.MIN_AGE(),
              await a.EXPIRY_MARGIN(),
              pins.map(([h]) => h),
              pins.map(([, v]) => v),
            )
          : await (await ethers.getContractFactory('ZKPassportEvidenceAdapter', signer)).deploy(
              ...common,
              await (await ethers.getContractAt('ZKPassportEvidenceAdapter', live)).IDENTIFIER_TYPE(),
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
      const drillKey = adapterDrillKey(kind);
      let drill = recorded[drillKey]?.address;
      if (!drill) {
        drill = await deployCopy(await a.VERSION(), await a.HELPER(), kind === 'pepper' ? await livePins() : []);
        console.log(`${drillKey}:`, drill, '(deployed; never activated)');
        console.log('Wrote', writeDeployments(network.name, chainId, { [drillKey]: drill }));
      }
      if (await registry.isAdapter(drill)) throw new Error(`The drill adapter ${drill} is active: remove it through the Safe, not with this drill`);
      if ((await registry.adapterReadyAt(drill)) !== 0n) {
        // Left by a drill that stopped between its two transactions. Cancelling
        // it is a transaction of its own, so only when asked.
        if (process.env.DRILL_CANCEL_LEFTOVER?.trim() !== '1') {
          throw new Error(`The drill adapter ${drill} is still proposed from an earlier run: rerun with DRILL_CANCEL_LEFTOVER=1 to cancel it first`);
        }
        const block = await exec(`cancelAdapterProposal(${drill})`, iface.encodeFunctionData('cancelAdapterProposal', [drill]));
        expect('adapterReadyAt after cancel', await at(block, (o) => registry.adapterReadyAt(drill, o)), 0n);
      }
      const proposed = await exec(`proposeAdapter(${drill})`, iface.encodeFunctionData('proposeAdapter', [drill]));
      const readyAt: bigint = await at(proposed, (o) => registry.adapterReadyAt(drill, o));
      expect('adapterReadyAt', readyAt, (await blockTime(proposed)) + delay);
      console.log(`  (${iso(readyAt)}, the ${delay}-second timelock)`);
      expect('isAdapter', await at(proposed, (o) => registry.isAdapter(drill, o)), false);
      const cancelled = await exec(`cancelAdapterProposal(${drill})`, iface.encodeFunctionData('cancelAdapterProposal', [drill]));
      expect('adapterReadyAt after cancel', await at(cancelled, (o) => registry.adapterReadyAt(drill, o)), 0n);
      expect('isAdapter', await at(cancelled, (o) => registry.isAdapter(drill, o)), false);
    } else {
      // One adapter per ZKPassport circuits version: ZKPassport's app chooses
      // the version it proves in, and RootVerifier checks a proof under its own.
      const versionLabel = process.env.ZKP_CIRCUITS_VERSION?.trim();
      const key = adapterKeyForVersion(versionLabel, kind);
      const version = zkpCircuitsVersion(versionLabel!);
      let adapterAddr = recorded[key]?.address;
      /** RootVerifier's helper for this version now (propose and activate only: cancel never depends on it). */
      const currentHelper = async (): Promise<string> =>
        (await ethers.getContractAt('IZKPassportRootVerifier', await a.ROOT_VERIFIER())).getHelper(version);
      /**
       * The recorded adapter pins this version and RootVerifier's helper for it
       * now, or it would refuse every proof; a pepper adapter's outer verifiers
       * must all still be the ones ZKPassport's sub-verifier lists.
       */
      const checkRecorded = async (address: string, helper: string) => {
        const recordedAdapter = adapterAt(kind, address);
        const recordedVersion: string = await recordedAdapter.VERSION();
        if (recordedVersion !== version) throw new Error(`${key} ${address} pins circuits ${label(recordedVersion)}, not ${versionLabel}`);
        const recordedHelper: string = await recordedAdapter.HELPER();
        if (recordedHelper.toLowerCase() !== helper.toLowerCase()) {
          throw new Error(
            `${key} ${address} pins the helper ${recordedHelper}, but ZKPassport's RootVerifier names ${helper} for circuits ${versionLabel} now: ` +
              'it would refuse every proof. Cancel its proposal (SAFE_ACTION=adapter-cancel); a replacement needs its own deployments key',
          );
        }
        if (kind === 'pepper') {
          const p = pepperAt(address);
          const root = await ethers.getContractAt('IZKPassportRootVerifierState', await a.ROOT_VERIFIER());
          const sub = await ethers.getContractAt('IZKPassportSubVerifier', await root.getSubVerifier(version));
          for (const h of await p.vkeyHashes()) {
            const pinned = await p.outerVerifier(h);
            const listed = await sub.proofVerifiers(h);
            if (listed.toLowerCase() !== pinned.toLowerCase()) {
              throw new Error(
                `${key} ${address} pins the outer verifier ${pinned} for ${h}, but ZKPassport's sub-verifier lists ${listed} now: ` +
                  'it would refuse those proofs. Cancel its proposal (SAFE_ACTION=adapter-cancel); a replacement needs its own deployments key',
              );
            }
          }
        }
      };

      if (action === 'adapter-propose') {
        if ((await a.VERSION()) === version) throw new Error(`The live adapter ${live} pins circuits ${versionLabel} already`);
        if (kind === 'pepper') {
          const min: string = await pepperAt(live).MIN_VERSION();
          if (BigInt(version) < BigInt(min)) throw new Error(`The pepper adapter reads circuits ${label(min)} or later; ${versionLabel} is older`);
        }
        const helper = await currentHelper();
        if (helper === ethers.ZeroAddress) throw new Error(`ZKPassport's RootVerifier has no helper for circuits ${versionLabel}: it does not verify that version yet`);
        if (!adapterAddr) {
          const pins = kind === 'pepper' ? await outerVerifierPins(await a.ROOT_VERIFIER(), version, versionLabel!, false) : [];
          for (const [h, v] of pins) console.log(`  Outer verifier (pinned): ${h} -> ${v}`);
          adapterAddr = await deployCopy(version, helper, pins);
          console.log(`${key}: ${adapterAddr} (circuits ${versionLabel}, helper ${helper})`);
          console.log('Wrote', writeDeployments(network.name, chainId, { [key]: adapterAddr }));
        } else {
          await checkRecorded(adapterAddr, helper);
          console.log(`${key}: ${adapterAddr} (recorded; not deployed again)`);
        }
        if (await registry.isAdapter(adapterAddr)) throw new Error(`${key} ${adapterAddr} is active already`);
        const pending: bigint = await registry.adapterReadyAt(adapterAddr);
        const refusal = reproposalRefusal(pending, await now(), grace);
        if (refusal) throw new Error(`${key} ${adapterAddr}: ${refusal}`);
        if (pending !== 0n) console.log(`  Its proposal expired at ${iso(pending + grace)}: proposing it again restarts the ${delay}-second timelock`);
        const block = await exec(`proposeAdapter(${adapterAddr})`, iface.encodeFunctionData('proposeAdapter', [adapterAddr]));
        const readyAt: bigint = await at(block, (o) => registry.adapterReadyAt(adapterAddr!, o));
        expect('adapterReadyAt', readyAt, (await blockTime(block)) + delay);
        expect('isAdapter', await at(block, (o) => registry.isAdapter(adapterAddr!, o)), false);
        console.log(`  Activate with SAFE_ACTION=adapter-activate ZKP_CIRCUITS_VERSION=${versionLabel} from ${iso(readyAt)} until ${iso(readyAt + grace)}`);
      } else if (action === 'adapter-activate') {
        if (!adapterAddr) throw new Error(`No ${key} recorded: propose it first (SAFE_ACTION=adapter-propose)`);
        await checkRecorded(adapterAddr, await currentHelper());
        const refusal = activationRefusal(await registry.adapterReadyAt(adapterAddr), await now(), grace);
        if (refusal) throw new Error(`${key} ${adapterAddr} cannot be activated: ${refusal}`);
        const block = await exec(`activateAdapter(${adapterAddr})`, iface.encodeFunctionData('activateAdapter', [adapterAddr]));
        expect('isAdapter', await at(block, (o) => registry.isAdapter(adapterAddr!, o)), true);
        expect('adapterReadyAt', await at(block, (o) => registry.adapterReadyAt(adapterAddr!, o)), 0n);
      } else {
        // adapter-cancel: by version and kind only, so it never touches the live adapter or the drill.
        if (!adapterAddr) throw new Error(`No ${key} recorded: nothing to cancel`);
        if (await registry.isAdapter(adapterAddr)) throw new Error(`${key} ${adapterAddr} is active: a cancel cannot undo that (removeAdapter is not this script's)`);
        if ((await registry.adapterReadyAt(adapterAddr)) === 0n) throw new Error(`${key} ${adapterAddr} is not proposed`);
        const block = await exec(`cancelAdapterProposal(${adapterAddr})`, iface.encodeFunctionData('cancelAdapterProposal', [adapterAddr]));
        expect('adapterReadyAt', await at(block, (o) => registry.adapterReadyAt(adapterAddr!, o)), 0n);
        expect('isAdapter', await at(block, (o) => registry.isAdapter(adapterAddr!, o)), false);
      }
    }
  }
  console.log('Safe nonce now', (await safe.nonce()).toString());
}

/** The getters both adapter contracts share, the ones a copy is built from. */
type AdapterCommon = Pick<
  ZKPassportEvidenceAdapter,
  'ROOT_VERIFIER' | 'HELPER' | 'VERSION' | 'scope' | 'VALIDITY' | 'OPRF_KEY_HASH' | 'MIN_AGE' | 'EXPIRY_MARGIN'
>;

/** An adapter of `kind` at `address`, as the getters both contracts share. */
function adapterAt(kind: AdapterKind, address: string): AdapterCommon {
  return kind === 'pepper' ? pepperAt(address) : ZKPassportEvidenceAdapter__factory.connect(address, ethers.provider);
}

const pepperAt = (address: string) => CofferdamZKPassportPepperAdapter__factory.connect(address, ethers.provider);

/**
 * Which adapter contract is at `address`: the pepper's answers `vkeyHashes()`,
 * which ZKPassportEvidenceAdapter does not have, so the call reverts (ethers
 * reports CALL_EXCEPTION, Hardhat's provider "execution reverted"). Any other
 * failure, a timeout say, is thrown.
 */
async function adapterKindOf(address: string): Promise<AdapterKind> {
  try {
    await pepperAt(address).vkeyHashes();
    return 'pepper';
  } catch (e) {
    const { code, message } = e as { code?: string; message?: string };
    if (code === 'CALL_EXCEPTION' || code === 'BAD_DATA' || /execution reverted/i.test(message ?? '')) return 'root-verifier';
    throw e;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
