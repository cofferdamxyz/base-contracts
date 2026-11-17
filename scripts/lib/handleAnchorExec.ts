// The anchor's Safe actions for scripts/safe-exec.ts (workspace decision
// 0086, rule 3): one call from the Safe to CofferdamHandleAnchor, pre-flighted
// from the Safe's address so a refusal comes back with the anchor's own error,
// sent as `execTransaction` with the sender's pre-validated signature, and its
// effect read back. Takes its provider and signer as arguments, so the fork
// test drives it without the script.

import { ethers } from 'ethers';
import { SAFE_EXEC_ABI, senderOwnerSignature } from './safe';
import { AnchorSafeAction, anchorCall } from './handleAnchor';

export const HANDLE_ANCHOR_EXEC_ABI = [
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function isRegistrar(address) view returns (bool)',
  'function safeOpReadyAt(bytes32) view returns (uint256)',
  'function isFrozen(bytes32) view returns (bool)',
  'function SAFE_DELAY() view returns (uint256)',
  'function SAFE_OP_GRACE() view returns (uint256)',
  'function addRegistrarOpId(address) pure returns (bytes32)',
  'function rekeyOpId(bytes32,address,bytes) pure returns (bytes32)',
  'function forceReleaseOpId(bytes32,bool) pure returns (bytes32)',
  'function resolve(bytes32) view returns (address handleOwner, uint256 serial, bytes metaAddress, bool derivable)',
  'function claimableAt(bytes32) view returns (uint256)',
  'function scheduleAddRegistrar(address)',
  'function executeAddRegistrar(address)',
  'function removeRegistrar(address)',
  'function scheduleRekey(bytes32,address,bytes)',
  'function executeRekey(bytes32,address,bytes)',
  'function scheduleForceRelease(bytes32,bool)',
  'function executeForceRelease(bytes32,bool)',
  'function cancelSafeOp(bytes32)',
  'function liftFreeze(bytes32)',
  'function transferOwnership(address)',
  'function acceptOwnership()',
];

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/**
 * Run one anchor action through the Safe. `errorInterface` (the anchor's
 * full ABI, from its artifact) decodes refusals; `log` prints progress.
 * Returns the block that mined the call.
 */
export async function runAnchorSafeAction(o: {
  action: AnchorSafeAction;
  env: NodeJS.ProcessEnv;
  provider: ethers.Provider;
  signer: ethers.Signer;
  safeAddress: string;
  anchorAddress: string;
  errorInterface?: ethers.Interface;
  log?: (line: string) => void;
}): Promise<number> {
  const log = o.log ?? (() => {});
  const call = anchorCall(o.action, o.env);
  const anchor = new ethers.Contract(o.anchorAddress, HANDLE_ANCHOR_EXEC_ABI, o.provider);
  const iface = anchor.interface;

  // Who may send it: the Safe owns the anchor, or (accept) is its pending owner.
  const anchorOwner: string = await anchor.owner();
  if (o.action === 'anchor-accept-ownership') {
    const pending: string = await anchor.pendingOwner();
    if (!same(pending, o.safeAddress)) throw new Error(`The anchor's pending owner is ${pending}, not the Safe ${o.safeAddress}`);
  } else if (!same(anchorOwner, o.safeAddress)) {
    throw new Error(`The anchor ${o.anchorAddress} is owned by ${anchorOwner}, not the Safe ${o.safeAddress}`);
  }

  // Refusals the anchor would give, said in plain words before anything is sent.
  if (o.action === 'anchor-rekey' || o.action === 'anchor-force-release' || o.action === 'anchor-registrar-add') {
    const opId: string =
      o.action === 'anchor-rekey'
        ? await anchor.rekeyOpId(...(call.args as [string, string, string]))
        : o.action === 'anchor-force-release'
          ? await anchor.forceReleaseOpId(...(call.args as [string, boolean]))
          : await anchor.addRegistrarOpId(call.args[0] as string);
    const readyAt: bigint = await anchor.safeOpReadyAt(opId);
    if (readyAt === 0n) throw new Error(`${call.describe}: not scheduled (op ${opId}); schedule it first`);
    log(`  op ${opId}, ready at ${new Date(Number(readyAt) * 1000).toISOString()}`);
  }

  const data = iface.encodeFunctionData(call.fn, call.args);
  try {
    await o.provider.call({ from: o.safeAddress, to: o.anchorAddress, data });
  } catch (e) {
    const raw = (e as { data?: string }).data;
    let reason = (e as Error).message;
    try {
      const parsed = raw && o.errorInterface ? o.errorInterface.parseError(raw) : null;
      if (parsed) reason = `${parsed.name}(${parsed.args.join(', ')})`;
    } catch {
      // not one of the anchor's errors
    }
    throw new Error(`${call.describe}: the anchor refuses it: ${reason}`);
  }

  const safe = new ethers.Contract(o.safeAddress, SAFE_EXEC_ABI, o.signer);
  const args = [o.anchorAddress, 0, data, 0, 0, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, senderOwnerSignature(await o.signer.getAddress())] as const;
  await safe.execTransaction.staticCall(...args);
  const receipt = await (await safe.execTransaction(...args)).wait();
  const ok = receipt?.logs.some((l: ethers.Log) => {
    if (!same(l.address, o.safeAddress)) return false;
    try {
      return safe.interface.parseLog(l)?.name === 'ExecutionSuccess';
    } catch {
      return false;
    }
  });
  if (!ok) throw new Error(`${call.describe}: no ExecutionSuccess from the Safe in ${receipt?.hash}`);
  log(`${call.describe}: ${receipt?.hash} (gas ${receipt?.gasUsed})`);
  const block = receipt!.blockNumber;

  // Read the effect back at the mined block.
  const at = { blockTag: block };
  const expect = (what: string, actual: unknown, wanted: unknown) => {
    if (actual !== wanted) throw new Error(`${what}: read ${actual}, expected ${wanted}`);
    log(`  ${what}: ${actual}`);
  };
  switch (o.action) {
    case 'anchor-registrar-schedule': {
      const opId: string = await anchor.addRegistrarOpId(call.args[0]);
      const readyAt: bigint = await anchor.safeOpReadyAt(opId, at);
      if (readyAt === 0n) throw new Error(`op ${opId} reads unscheduled`);
      log(`  op ${opId} ready at ${new Date(Number(readyAt) * 1000).toISOString()}: then SAFE_ACTION=anchor-registrar-add`);
      break;
    }
    case 'anchor-registrar-add':
      expect('isRegistrar', await anchor.isRegistrar(call.args[0], at), true);
      break;
    case 'anchor-registrar-remove':
      expect('isRegistrar', await anchor.isRegistrar(call.args[0], at), false);
      break;
    case 'anchor-rekey-schedule': {
      const opId: string = await anchor.rekeyOpId(...(call.args as [string, string, string]));
      const readyAt: bigint = await anchor.safeOpReadyAt(opId, at);
      if (readyAt === 0n) throw new Error(`op ${opId} reads unscheduled`);
      log(`  op ${opId} ready at ${new Date(Number(readyAt) * 1000).toISOString()}: then SAFE_ACTION=anchor-rekey`);
      break;
    }
    case 'anchor-rekey': {
      const [owner, , meta] = await anchor.resolve(call.args[0], at);
      expect('owner', (owner as string).toLowerCase(), (call.args[1] as string).toLowerCase());
      expect('metaAddress', (meta as string).toLowerCase(), (call.args[2] as string).toLowerCase());
      break;
    }
    case 'anchor-force-release-schedule': {
      const opId: string = await anchor.forceReleaseOpId(...(call.args as [string, boolean]));
      if ((await anchor.safeOpReadyAt(opId, at)) === 0n) throw new Error(`op ${opId} reads unscheduled`);
      log(`  op ${opId} scheduled: then SAFE_ACTION=anchor-force-release`);
      break;
    }
    case 'anchor-force-release': {
      const [owner] = await anchor.resolve(call.args[0], at);
      expect('owner', owner, ethers.ZeroAddress);
      break;
    }
    case 'anchor-cancel-op':
      expect('safeOpReadyAt', await anchor.safeOpReadyAt(call.args[0], at), 0n);
      break;
    case 'anchor-lift-freeze':
      expect('isFrozen', await anchor.isFrozen(call.args[0], at), false);
      break;
    case 'anchor-transfer-ownership':
      expect('pendingOwner', ((await anchor.pendingOwner(at)) as string).toLowerCase(), (call.args[0] as string).toLowerCase());
      break;
    case 'anchor-accept-ownership':
      expect('owner', ((await anchor.owner(at)) as string).toLowerCase(), o.safeAddress.toLowerCase());
      break;
  }
  return block;
}
