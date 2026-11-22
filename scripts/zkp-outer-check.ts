import fs from 'fs';
import { ethers, network } from 'hardhat';

import { ZKP_ROOT_VERIFIER, revertReason, zkpCircuitsVersion, type ZkpSolidityParams } from './lib/identity';

// Decision 0080, the pepper: checks a salted proof's outer proof against
// ZKPassport's own outer verifier for the proof's circuits version, called
// directly, on a local fork of Base mainnet. Read-only: eth_call only, nothing
// is deployed or sent. Before 0.23.0 no adapter of ours reads the proof, so
// this is the check that ZKPassport's cloud prover made a valid outer proof
// for inner proofs salted under a key of ours.
//
//   yarn node:start:base                       # base-anvil on :8546, the fork
//   mkfifo -m 600 /tmp/zkp.fifo
//   ZKP_PARAMS_FILE=/tmp/zkp.fifo ZKP_OPRF_KEY_HASH=0x… \
//     npx hardhat run scripts/zkp-outer-check.ts --network baseFork && rm /tmp/zkp.fifo
//
// The parameters come through a named pipe so no copy lands on disk. Nothing
// here prints the proof, a public input or the identifier: only booleans, the
// version, and revert reasons with every long hex run withheld.

const LAYOUT_0_23_0 = zkpCircuitsVersion('0.23.0');

async function main() {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (chainId !== 8453n || network.name !== 'baseFork') throw new Error('Run on baseFork (a local fork of Base mainnet) only');
  const file = process.env.ZKP_PARAMS_FILE?.trim();
  const key = process.env.ZKP_OPRF_KEY_HASH?.trim().toLowerCase();
  if (!file) throw new Error('Set ZKP_PARAMS_FILE (a named pipe)');
  if (!key || !/^0x[0-9a-f]{64}$/.test(key)) throw new Error('Set ZKP_OPRF_KEY_HASH to the expected key hash');

  console.log('Waiting for the proof parameters on the pipe…');
  const p = JSON.parse(await fs.promises.readFile(file, 'utf8')) as ZkpSolidityParams;
  // anvil mines only on transactions: a block now, so the proof's date is not after the fork's.
  await ethers.provider.send('evm_mine', []);

  const failures: string[] = [];
  const report = (what: string, ok: boolean, detail = '') => {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${detail ? `: ${detail}` : ''}`);
    if (!ok) failures.push(what);
  };

  const version = p.version.toLowerCase();
  const label = [2, 6, 10].map((i) => parseInt(version.slice(i, i + 4), 16)).join('.');
  console.log(`circuits ${label}, ${p.proofVerificationData.publicInputs.length} public inputs`);

  // Trailing public inputs: … nullifier type, scoped nullifier, OPRF key hash,
  // and from 0.23.0 the verification method.
  const pi = p.proofVerificationData.publicInputs.map((x) => x.toLowerCase());
  const tail = BigInt(version) >= BigInt(LAYOUT_0_23_0) ? 1 : 0;
  const n = pi.length - tail;
  report('identifier type is 1 (SALTED)', BigInt(pi[n - 3]) === 1n);
  report('OPRF key hash is the expected one', pi[n - 1] === key);
  if (tail) report('verification method is 100 (the chip)', BigInt(pi[pi.length - 1]) === 100n);

  const root = await ethers.getContractAt('IZKPassportRootVerifierState', ZKP_ROOT_VERIFIER);
  const subAddress = await root.getSubVerifier(version);
  report(`RootVerifier registers ${label}`, subAddress !== ethers.ZeroAddress);
  if (subAddress === ethers.ZeroAddress) throw new Error('No sub-verifier for this version');
  const sub = await ethers.getContractAt('IZKPassportSubVerifier', subAddress);
  const verifierAddress = await sub.proofVerifiers(p.proofVerificationData.vkeyHash);
  report(`${label}'s sub-verifier lists the proof's verification key`, verifierAddress !== ethers.ZeroAddress, verifierAddress);
  report("the key is not ZKPassport's global one", key !== (await sub.globalOPRFPubKeyHash()).toLowerCase());

  // The check itself: ZKPassport's outer verifier for this vkey, called directly.
  if (verifierAddress !== ethers.ZeroAddress) {
    const verifier = await ethers.getContractAt('IZKPassportProofVerifier', verifierAddress);
    try {
      const ok = await verifier.verify(p.proofVerificationData.proof, p.proofVerificationData.publicInputs);
      report("ZKPassport's outer verifier accepts the outer proof", ok, ok ? '' : 'returned false');
    } catch (e) {
      report("ZKPassport's outer verifier accepts the outer proof", false, revertReason([], e));
    }
  }

  // ZKPassport's own path refuses a key that is not its global one, after the
  // roots, date, scopes and commitments: its reason says how far it got.
  const live = await ethers.getContractAt('IZKPassportRootVerifier', ZKP_ROOT_VERIFIER);
  try {
    await live.verify.staticCall(p);
    report("RootVerifier refuses the key (expected 'Invalid OPRF public key')", false, 'it accepted');
  } catch (e) {
    const reason = revertReason([], e);
    report("RootVerifier refuses the key (expected 'Invalid OPRF public key')", /Invalid OPRF public key/.test(reason), reason);
  }

  if (failures.length) {
    console.log(`\n${failures.length} check(s) failed.`);
    process.exitCode = 1;
  } else console.log('\nEvery check passed.');
}

main().catch((e) => {
  console.error(revertReason([], e));
  process.exitCode = 1;
});
