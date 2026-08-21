import { ethers, network } from 'hardhat';
import { writeDeployments } from './lib/deployments';
import {
  COFFERDAM_BIND_V1_SCOPE,
  COFFERDAM_SELF_HOST,
  COFFERDAM_SELF_SCOPE_STRING,
  deriveCofferdamScope,
} from './lib/selfScope';
import { COFFERDAM_SELF_DEST_CHAIN_ID } from './lib/selfUserContext';

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying Self.xyz contracts from:', deployer.address);

  // 1. Deploy the real snarkJS-generated Groth16 verifier for the
  //    `vc_and_disclose` circuit (21 public signals, E_PASSPORT).
  //    Vendored byte-identical from
  //    `self/contracts/contracts/verifiers/disclose/Verifier_vc_and_disclose.sol`.
  //    Override with SELF_VERIFIER_ADDRESS to reuse an existing deploy
  //    (e.g. to point at MockGroth16Verifier while debugging plumbing).
  let verifierAddress = process.env.SELF_VERIFIER_ADDRESS;
  if (verifierAddress) {
    console.log('Reusing existing verifier:', verifierAddress);
  } else {
    const Verifier = await ethers.getContractFactory('Verifier_vc_and_disclose');
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    verifierAddress = await verifier.getAddress();
    console.log('Verifier_vc_and_disclose:', verifierAddress);
  }

  // 2. Deploy SelfAttesterRegistry, registering the attester signer in
  //    the constructor so the registry is never briefly live with an
  //    empty allow-list. Without a trusted attester, `verifyAndBind`
  //    reverts `UntrustedAttester` for every bind.
  //
  //    ATTESTER_ADDRESS is the secp256k1 address whose private key lives
  //    as the ATTESTER_PRIVATE_KEY secret on the cofferdam-attester
  //    Worker. Derive it with:
  //      cast wallet address --private-key $ATTESTER_PRIVATE_KEY
  //    A registry with an empty allow-list cannot bind anything, so this is a
  //    hard error. Set ALLOW_NO_ATTESTER=1 only if you intend to call
  //    addAttester() manually afterwards.
  //
  //    NOTE: `FOO=bar` on its own shell line sets a *shell* variable that child
  //    processes do NOT inherit. Use `export FOO=bar`, or prefix the command
  //    inline: `ATTESTER_ADDRESS=0x.. npx hardhat run ...`.
  const attesterAddress = process.env.ATTESTER_ADDRESS;
  if (!attesterAddress) {
    if (process.env.ALLOW_NO_ATTESTER !== '1') {
      throw new Error(
        'ATTESTER_ADDRESS is not set, so no trusted attester would be registered and\n' +
          'verifyAndBind would revert UntrustedAttester for every bind.\n' +
          '  Derive it:  cast wallet address --private-key $ATTESTER_PRIVATE_KEY\n' +
          '  Then EXPORT it (a bare `FOO=bar` line is not inherited by npx):\n' +
          '    export ATTESTER_ADDRESS=0x...\n' +
          '  Override intentionally with ALLOW_NO_ATTESTER=1.'
      );
    }
    console.warn('WARNING: ALLOW_NO_ATTESTER=1 — deploying with an empty allow-list.');
    console.warn('  verifyAndBind will revert UntrustedAttester until you call addAttester().');
  } else if (!ethers.isAddress(attesterAddress)) {
    throw new Error(`ATTESTER_ADDRESS is not a valid address: ${attesterAddress}`);
  } else if (attesterAddress === ethers.ZeroAddress) {
    throw new Error('ATTESTER_ADDRESS is the zero address.');
  }

  const SelfAttesterRegistry = await ethers.getContractFactory('SelfAttesterRegistry');
  const attesterRegistry = await SelfAttesterRegistry.deploy(
    deployer.address,
    attesterAddress ? [attesterAddress] : []
  );
  await attesterRegistry.waitForDeployment();
  console.log('SelfAttesterRegistry:', await attesterRegistry.getAddress());
  if (attesterAddress) console.log('  trusted attester:', attesterAddress);

  // 3. Deploy NullifierRegistry. `expectedScope` is immutable, so a scope
  //    change means redeploying and re-binding every user. Re-derive it
  //    from Self's own primitives and abort before spending gas if the
  //    pinned literal has drifted.
  const derived = deriveCofferdamScope();
  if (derived !== COFFERDAM_BIND_V1_SCOPE) {
    throw new Error(
      `Pinned scope literal is stale.\n` +
        `  derived: ${derived}\n` +
        `  pinned:  ${COFFERDAM_BIND_V1_SCOPE}\n` +
        `Update COFFERDAM_BIND_V1_SCOPE in scripts/lib/selfScope.ts.`
    );
  }

  //    SELF_SCOPE may override the derived value, but a bad override bricks an
  //    immutable field. Guard it hard: `BigInt('0') === 0n` and '0' is truthy in
  //    JS, so a stale `SELF_SCOPE=0` in .env (left over from deploy-all.ts,
  //    which defaults to '0') would otherwise silently deploy a zero scope that
  //    reverts WrongScope on every real proof.
  let scope: bigint;
  const scopeOverride = process.env.SELF_SCOPE?.trim();
  if (scopeOverride) {
    try {
      scope = BigInt(scopeOverride);
    } catch {
      throw new Error(`SELF_SCOPE is not a valid integer: '${scopeOverride}'`);
    }
    if (scope === 0n) {
      throw new Error(
        `SELF_SCOPE='${scopeOverride}' resolves to 0, which is never a valid scope.\n` +
          'expectedScope is immutable, so this would permanently revert WrongScope.\n' +
          `Remove SELF_SCOPE from .env to use the derived scope (${COFFERDAM_BIND_V1_SCOPE}).`
      );
    }
  } else {
    scope = COFFERDAM_BIND_V1_SCOPE;
  }

  console.log(
    `expectedScope: ${scope} ` +
      `(host='${COFFERDAM_SELF_HOST}' scope='${COFFERDAM_SELF_SCOPE_STRING}')`
  );
  if (scope !== COFFERDAM_BIND_V1_SCOPE) {
    console.warn(
      `WARNING: SELF_SCOPE override in use — ${scope} != derived ${COFFERDAM_BIND_V1_SCOPE}.`
    );
    console.warn('  The app SelfApp.scope must hash to this value or no bind can succeed.');
  }

  // Self folds its own `destChainID` into the `userIdentifier` commitment, so
  // this must track `SelfApp.chainID` in the app (Celo's 42220), NOT Base's.
  const selfDestChainId = process.env.SELF_DEST_CHAIN_ID
    ? Number(process.env.SELF_DEST_CHAIN_ID)
    : COFFERDAM_SELF_DEST_CHAIN_ID;
  if (!Number.isInteger(selfDestChainId) || selfDestChainId <= 0) {
    throw new Error(
      `SELF_DEST_CHAIN_ID must be a positive integer, got '${process.env.SELF_DEST_CHAIN_ID}'. ` +
        'It is immutable and folded into every userIdentifier commitment.'
    );
  }
  console.log('selfDestChainId:', selfDestChainId, '(Self SelfApp.chainID, not the host chain)');

  const NullifierRegistry = await ethers.getContractFactory('NullifierRegistry');
  const nullifierRegistry = await NullifierRegistry.deploy(
    verifierAddress,
    await attesterRegistry.getAddress(),
    scope,
    selfDestChainId
  );
  await nullifierRegistry.waitForDeployment();
  console.log('NullifierRegistry:', await nullifierRegistry.getAddress());

  // Merge into deployments/<network>.json (preserve auth + escrow entries).
  const registryPath = writeDeployments(network.name, {
    Verifier_vc_and_disclose: verifierAddress,
    SelfAttesterRegistry: await attesterRegistry.getAddress(),
    NullifierRegistry: await nullifierRegistry.getAddress(),
  });
  console.log('Wrote', registryPath);

  console.log('\n--- Self contracts deployed ---');
  console.log('Re-vendor cofferdam-api/src/chain/deployments.ts with the addresses above.');
  console.log('Scope must match buildCofferdamSelfApp() in cofferdam-app.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
