import { ethers, network } from 'hardhat';
import { assertMainnetSigner, chainId as nodeChainId, getDeployer, readSafe } from './lib/chain';
import { refuseRecordedGeneration, writeDeployments } from './lib/deployments';
import { SAFE_V141 } from './lib/devKeyException';

// Creates the Safe that owns a generation's registries from their first block,
// as in production (decision 0017): a SafeL2 v1.4.1 proxy through Safe's
// canonical proxy factory, from the deployer. For zkp-test-1 under the M2
// dev-key exception (the founder, 2026-11-14) the deployer is the CofferdamDev
// wallet, the only owner until the Ledger joins (threshold 1); pass its address
// as REGISTRY_OWNER to deploy-identity.ts and deploy-auth.ts.
//
//   GENERATION        Base mainnet only: the deployments file, e.g. zkp-test-1
//   SAFE_OWNERS       comma-separated owners; default the deployer
//   SAFE_THRESHOLD    default 1
//   SAFE_SALT_NONCE   default keccak256("cofferdam-safe:<GENERATION or network>")
//
// The Safe's address depends on the factory, the setup and the salt nonce,
// not on the deployer's nonce.
const FACTORY_ABI = [
  'function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)',
];
const SAFE_ABI = [
  'function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)',
  'function VERSION() view returns (string)',
];

async function main() {
  const deployer = await getDeployer();
  const chainId = await nodeChainId();
  console.log(`Creating a Safe on ${network.name} (chain ${chainId}) from ${deployer.address}`);
  await assertMainnetSigner(deployer.address);
  refuseRecordedGeneration(network.name, chainId, ['CofferdamSafe']);

  for (const [name, address] of Object.entries(SAFE_V141)) {
    if ((await ethers.provider.getCode(address)) === '0x') throw new Error(`No Safe v1.4.1 ${name} at ${address} on this chain`);
  }
  const singleton = new ethers.Contract(SAFE_V141.singletonL2, SAFE_ABI, ethers.provider);
  const version = await singleton.VERSION();
  if (version !== '1.4.1') throw new Error(`SafeL2 at ${SAFE_V141.singletonL2} reports ${version}, not 1.4.1`);

  const owners = (process.env.SAFE_OWNERS?.trim() ? process.env.SAFE_OWNERS.split(',') : [deployer.address])
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => ethers.getAddress(a));
  const threshold = BigInt(process.env.SAFE_THRESHOLD?.trim() || '1');
  if (threshold < 1n || threshold > BigInt(owners.length)) throw new Error(`SAFE_THRESHOLD ${threshold} over ${owners.length} owners`);
  const label = process.env.GENERATION?.trim() || network.name;
  const saltNonce = BigInt(process.env.SAFE_SALT_NONCE?.trim() || ethers.id(`cofferdam-safe:${label}`));

  const initializer = singleton.interface.encodeFunctionData('setup', [
    owners,
    threshold,
    ethers.ZeroAddress,
    '0x',
    SAFE_V141.fallbackHandler,
    ethers.ZeroAddress,
    0,
    ethers.ZeroAddress,
  ]);
  const factory = new ethers.Contract(SAFE_V141.proxyFactory, FACTORY_ABI, deployer);
  const predicted: string = await factory.createProxyWithNonce.staticCall(SAFE_V141.singletonL2, initializer, saltNonce);
  console.log({ owners, threshold: threshold.toString(), saltNonce: saltNonce.toString(), predicted });
  if ((await ethers.provider.getCode(predicted)) !== '0x') throw new Error(`A Safe already exists at ${predicted}: use another SAFE_SALT_NONCE`);

  const receipt = await (await factory.createProxyWithNonce(SAFE_V141.singletonL2, initializer, saltNonce)).wait();
  console.log(`Created in ${receipt?.hash} (gas ${receipt?.gasUsed})`);

  const safe = await readSafe(predicted);
  if (!safe || safe.singleton.toLowerCase() !== SAFE_V141.singletonL2.toLowerCase()) throw new Error(`No SafeL2 proxy at ${predicted}`);
  if (safe.threshold !== threshold || safe.owners.length !== owners.length) throw new Error(`The Safe at ${predicted} reports another setup`);
  console.log('CofferdamSafe:', predicted, `(owners ${safe.owners.join(', ')}; threshold ${safe.threshold})`);

  const file = writeDeployments(network.name, chainId, { CofferdamSafe: predicted });
  console.log('Wrote', file);
  console.log(`Next: REGISTRY_OWNER=${predicted} for deploy-identity.ts and deploy-auth.ts.`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
