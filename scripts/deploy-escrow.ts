import { ethers, network } from 'hardhat';
import { createHmac } from 'crypto';
import { writeDeployments } from './lib/deployments';

// Mirror of LocalChainDemo's deriveDeterministicPk — same salt + algorithm
// so the deployed escrow's policy matches the demo's wallets.
function deriveDeterministicPk(mockUserId: string): string {
  const salt = 'cofferdam-local-privatekey-v1';
  const sig = createHmac('sha256', salt).update(mockUserId).digest();
  return '0x' + sig.toString('hex');
}

async function main() {
  console.log('=== Deploy MockUSDC + EscrowFactory + Sample SpotEscrow ===\n');

  const [deployer] = await ethers.getSigners();
  console.log('Network:', network.name);
  console.log('Deployer:', deployer.address);

  // The demo derives each role's wallet from a per-network mockUserId
  // (LocalChainDemo buildConfig): `local-*` on the local-chain target and
  // `sepolia-*` on the testnet target. Match that here so the sample escrow's
  // policy + the recruiter authorization line up with the wallets the demo
  // will actually sign in as.
  const isTestnet = network.name === 'baseSepolia';
  const funderId = isTestnet ? 'sepolia-finance-1' : 'local-finance-1';
  const recruiterId = isTestnet ? 'sepolia-recruiter-1' : 'local-recruiter-1';
  const envPrefix = isTestnet ? 'VITE_TESTNET' : 'VITE_LOCAL';

  // Compute the demo's deterministic wallet addresses
  const funderPk = deriveDeterministicPk(funderId);
  const funderWallet = new ethers.Wallet(funderPk, deployer.provider);
  console.log('Demo funder wallet:', funderWallet.address);

  const witnessPk = deriveDeterministicPk(recruiterId);
  const witnessWallet = new ethers.Wallet(witnessPk, deployer.provider);
  console.log('Demo witness (HR) wallet:', witnessWallet.address);

  // 1. MockUSDC
  const USDC = await ethers.getContractFactory('USDC');
  const usdc = await USDC.deploy('USD Coin', 'USDC');
  await usdc.waitForDeployment();
  const usdcAddr = await usdc.getAddress();
  console.log('MockUSDC:', usdcAddr);

  // 2. EscrowFactory
  const Factory = await ethers.getContractFactory('EscrowFactory');
  const factory = await Factory.deploy(usdcAddr);
  await factory.waitForDeployment();
  const factoryAddr = await factory.getAddress();
  console.log('EscrowFactory:', factoryAddr);

  // Authorize the recruiter (HR) wallet so it can create escrows from the demo
  await factory.authorize(witnessWallet.address);
  console.log('Authorized recruiter (HR) wallet to create escrows');

  // 3. Create a sample spot escrow via CREATE2.
  //    funder = demo's Finance wallet (so onlyFunder passes)
  //    recruiter = demo's HR wallet (so onlyRecruiter passes for setWitness)
  //    witness = demo's HR wallet initially (HR as fallback for remote jobs;
  //              HR can setWitness to supervisor on-site when ready)
  //    checkOutTimeout = 120 seconds (so void can be tested quickly on local node)
  //    salt = deterministic so the address is reproducible across redeployments
  //    arbiter = deployer (platform/Cofferdam acts as the neutral dispute
  //              resolver; the demo's admin key is this same wallet so it can
  //              call resolveDispute)
  //    killFeeBps = 1000 (10%) — recommended default funder cancellation fee
  //              paid to the awarded worker (allowed range 5%-25%), analogous
  //              to Instawork/Indeed Flex cancellation pay; see SPOT_ESCROW_RULES.md
  const policy = {
    funder: funderWallet.address,
    recruiter: witnessWallet.address,
    workerNullifier: ethers.randomBytes(32),
    checkInTimeout: 3600,
    checkOutTimeout: 120,
    witness: witnessWallet.address,
    arbiter: deployer.address,
    killFeeBps: 1000,
    amount: 1_000_000n, // 1 USDC (6 decimals) — fund() must match; equals the testnet demo amount
    termsHash: ethers.id('cofferdam-spot-demo-terms-v1'), // pointer to off-chain agreed terms
    jobStartTime: 0, // effective at creation (no scheduled start)
    disputeWindow: 120, // 2m demo — worker can claim if the arbiter stays silent
  };

  // Predict the address before deploying
  const predictedAddr = await factory.predictSpotEscrowAddress(policy, ethers.id('cofferdam-spot-demo-v1'));
  console.log('Predicted escrow address:', predictedAddr);

  const tx = await factory.createSpotEscrow(policy, ethers.id('cofferdam-spot-demo-v1'));
  const receipt = await tx.wait();

  const iface = factory.interface;
  const log = receipt!.logs.find((l: any) => {
    try { return iface.parseLog(l)?.name === 'SpotEscrowCreated'; } catch { return false; }
  });

  let escrowAddr = '';
  if (log) {
    const parsed = iface.parseLog(log!);
    escrowAddr = parsed!.args.escrow;
    console.log('CofferdamSpotEscrow (sample):', escrowAddr);
  }

  // 4. Mint USDC to the funder (so they can approve + fund the escrow).
  //    MockUSDC has a public mint, so the demo funder can be topped up freely
  //    on testnet too — no faucet round-trip per role wallet.
  await usdc.mint(funderWallet.address, ethers.parseUnits('1000000', 6));
  console.log('Minted 1,000,000 USDC to demo funder');

  // Also mint to deployer for convenience
  await usdc.mint(deployer.address, ethers.parseUnits('1000000', 6));
  console.log('Minted 1,000,000 USDC to deployer');

  // 5. Persist addresses to deployments/<network>.json (merge with any
  //    existing entries written by deploy-all.ts / deploy-self.ts).
  const registryPath = writeDeployments(network.name, {
    MockUSDC: usdcAddr,
    EscrowFactory: factoryAddr,
    CofferdamSpotEscrow: escrowAddr,
  });
  console.log('Wrote', registryPath);

  console.log('\n=== Summary ===');
  console.log('MockUSDC:', usdcAddr);
  console.log('EscrowFactory:', factoryAddr);
  console.log('CofferdamSpotEscrow:', escrowAddr);
  console.log(`\nPaste these into the example's .env.local:`);
  console.log(`${envPrefix}_ESCROW_ADDRESS=${escrowAddr}`);
  console.log(`${envPrefix}_FACTORY_ADDRESS=${factoryAddr}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
