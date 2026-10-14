import { network } from 'hardhat';
import { writeDeployments } from './lib/deployments';
import { deployAccountLayer } from './lib/accountLayer';

async function main() {
  console.log('Deploying the account layer on', network.name);
  const addresses = await deployAccountLayer();

  // Persist to deployments/<network>.json (merge with existing entries).
  const registryPath = writeDeployments(network.name, addresses);
  console.log('\n--- Deployment complete ---');
  console.log('Wrote', registryPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
