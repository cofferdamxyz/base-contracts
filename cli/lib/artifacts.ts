import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';

const ARTIFACTS_DIR = path.join(__dirname, '..', '..', 'artifacts', 'contracts');

interface Artifact {
  abi: ethers.InterfaceAbi;
  bytecode: string;
}

export function loadArtifact(contractPath: string): Artifact {
  const parts = contractPath.split('/');
  const contractName = parts[parts.length - 1];
  const fullPath = path.join(ARTIFACTS_DIR, contractPath + '.sol', contractName + '.json');
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Artifact not found: ${fullPath}. Run 'yarn compile' first.`);
  }
  const raw = fs.readFileSync(fullPath, 'utf-8');
  const parsed = JSON.parse(raw);
  return { abi: parsed.abi, bytecode: parsed.bytecode };
}

export async function deployContract(
  signer: ethers.Wallet,
  contractPath: string,
  ...args: any[]
): Promise<ethers.Contract> {
  const { abi, bytecode } = loadArtifact(contractPath);
  const factory = new ethers.ContractFactory(abi, bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract as ethers.Contract;
}

export function getContract(
  signer: ethers.Wallet,
  contractPath: string,
  address: string
): ethers.Contract {
  const { abi } = loadArtifact(contractPath);
  return new ethers.Contract(address, abi, signer);
}
