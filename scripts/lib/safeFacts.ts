// A Safe's facts read from the chain through any ethers provider, so the
// scripts (through Hardhat's) and the fork tests share one reader.

import { ethers } from 'ethers';
import type { SafeFacts } from './devKeyException';

export const SAFE_READ_ABI = [
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function getModulesPaginated(address start, uint256 pageSize) view returns (address[] array, address next)',
  'function nonce() view returns (uint256)',
  'function VERSION() view returns (string)',
];
const SENTINEL = '0x0000000000000000000000000000000000000001';

/** The Safe facts of `address`, or null when it has no code or does not answer as a Safe. */
export async function readSafeFacts(provider: ethers.Provider, address: string): Promise<SafeFacts | null> {
  const code = await provider.getCode(address);
  if (code === '0x') return null;
  const safe = new ethers.Contract(address, SAFE_READ_ABI, provider);
  let facts: SafeFacts;
  try {
    const slot0 = await provider.getStorage(address, 0);
    facts = {
      singleton: ethers.getAddress(ethers.dataSlice(slot0, 12)),
      owners: [...(await safe.getOwners())],
      threshold: await safe.getThreshold(),
      codeHash: ethers.keccak256(code),
    };
  } catch {
    return null;
  }
  try {
    // From the sentinel; a page of 10 is enough to tell none from some.
    const [modules] = await safe.getModulesPaginated(SENTINEL, 10);
    facts.modules = [...modules];
  } catch {
    // left undefined: the production check refuses a Safe whose modules it cannot read
  }
  return facts;
}
