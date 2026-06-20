import { ethers } from 'ethers';

export function fmtEth(wei: bigint): string {
  return `${ethers.formatEther(wei)} ETH`;
}

export function fmtAddr(addr: string): string {
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}

export function printHeader(title: string): void {
  console.log('\n' + '─'.repeat(60));
  console.log(`  ${title}`);
  console.log('─'.repeat(60));
}

export function printKV(key: string, value: string): void {
  const padded = key.padEnd(28);
  console.log(`  ${padded} ${value}`);
}

export function printTx(addr: string): void {
  console.log(`  tx: ${addr}`);
}

export async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
