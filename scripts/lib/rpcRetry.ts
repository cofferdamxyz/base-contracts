import { ProviderWrapper } from 'hardhat/plugins';
import type { EIP1193Provider, RequestArguments } from 'hardhat/types';

// A public RPC sometimes answers a read with neither `result` nor `error`
// (publicnode on Base mainnet, 2026-11-16 and 2026-11-19:
// `{"jsonrpc":"2.0","id":37}`), and Hardhat throws HH110 on it. Right after a
// send, hardhat-ethers looks the transaction up with eth_getTransactionByHash,
// so a script stopped there although its transaction had gone out and mined:
// the zkp-test-1 adapter proposals, each read back by hand. Reads are retried
// on that empty answer; a send never is, whatever it gets back.

/** Methods that only read the chain, safe to ask again. */
export const RETRIED_READS: ReadonlySet<string> = new Set([
  'eth_blockNumber',
  'eth_call',
  'eth_chainId',
  'eth_estimateGas',
  'eth_feeHistory',
  'eth_gasPrice',
  'eth_getBalance',
  'eth_getBlockByHash',
  'eth_getBlockByNumber',
  'eth_getCode',
  'eth_getLogs',
  'eth_getStorageAt',
  'eth_getTransactionByHash',
  'eth_getTransactionCount',
  'eth_getTransactionReceipt',
  'eth_maxPriorityFeePerGas',
  'net_version',
]);

/** Hardhat's HH110: a JSON-RPC answer with neither result nor error. */
export function isEmptyRpcAnswer(error: unknown): boolean {
  const e = error as { number?: unknown; _isHardhatError?: unknown } | null;
  return typeof e === 'object' && e !== null && e._isHardhatError === true && e.number === 110;
}

export class RetryEmptyReadsProvider extends ProviderWrapper {
  constructor(
    provider: EIP1193Provider,
    private readonly attempts = 10,
    private readonly delayMs = 1500,
  ) {
    super(provider);
  }

  public async request(args: RequestArguments): Promise<unknown> {
    if (!RETRIED_READS.has(args.method)) return this._wrappedProvider.request(args);
    for (let attempt = 1; ; attempt++) {
      try {
        return await this._wrappedProvider.request(args);
      } catch (error) {
        if (attempt >= this.attempts || !isEmptyRpcAnswer(error)) throw error;
        await new Promise((resolve) => setTimeout(resolve, this.delayMs));
      }
    }
  }
}
