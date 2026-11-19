import { expect } from 'chai';
import { EventEmitter } from 'node:events';
import type { EIP1193Provider, RequestArguments } from 'hardhat/types';
import { isEmptyRpcAnswer, RetryEmptyReadsProvider } from '../scripts/lib/rpcRetry';

// HH110 as Hardhat throws it for publicnode's `{"jsonrpc":"2.0","id":37}`.
function hh110(): Error {
  return Object.assign(new Error('HH110: Invalid JSON-RPC response received: {"jsonrpc":"2.0","id":37}'), {
    number: 110,
    _isHardhatError: true,
  });
}

/** A provider that throws `failures` errors per method before answering. */
function flaky(failures: number, error: () => Error = hh110) {
  const calls: string[] = [];
  const provider = Object.assign(new EventEmitter(), {
    async request(args: RequestArguments) {
      calls.push(args.method);
      if (calls.filter((m) => m === args.method).length <= failures) throw error();
      return `${args.method} answered`;
    },
  }) as unknown as EIP1193Provider;
  return { provider, calls };
}

describe('scripts/lib/rpcRetry: an RPC answer with neither result nor error', () => {
  it('recognises Hardhat HH110 and nothing else', () => {
    expect(isEmptyRpcAnswer(hh110())).to.equal(true);
    expect(isEmptyRpcAnswer(new Error('HH110: Invalid JSON-RPC response received'))).to.equal(false);
    expect(isEmptyRpcAnswer(Object.assign(new Error('x'), { number: 108, _isHardhatError: true }))).to.equal(false);
    expect(isEmptyRpcAnswer(undefined)).to.equal(false);
  });

  it('asks a read again until it is answered', async () => {
    const { provider, calls } = flaky(3);
    const retrying = new RetryEmptyReadsProvider(provider, 10, 0);
    expect(await retrying.request({ method: 'eth_getTransactionByHash', params: ['0x01'] })).to.equal(
      'eth_getTransactionByHash answered',
    );
    expect(calls).to.have.length(4);
  });

  it('gives up after its attempts and throws the empty answer', async () => {
    const { provider, calls } = flaky(5);
    const retrying = new RetryEmptyReadsProvider(provider, 3, 0);
    let thrown: unknown;
    try {
      await retrying.request({ method: 'eth_getTransactionReceipt', params: ['0x01'] });
    } catch (e) {
      thrown = e;
    }
    expect(isEmptyRpcAnswer(thrown)).to.equal(true);
    expect(calls).to.have.length(3);
  });

  it('never sends a transaction twice', async () => {
    for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction']) {
      const { provider, calls } = flaky(1);
      const retrying = new RetryEmptyReadsProvider(provider, 10, 0);
      let thrown: unknown;
      try {
        await retrying.request({ method, params: ['0x02'] });
      } catch (e) {
        thrown = e;
      }
      expect(isEmptyRpcAnswer(thrown), method).to.equal(true);
      expect(calls, method).to.deep.equal([method]);
    }
  });

  it('does not retry a read on any other error', async () => {
    const { provider, calls } = flaky(1, () => new Error('execution reverted'));
    const retrying = new RetryEmptyReadsProvider(provider, 10, 0);
    let thrown: unknown;
    try {
      await retrying.request({ method: 'eth_call', params: [] });
    } catch (e) {
      thrown = e;
    }
    expect((thrown as Error).message).to.equal('execution reverted');
    expect(calls).to.have.length(1);
  });
});
