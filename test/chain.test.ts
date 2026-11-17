import { expect } from 'chai';

import { forkReceipt, isForkTransportError } from '../scripts/lib/chain';

// forkReceipt: a fork's receipt waited for through the forked RPC's refusals
// (scripts/identity-bind.ts; publicnode refused anvil's receipt lookup on
// 2026-11-16 while the bind mined).

const REFUSAL =
  'Fork Error: Transport(HttpError(HttpError { status: 403, body: "{\\"error\\":{\\"message\\":\\"Archive requests require a personal token\\"}}" }))';

describe('forkReceipt', () => {
  it('recognises the forked RPC refusing a request', () => {
    expect(isForkTransportError(new Error(`ProviderError: ${REFUSAL}`))).to.equal(true);
    expect(isForkTransportError(new Error('execution reverted: AlreadyBound()'))).to.equal(false);
  });

  it('retries the refusal until the receipt is there', async () => {
    let calls = 0;
    const receipt = await forkReceipt(async () => {
      calls++;
      if (calls < 3) throw new Error(REFUSAL);
      return 'receipt';
    }, 10, 0);
    expect(receipt).to.equal('receipt');
    expect(calls).to.equal(3);
  });

  it('throws any other error at once', async () => {
    let calls = 0;
    const error = await forkReceipt(async () => {
      calls++;
      throw new Error('transaction execution reverted');
    }, 10, 0).catch((e: Error) => e);
    expect(String(error)).to.include('transaction execution reverted');
    expect(calls).to.equal(1);
  });

  it('gives up after the attempts', async () => {
    let calls = 0;
    const error = await forkReceipt(async () => {
      calls++;
      throw new Error(REFUSAL);
    }, 3, 0).catch((e: Error) => e);
    expect(String(error)).to.include('Fork Error: Transport');
    expect(calls).to.equal(3);
  });
});
