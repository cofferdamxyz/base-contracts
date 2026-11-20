import { expect } from 'chai';

import { forkReceipt, isForkTransportError } from '../scripts/lib/chain';
import { CofferdamIdentityRegistry__factory, ZKPassportEvidenceAdapter__factory } from '../typechain-types';
import { describeCustomError, identifierTypeFor, revertReason, withholdWords } from '../scripts/lib/identity';

// Script helpers. forkReceipt: a fork's receipt waited for through the forked RPC's refusals
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

describe('withholdWords', () => {
  it('withholds the identifier a registry error names, and keeps the account', () => {
    const id = '0x' + 'ab'.repeat(32);
    const account = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const text = withholdWords(`execution reverted: IdentifierAlreadyBound("${id}", "${account}")`);
    expect(text).to.equal(`execution reverted: IdentifierAlreadyBound("<32 bytes withheld>", "${account}")`);
  });

  it('withholds a longer run whole, with or without 0x', () => {
    // ethers prints an undecoded custom error's data without 0x: the selector,
    // then the identifier and the account as one run.
    const raw = 'e55adcda' + 'ab'.repeat(32) + '00'.repeat(12) + '70997970c51812dc3a010c7d01b50e0d17dc79c8';
    expect(withholdWords(`custom error 0xe55adcda: ${raw.slice(8)}`)).to.equal('custom error 0xe55adcda: <64 bytes withheld>');
    expect(withholdWords('0x' + 'cd'.repeat(36))).to.equal('<36 bytes withheld>');
  });

  it('keeps addresses, selectors and short values', () => {
    const text = 'NotTestAccount(0x70997970C51812dc3A010C7d01b50e0d17dc79C8) 0xe55adcda';
    expect(withholdWords(text)).to.equal(text);
  });
});

describe('describeCustomError', () => {
  const iface = CofferdamIdentityRegistry__factory.createInterface();

  it("names the registry's error, withholds the identifier and keeps the account", () => {
    const account = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const data = iface.encodeErrorResult('IdentifierAlreadyBound', ['0x' + 'ab'.repeat(32), account]);
    expect(data.slice(0, 10)).to.equal('0xe55adcda');
    expect(describeCustomError(iface, data)).to.equal(`IdentifierAlreadyBound(<32 bytes withheld>, ${account})`);
  });

  it("withholds an integer argument too large to be a count: the adapter's WrongIdentifierType carried the identifier (2026-11-18)", () => {
    const adapter = ZKPassportEvidenceAdapter__factory.createInterface();
    const data = adapter.encodeErrorResult('WrongIdentifierType', [1n, 2n ** 250n + 7n]);
    expect(describeCustomError(adapter, data)).to.equal('WrongIdentifierType(1, <uint256 withheld>)');
    expect(describeCustomError(adapter, adapter.encodeErrorResult('ExpiryNotProven', [1797558977n]))).to.equal(
      'ExpiryNotProven(1797558977)',
    );
  });

  it('answers null for data that is not one of its errors', () => {
    expect(describeCustomError(iface, '0xdeadbeef')).to.equal(null);
  });
});

describe('revertReason', () => {
  const iface = CofferdamIdentityRegistry__factory.createInterface();
  const account = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
  const data = iface.encodeErrorResult('IdentifierAlreadyBound', ['0x' + 'ab'.repeat(32), account]);

  it("decodes anvil's undecoded custom error, as the second account's check() printed it (2026-11-17)", () => {
    const message = `execution reverted: custom error ${data.slice(0, 10)}: ${data.slice(10)}`;
    expect(revertReason(iface, new Error(message))).to.equal(`reverted IdentifierAlreadyBound(<32 bytes withheld>, ${account})`);
  });

  it("decodes ethers' revert data", () => {
    const error = Object.assign(new Error('execution reverted (unknown custom error)'), { data });
    expect(revertReason(iface, error)).to.equal(`reverted IdentifierAlreadyBound(<32 bytes withheld>, ${account})`);
  });

  it('withholds the hex of an error it cannot decode', () => {
    const message = `execution reverted: custom error 0xdeadbeef: ${'ab'.repeat(32)}`;
    expect(revertReason(iface, new Error(message))).to.equal('execution reverted: custom error 0xdeadbeef: <32 bytes withheld>');
  });
});

describe('identifierTypeFor (deploy-identity.ts)', () => {
  const real = { mainnet: true, fork: false, pepper: false };
  const fork = { mainnet: true, fork: true, pepper: false };
  const off = { mainnet: false, fork: false, pepper: false };

  it('on chain 8453 the type must be named, a fork included', () => {
    expect(() => identifierTypeFor({ GENERATION: 'zkp-prod-1' }, real)).to.throw(/set ZKP_IDENTIFIER_TYPE/);
    expect(() => identifierTypeFor({}, fork)).to.throw(/set ZKP_IDENTIFIER_TYPE/);
    expect(() => identifierTypeFor({}, { ...real, pepper: true })).to.throw(/set ZKP_IDENTIFIER_TYPE/);
  });

  it('Base mainnet refuses non-salted outside zkp-test-1; a fork rehearsal may run it', () => {
    expect(() => identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'non-salted', GENERATION: 'cofferdam-id-v1' }, real)).to.throw(/only in zkp-test-1/);
    expect(identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'non-salted', GENERATION: 'zkp-test-1' }, real)).to.equal('non-salted');
    expect(identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'non-salted', GENERATION: 'zkp-dryrun-1' }, fork)).to.equal('non-salted');
    expect(identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'salted', GENERATION: 'cofferdam-id-v1' }, real)).to.equal('salted');
  });

  it('off mainnet the defaults stand; the pepper is salted only', () => {
    expect(identifierTypeFor({}, off)).to.equal('non-salted');
    expect(identifierTypeFor({}, { ...off, pepper: true })).to.equal('salted');
    expect(() => identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'non-salted' }, { ...off, pepper: true })).to.throw(/salted identifiers only/);
    expect(() => identifierTypeFor({ ZKP_IDENTIFIER_TYPE: 'unsalted' }, off)).to.throw(/non-salted or salted/);
  });
});
