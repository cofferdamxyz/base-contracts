import { expect } from 'chai';
import { Wallet } from 'ethers';

import { DEV_KEY_EXCEPTION, SAFE_V141, exceptionOwnerRefusal } from '../scripts/lib/devKeyException';
import { productionOwnerRefusal, productionSafeSetupRefusal } from '../scripts/lib/productionSafe';
import {
  LOCAL_DEFAULT_MAX_COST,
  MAINNET_MAX_COST_CEILING,
  parseWei,
  relayPaymasterMaxCost,
  relayPaymasterRelayer,
  relayerRefusal,
} from '../scripts/lib/relayPaymaster';

// The company Safe's guards on Base mainnet (the founder's ruling of
// 2026-11-26: 2-of-3, the Ledger, the phone and a second hardware wallet) and
// CofferdamRelayPaymaster's deploy settings (ruling P9). Pure checks, no network.

const DEV = DEV_KEY_EXCEPTION.signer;
const [A, B, C, D] = Array.from({ length: 4 }, () => Wallet.createRandom().address);
const SAFE = Wallet.createRandom().address;
const facts = (o: Partial<{ singleton: string; owners: string[]; threshold: bigint; modules?: string[] }> = {}) => ({
  singleton: SAFE_V141.singletonL2,
  owners: [A, B, C],
  threshold: 2n,
  modules: [] as string[] | undefined,
  ...o,
});

describe('the company Safe (scripts/lib/productionSafe.ts)', function () {
  describe('create-safe.ts on chain 8453 outside the exception', function () {
    it('takes exactly three distinct owners and threshold 2', function () {
      expect(productionSafeSetupRefusal([A, B, C], 2n)).to.equal(null);
    });

    it('refuses another count, another threshold, a repeated owner and the dev wallet', function () {
      expect(productionSafeSetupRefusal([A, B], 2n)).to.match(/exactly 3 owners/);
      expect(productionSafeSetupRefusal([A, B, C, D], 2n)).to.match(/exactly 3 owners/);
      expect(productionSafeSetupRefusal([A], 1n)).to.match(/exactly 3 owners/);
      expect(productionSafeSetupRefusal([A, B, C], 1n)).to.match(/threshold is 2/);
      expect(productionSafeSetupRefusal([A, B, C], 3n)).to.match(/threshold is 2/);
      expect(productionSafeSetupRefusal([A, B, A.toLowerCase()], 2n)).to.match(/twice/);
      expect(productionSafeSetupRefusal([A, B, DEV], 2n)).to.match(/never owns the company Safe/);
      expect(productionSafeSetupRefusal([A, B, '0x1234'], 2n)).to.match(/not an address/);
    });
  });

  describe("the deploy scripts' owner guard (assertMainnetOwner)", function () {
    it('takes a Safe v1.4.1 (L2 or not) with 3 or more owners, threshold 2 or more, no module', function () {
      expect(productionOwnerRefusal(SAFE, facts())).to.equal(null);
      expect(productionOwnerRefusal(SAFE, facts({ singleton: SAFE_V141.singleton }))).to.equal(null);
      expect(productionOwnerRefusal(SAFE, facts({ owners: [A, B, C, D], threshold: 3n }))).to.equal(null);
    });

    it('refuses an EOA or no Safe, another singleton, fewer owners, threshold 1, a module, unreadable modules and the dev wallet', function () {
      expect(productionOwnerRefusal(SAFE, null)).to.match(/not a Safe on this chain/);
      expect(productionOwnerRefusal(SAFE, facts({ singleton: D }))).to.match(/not a Safe v1.4.1 proxy/);
      expect(productionOwnerRefusal(SAFE, facts({ owners: [A, B] }))).to.match(/has 2 owners/);
      expect(productionOwnerRefusal(SAFE, facts({ threshold: 1n }))).to.match(/threshold 1 over 3/);
      expect(productionOwnerRefusal(SAFE, facts({ threshold: 4n }))).to.match(/threshold 4 over 3/);
      expect(productionOwnerRefusal(SAFE, facts({ modules: [D] }))).to.match(/modules enabled/);
      expect(productionOwnerRefusal(SAFE, facts({ modules: undefined }))).to.match(/modules could not be read/);
      expect(productionOwnerRefusal(SAFE, facts({ owners: [A, B, DEV] }))).to.match(/lists the CofferdamDev hot wallet/);
    });

    it("leaves zkp-test-1's threshold-1 Safe to the exception's own check", function () {
      const throwaway = { singleton: SAFE_V141.singletonL2, owners: [DEV], threshold: 1n };
      expect(exceptionOwnerRefusal(SAFE, throwaway)).to.equal(null);
      expect(productionOwnerRefusal(SAFE, throwaway)).to.not.equal(null);
    });
  });
});

describe('CofferdamRelayPaymaster settings (scripts/lib/relayPaymaster.ts)', function () {
  it('reads wei as a positive decimal integer', function () {
    expect(parseWei('X', ' 1000 ')).to.equal(1000n);
    for (const bad of [undefined, '', '0', '-1', '1e15', '0.001', '0x10', '1 000']) expect(() => parseWei('X', bad)).to.throw(/X/);
  });

  it('requires the cap on Base mainnet and public testnets, caps it at 0.01 ETH on mainnet, defaults it locally', function () {
    expect(() => relayPaymasterMaxCost(undefined, { mainnet: true, local: false })).to.throw(/PAYMASTER_MAX_COST_WEI is required/);
    expect(() => relayPaymasterMaxCost('', { mainnet: true, local: true })).to.throw(/required/);
    expect(() => relayPaymasterMaxCost(undefined, { mainnet: false, local: false })).to.throw(/required/);
    expect(relayPaymasterMaxCost(undefined, { mainnet: false, local: true })).to.equal(LOCAL_DEFAULT_MAX_COST);
    expect(relayPaymasterMaxCost(String(MAINNET_MAX_COST_CEILING), { mainnet: true, local: false })).to.equal(MAINNET_MAX_COST_CEILING);
    expect(() => relayPaymasterMaxCost(String(MAINNET_MAX_COST_CEILING + 1n), { mainnet: true, local: false })).to.throw(/likely typo/);
    expect(relayPaymasterMaxCost(String(10n ** 18n), { mainnet: false, local: false })).to.equal(10n ** 18n);
  });

  it('requires the relayer on Base mainnet (no default) and public testnets, defaults it to the deployer locally', function () {
    expect(() => relayPaymasterRelayer(undefined, { mainnet: true, local: true, deployer: A })).to.throw(/RELAYER_ADDRESS is required/);
    expect(() => relayPaymasterRelayer(' ', { mainnet: false, local: false, deployer: A })).to.throw(/required/);
    expect(relayPaymasterRelayer(undefined, { mainnet: false, local: true, deployer: A })).to.equal(A);
    expect(relayPaymasterRelayer(` ${B} `, { mainnet: true, local: false, deployer: A })).to.equal(B);
  });

  it('refuses a relayer that is the owner, the Ledger or the dev wallet on mainnet, a contract, or zero', function () {
    const ok = { owner: SAFE, deployer: A, mainnet: true, code: '0x' };
    expect(relayerRefusal(B, ok)).to.equal(null);
    expect(relayerRefusal(B, { ...ok, code: '0xef0100' + 'ab'.repeat(20) })).to.equal(null); // an EIP-7702 EOA
    expect(relayerRefusal(SAFE, ok)).to.match(/is the owner/);
    expect(relayerRefusal(A, ok)).to.match(/Ledger is never the relayer/);
    expect(relayerRefusal(A, { ...ok, mainnet: false })).to.equal(null); // a local run defaults to the deployer
    expect(relayerRefusal(DEV, ok)).to.match(/CofferdamDev hot wallet/);
    expect(relayerRefusal(B, { ...ok, code: '0x6080' })).to.match(/is a contract/);
    expect(relayerRefusal('0x' + '0'.repeat(40), ok)).to.match(/non-zero/);
  });
});
