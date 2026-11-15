import { expect } from 'chai';
import { Wallet, computeAddress } from 'ethers';

import { assertMainnetSigner, getDeployer } from '../scripts/lib/chain';
import {
  DEV_KEY_EXCEPTION,
  assertNoMainnetKeys,
  devKeyAccounts,
  devKeyExceptionRecord,
  devKeyExceptionRefusal,
  mainnetRegistryOwner,
  mainnetSignerRefusal,
} from '../scripts/lib/devKeyException';

// The M2 dev-key exception (workspace docs/runbooks/mainnet-deploys.md): the
// CofferdamDev wallet deploys and owns zkp-test-1 on Base mainnet through
// `baseDevTest`, and nothing else on chain 8453 signs with a key. Pure checks,
// no network; no real key is used or printed (the allowed path stubs the
// key-to-address step).

const DEV = DEV_KEY_EXCEPTION.signer;
const LEDGER = '0x00000000000000000000000000000000000Ce11E';
const OTHER = Wallet.createRandom();
const OK = { MAINNET_DEV_KEY_EXCEPTION: 'zkp-test-1', GENERATION: 'zkp-test-1' };
const stubKey = '0x' + '11'.repeat(32);
const derive = (key: string) => (key === stubKey ? DEV : computeAddress(key));

async function rejection(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return (e as Error).message;
  }
  return 'resolved';
}

describe('M2 dev-key exception', function () {
  describe('the request', function () {
    it('is well formed only for zkp-test-1 in both variables, without LEDGER_ADDRESS', function () {
      expect(devKeyExceptionRefusal({})).to.equal(null);
      expect(devKeyExceptionRefusal(OK)).to.equal(null);
      expect(devKeyExceptionRefusal({ ...OK, MAINNET_DEV_KEY_EXCEPTION: '1' })).to.match(/covers zkp-test-1 only/);
      expect(devKeyExceptionRefusal({ ...OK, MAINNET_DEV_KEY_EXCEPTION: 'zkp-test-2' })).to.match(/covers zkp-test-1 only/);
      expect(devKeyExceptionRefusal({ ...OK, GENERATION: 'zkp-test-2' })).to.match(/needs GENERATION=zkp-test-1/);
      expect(devKeyExceptionRefusal({ MAINNET_DEV_KEY_EXCEPTION: 'zkp-test-1' })).to.match(/needs GENERATION=zkp-test-1/);
      expect(devKeyExceptionRefusal({ ...OK, LEDGER_ADDRESS: LEDGER })).to.match(/not both/);
    });
  });

  describe("baseDevTest's accounts (hardhat.config.ts)", function () {
    it('lists no key without the exception, whatever DEPLOYER_PRIVATE_KEY holds', function () {
      expect(devKeyAccounts({ DEPLOYER_PRIVATE_KEY: stubKey }, derive)).to.deep.equal([]);
      expect(devKeyAccounts({ GENERATION: 'zkp-test-1', DEPLOYER_PRIVATE_KEY: stubKey }, derive)).to.deep.equal([]);
    });

    it("lists the CofferdamDev wallet's key under the exception", function () {
      expect(devKeyAccounts({ ...OK, DEPLOYER_PRIVATE_KEY: stubKey }, derive)).to.deep.equal([stubKey]);
      expect(devKeyAccounts(OK, derive)).to.deep.equal([]);
    });

    it("refuses another wallet's key, a malformed key and a malformed request", function () {
      expect(() => devKeyAccounts({ ...OK, DEPLOYER_PRIVATE_KEY: OTHER.privateKey }, derive)).to.throw(/not the CofferdamDev wallet/);
      expect(() => devKeyAccounts({ ...OK, DEPLOYER_PRIVATE_KEY: '0x1234' }, derive)).to.throw(/not a valid private key/);
      expect(() => devKeyAccounts({ ...OK, GENERATION: 'zkp-test-2', DEPLOYER_PRIVATE_KEY: stubKey }, derive)).to.throw(/GENERATION/);
    });

    it('never echoes the key in a refusal', function () {
      try {
        devKeyAccounts({ ...OK, DEPLOYER_PRIVATE_KEY: OTHER.privateKey }, derive);
        expect.fail('should refuse');
      } catch (e) {
        expect((e as Error).message).not.to.include(OTHER.privateKey.slice(2));
      }
    });
  });

  describe('no key on chain 8453 (hardhat.config.ts)', function () {
    const nets = (accounts: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(accounts).map(([name, a]) => [name, { chainId: 8453, accounts: a }]));

    it('lets baseDevTest carry one key under the exception only', function () {
      expect(() => assertNoMainnetKeys(nets({ baseDevTest: [stubKey] }), OK)).not.to.throw();
      expect(() => assertNoMainnetKeys(nets({ baseDevTest: [stubKey] }), {})).to.throw(/lists private keys/);
      expect(() => assertNoMainnetKeys(nets({ baseDevTest: [stubKey, stubKey] }), OK)).to.throw(/lists private keys/);
    });

    it('refuses a key on any other chain-8453 network, the exception or not', function () {
      expect(() => assertNoMainnetKeys(nets({ base: [stubKey] }), OK)).to.throw(/network base/);
      expect(() => assertNoMainnetKeys(nets({ baseFork: [stubKey] }), OK)).to.throw(/network baseFork/);
      expect(() => assertNoMainnetKeys({ ...nets({ base: [], baseFork: 'remote' }), hardhat: { chainId: 8453, accounts: [stubKey] } }, {})).not.to.throw();
    });
  });

  describe('the deployer on chain 8453 (scripts/lib/chain.ts)', function () {
    const live = { fork: false, hasKeys: true, ledgerAccounts: [] as string[] };

    it('allows the CofferdamDev wallet on baseDevTest for zkp-test-1', function () {
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: DEV, env: OK })).to.equal(null);
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: DEV.toLowerCase(), env: OK })).to.equal(null);
    });

    it('refuses another signer, another generation and another network under the exception', function () {
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: OTHER.address, env: OK })).to.match(/must be the CofferdamDev wallet/);
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: DEV, env: { ...OK, GENERATION: 'zkp-test-2' } })).to.match(/GENERATION/);
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: DEV, env: { ...OK, MAINNET_DEV_KEY_EXCEPTION: 'yes' } })).to.match(/zkp-test-1 only/);
      expect(mainnetSignerRefusal({ ...live, hasKeys: false, networkName: 'base', signer: DEV, env: OK })).to.match(/stays Ledger-only/);
    });

    it('refuses baseDevTest and any key without the exception', function () {
      expect(mainnetSignerRefusal({ ...live, networkName: 'baseDevTest', signer: DEV, env: {} })).to.match(/only under the dev-key exception/);
      expect(mainnetSignerRefusal({ ...live, networkName: 'base', signer: DEV, ledgerAccounts: [DEV], env: {} })).to.match(/private keys configured/);
      expect(mainnetSignerRefusal({ ...live, hasKeys: false, networkName: 'base', signer: DEV, env: {} })).to.match(/must be a Ledger account/);
    });

    it('keeps the Ledger path on base', function () {
      expect(mainnetSignerRefusal({ ...live, hasKeys: false, networkName: 'base', signer: LEDGER, ledgerAccounts: [LEDGER], env: { GENERATION: 'zkp-test-1' } })).to.equal(null);
    });

    it('runs the same checks on a fork dry run, on any network', function () {
      const fork = { fork: true, hasKeys: false, ledgerAccounts: [] as string[], networkName: 'baseFork' };
      expect(mainnetSignerRefusal({ ...fork, signer: DEV, env: OK })).to.equal(null);
      expect(mainnetSignerRefusal({ ...fork, signer: OTHER.address, env: OK })).to.match(/must be the CofferdamDev wallet/);
      expect(mainnetSignerRefusal({ ...fork, signer: DEV, env: { ...OK, GENERATION: 'zkp-dryrun-1' } })).to.match(/GENERATION/);
      expect(mainnetSignerRefusal({ ...fork, signer: OTHER.address, env: {} })).to.equal(null);
    });
  });

  describe('the registry owner', function () {
    it('is the CofferdamDev wallet under the exception, by default or repeated', function () {
      expect(mainnetRegistryOwner(OK)).to.equal(DEV);
      expect(mainnetRegistryOwner({ ...OK, REGISTRY_OWNER: DEV.toLowerCase() })).to.equal(DEV);
      expect(() => mainnetRegistryOwner({ ...OK, REGISTRY_OWNER: LEDGER })).to.throw(/REGISTRY_OWNER is the CofferdamDev wallet/);
    });

    it('is REGISTRY_OWNER, required, without it', function () {
      expect(mainnetRegistryOwner({ REGISTRY_OWNER: LEDGER })).to.equal(LEDGER);
      expect(() => mainnetRegistryOwner({})).to.throw(/REGISTRY_OWNER is required/);
    });
  });

  it('records the exception for the deployments file', function () {
    const r = devKeyExceptionRecord();
    expect(r.generation).to.equal('zkp-test-1');
    expect(r.deployer).to.equal(DEV);
    expect(r.owner).to.equal(DEV);
    expect(r.note).to.match(/never production/);
  });

  describe('off Base mainnet (the in-process network, chain 31337)', function () {
    const saved = { ...process.env };
    afterEach(function () {
      for (const k of ['MAINNET_DEV_KEY_EXCEPTION', 'GENERATION']) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    });

    it('refuses the exception, so it never applies to another chain', async function () {
      Object.assign(process.env, OK);
      const deployer = await getDeployer();
      expect(await rejection(assertMainnetSigner(deployer.address))).to.match(/for Base mainnet \(chain 8453\) only/);
    });

    it('refuses a malformed request before choosing a deployer', async function () {
      Object.assign(process.env, { ...OK, GENERATION: 'zkp-test-2' });
      expect(await rejection(getDeployer())).to.match(/GENERATION/);
    });
  });
});
