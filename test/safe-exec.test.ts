import { expect } from 'chai';
import { Wallet } from 'ethers';

import { DEV_KEY_EXCEPTION, SAFE_V141 } from '../scripts/lib/devKeyException';
import {
  SAFE_ACTIONS,
  activationRefusal,
  adapterKeyForVersion,
  parseAllowed,
  parseSafeAction,
  reproposalRefusal,
  safeExecRefusal,
  senderOwnerSignature,
} from '../scripts/lib/safe';

// scripts/safe-exec.ts's pure parts: the action, the sender's pre-validated
// signature and the Safe it may execute through. The script itself was
// rehearsed on a fork of Base mainnet against zkp-test-1's Safe.

const DEV = DEV_KEY_EXCEPTION.signer;
const SAFE = '0xC25c20Fb99f470567F38250acE1A04C095546bFe';
const OTHER = Wallet.createRandom().address;
const facts = { singleton: SAFE_V141.singletonL2, owners: [DEV], threshold: 1n };

describe('safe-exec (scripts/lib/safe.ts)', function () {
  it('takes only the listed actions', function () {
    for (const a of SAFE_ACTIONS) expect(parseSafeAction(` ${a} `)).to.equal(a);
    expect(() => parseSafeAction(undefined)).to.throw(/SAFE_ACTION is one of/);
    expect(() => parseSafeAction('transferOwnership')).to.throw(/SAFE_ACTION is one of/);
  });

  it("encodes the sender's pre-validated signature: r = owner, s = 0, v = 1", function () {
    const sig = senderOwnerSignature(DEV);
    expect(sig).to.have.length(2 + 130);
    expect(sig.slice(2, 66)).to.equal('0'.repeat(24) + DEV.slice(2).toLowerCase());
    expect(sig.slice(66, 130)).to.equal('0'.repeat(64));
    expect(sig.slice(130)).to.equal('01');
    expect(() => senderOwnerSignature('0x1234')).to.throw(/Not an address/);
  });

  it('executes through a v1.4.1 Safe that lists the signer at threshold 1', function () {
    expect(safeExecRefusal(SAFE, facts, DEV, SAFE)).to.equal(null);
    expect(safeExecRefusal(SAFE, { ...facts, singleton: SAFE_V141.singleton }, DEV.toLowerCase())).to.equal(null);
  });

  it('refuses another Safe than the recorded one, no Safe, another singleton, another signer and a higher threshold', function () {
    expect(safeExecRefusal(SAFE, facts, DEV, OTHER)).to.match(/not the generation's recorded CofferdamSafe/);
    expect(safeExecRefusal(SAFE, null, DEV)).to.match(/No Safe/);
    expect(safeExecRefusal(SAFE, { ...facts, singleton: OTHER }, DEV)).to.match(/not a Safe v1.4.1 proxy/);
    expect(safeExecRefusal(SAFE, facts, OTHER)).to.match(/does not list the signer/);
    expect(safeExecRefusal(SAFE, { ...facts, owners: [DEV, OTHER], threshold: 2n }, DEV)).to.match(/threshold 2/);
  });

  it('keys an adapter by its circuits version, and refuses anything else', function () {
    expect(adapterKeyForVersion('0.22.0')).to.equal('ZKPassportEvidenceAdapterV0_22_0');
    expect(adapterKeyForVersion(' 0.21.0 ')).to.equal('ZKPassportEvidenceAdapterV0_21_0');
    for (const bad of [undefined, '', '0.22', 'v0.22.0', '0.22.0; rm', '0.22.0.1']) {
      expect(() => adapterKeyForVersion(bad)).to.throw(/ZKP_CIRCUITS_VERSION/);
    }
  });

  it("activates only after the timelock and within the grace, the registry's rule", function () {
    const grace = 7n * 86_400n;
    const readyAt = 1_795_044_374n;
    expect(activationRefusal(0n, readyAt, grace)).to.match(/not proposed/);
    expect(activationRefusal(readyAt, readyAt - 1n, grace)).to.match(/timelock ends at 2026-11-18T23:26:14/);
    expect(activationRefusal(readyAt, readyAt, grace)).to.equal(null);
    expect(activationRefusal(readyAt, readyAt + grace, grace)).to.equal(null);
    expect(activationRefusal(readyAt, readyAt + grace + 1n, grace)).to.match(/expired .*propose it again/);
  });

  it('proposes again only once a proposal has expired, so a live one keeps its clock', function () {
    const grace = 7n * 86_400n;
    const readyAt = 1_795_044_374n;
    expect(reproposalRefusal(0n, readyAt, grace)).to.equal(null);
    expect(reproposalRefusal(readyAt, readyAt - 1n, grace)).to.match(/proposed already: activate it from 2026-11-18T23:26:14.*adapter-cancel/);
    expect(reproposalRefusal(readyAt, readyAt + grace, grace)).to.match(/proposed already/);
    // Where activate answers "expired: propose it again", propose takes it.
    expect(activationRefusal(readyAt, readyAt + grace + 1n, grace)).to.match(/propose it again/);
    expect(reproposalRefusal(readyAt, readyAt + grace + 1n, grace)).to.equal(null);
  });

  it('takes ALLOWED as 1 (or unset) to add and 0 to remove, and refuses anything else', function () {
    for (const add of [undefined, '', ' ', '1', ' 1 ']) expect(parseAllowed(add)).to.equal(true);
    expect(parseAllowed('0')).to.equal(false);
    expect(parseAllowed(' 0 ')).to.equal(false);
    for (const bad of ['true', 'yes', 'TRUE', 'false', 'no', '01', '2', 'o']) expect(() => parseAllowed(bad)).to.throw(/ALLOWED is 1 .* or 0/);
  });
});
