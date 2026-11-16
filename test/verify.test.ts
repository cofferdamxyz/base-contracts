import { expect } from 'chai';
import { AbiCoder, Wallet, getCreateAddress } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';

import { constructorArgsHex, createNonce, verifyPlan } from '../scripts/lib/verify';

// scripts/verify.ts's pure parts: what it verifies, how it finds a contract's
// creation nonce, and how it splits a creation input into bytecode and
// constructor arguments. The script itself ran in check-only mode against
// zkp-test-1 on Base mainnet.

const DEPLOYER = Wallet.createRandom().address;

describe('verify (scripts/lib/verify.ts)', function () {
  it("plans every contract of zkp-test-1's deployments file and reports the Safe and the EntryPoint", function () {
    const file = path.join(__dirname, '..', 'deployments', 'baseDevTest.zkp-test-1.json');
    const plan = verifyPlan(JSON.parse(fs.readFileSync(file, 'utf8')));
    expect(plan.ours.map((o) => o.key)).to.have.members([
      'ZKPassportEvidenceAdapter',
      'CofferdamIdentityRegistry',
      'WebAuthnPasskeyAuthority',
      'PartnerPasskeyAuthority',
      'SessionKeyAuthorityLowManaged',
      'CofferdamModuleRegistry',
      'CofferdamCeremonyAttesterRegistry',
      'CofferdamAccountFactory4337',
      'ZKPassportEvidenceAdapterDrill',
      'ZKPassportEvidenceAdapterV0_21_0',
      'ZKPassportEvidenceAdapterV0_22_0',
    ]);
    expect(plan.ours.find((o) => o.key === 'ZKPassportEvidenceAdapterV0_22_0')?.contract).to.equal('ZKPassportEvidenceAdapter');
    expect(plan.ours.find((o) => o.key === 'SessionKeyAuthorityLowManaged')?.contract).to.equal('SessionKeyAuthority');
    expect(plan.ours.find((o) => o.key === 'ZKPassportEvidenceAdapterDrill')?.contract).to.equal('ZKPassportEvidenceAdapter');
    expect(plan.notOurs.map((o) => o.key)).to.have.members(['CofferdamSafe', 'EntryPoint']);
  });

  it('refuses an entry it does not know, so nothing is skipped silently', function () {
    expect(() => verifyPlan({ Mystery: { address: DEPLOYER } })).to.throw(/does not know: add it/);
    expect(verifyPlan({ ZKPassportEvidenceAdapterV0_22_0: { address: DEPLOYER } }).ours[0].contract).to.equal('ZKPassportEvidenceAdapter');
    expect(() => verifyPlan({ ZKPassportEvidenceAdapterV0_22: { address: DEPLOYER } })).to.throw(/does not know/);
    expect(verifyPlan({ devKeyException: undefined, CofferdamSafe: { address: DEPLOYER } }).notOurs).to.have.length(1);
  });

  it("finds the deployer's nonce whose CREATE made the address", function () {
    const at7 = getCreateAddress({ from: DEPLOYER, nonce: 7 });
    expect(createNonce(DEPLOYER, at7, 14)).to.equal(7);
    expect(createNonce(DEPLOYER, at7.toLowerCase(), 14)).to.equal(7);
    expect(createNonce(DEPLOYER, at7, 7)).to.equal(null);
    expect(createNonce(Wallet.createRandom().address, at7, 14)).to.equal(null);
  });

  it('splits a creation input into the compiled bytecode and the constructor arguments', function () {
    const bytecode = '0x6080604052aBcD';
    const args = AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [DEPLOYER, 259200n]);
    expect(constructorArgsHex(bytecode + args.slice(2), bytecode)).to.equal(args.toLowerCase());
    expect(constructorArgsHex(bytecode, bytecode)).to.equal('0x');
    expect(() => constructorArgsHex('0x6080604052ffff' + args.slice(2), bytecode)).to.throw(/does not start with the compiled bytecode/);
    expect(() => constructorArgsHex(args, '0x')).to.throw(/no creation bytecode/);
  });
});
