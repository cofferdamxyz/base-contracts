import { expect } from 'chai';
import { Wallet, ethers } from 'ethers';

import { DEV_KEY_EXCEPTION, SAFE_V141 } from '../scripts/lib/devKeyException';
import {
  PROPOSE_ACTIONS,
  SAFE_TX_TYPES,
  actionTarget,
  packSafeSignatures,
  parseProposeAction,
  proposalNonce,
  safeCallTx,
  safeProposeRefusal,
  safeTxDomain,
  safeTxHash,
  safeTxHashParts,
  txBuilderChecksum,
  txBuilderFile,
} from '../scripts/lib/safeProposal';

// scripts/safe-propose.ts's pure parts: the actions, the Safe it proposes
// through, the nonce, the Safe transaction hash, the Transaction Builder file
// and the signature packing. test/fork/relay-paymaster-fork.test.ts runs the
// whole path against a real Safe v1.4.1 on a fork of Base mainnet.

const SAFE = '0x' + '5a'.repeat(20);
const OTHER = Wallet.createRandom().address;
const [A, B, C] = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
const facts = { singleton: SAFE_V141.singletonL2, owners: [A.address, B.address, C.address], threshold: 2n, modules: [] };

describe('safe-propose (scripts/lib/safeProposal.ts)', function () {
  it('takes the listed actions, and sends the drills back to their single steps', function () {
    for (const a of PROPOSE_ACTIONS) expect(parseProposeAction(` ${a} `)).to.equal(a);
    expect(() => parseProposeAction('pause-drill')).to.throw(/propose SAFE_ACTION=pause, then SAFE_ACTION=unpause/);
    expect(() => parseProposeAction('adapter-drill')).to.throw(/adapter-propose, then SAFE_ACTION=adapter-cancel/);
    expect(() => parseProposeAction(undefined)).to.throw(/SAFE_ACTION is one of/);
    expect(() => parseProposeAction('renounceOwnership')).to.throw(/SAFE_ACTION is one of/);
  });

  it('routes each family to its contract and Safe record', function () {
    expect(actionTarget('paymaster-pause').key).to.equal('CofferdamRelayPaymaster');
    expect(actionTarget('anchor-lift-freeze')).to.deep.equal({ key: 'CofferdamHandleAnchor', env: 'HANDLE_ANCHOR', safeKeys: ['CofferdamHandleAnchorSafe', 'CofferdamSafe'] });
    expect(actionTarget('set-test-account').key).to.equal('CofferdamIdentityRegistry');
  });

  it('proposes through a v1.4.1 Safe with threshold 2 or more, the recorded one, never a threshold-1 Safe', function () {
    expect(safeProposeRefusal(SAFE, facts, SAFE)).to.equal(null);
    expect(safeProposeRefusal(SAFE, { ...facts, singleton: SAFE_V141.singleton })).to.equal(null);
    expect(safeProposeRefusal(SAFE, facts, OTHER)).to.match(/not the generation's recorded Safe/);
    expect(safeProposeRefusal(SAFE, null)).to.match(/No Safe/);
    expect(safeProposeRefusal(SAFE, { ...facts, singleton: OTHER })).to.match(/not a Safe v1.4.1 proxy/);
    expect(safeProposeRefusal(SAFE, { ...facts, owners: [DEV_KEY_EXCEPTION.signer], threshold: 1n })).to.match(/safe-exec.ts/);
  });

  it('takes the current nonce, or a later one, never a used one', function () {
    expect(proposalNonce(undefined, 7n)).to.equal(7n);
    expect(proposalNonce(' 9 ', 7n)).to.equal(9n);
    expect(() => proposalNonce('6', 7n)).to.throw(/used already/);
    expect(() => proposalNonce('0x9', 7n)).to.throw(/decimal integer/);
  });

  it("hashes the Safe transaction as Safe v1.4.1's EIP-712 (domain: chainId and the Safe), no refund fields", function () {
    const tx = safeCallTx(OTHER, 0n, '0x1234', 3n);
    expect(tx).to.include({ operation: 0, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ethers.ZeroAddress, refundReceiver: ethers.ZeroAddress, nonce: 3n });
    const hash = safeTxHash(8453n, SAFE, tx);
    const { domainHash, messageHash } = safeTxHashParts(8453n, SAFE, tx);
    expect(ethers.keccak256(ethers.concat(['0x1901', domainHash, messageHash]))).to.equal(hash);
    // Safe's DOMAIN_SEPARATOR_TYPEHASH and SAFE_TX_TYPEHASH (Safe.sol v1.4.1).
    expect(domainHash).to.equal(
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'uint256', 'address'],
          ['0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218', 8453n, ethers.getAddress(SAFE)],
        ),
      ),
    );
    expect(ethers.TypedDataEncoder.from(SAFE_TX_TYPES).encodeType('SafeTx')).to.equal(
      'SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)',
    );
    expect(ethers.id(ethers.TypedDataEncoder.from(SAFE_TX_TYPES).encodeType('SafeTx'))).to.equal('0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8');
    // Another nonce, chain or Safe is another hash.
    expect(safeTxHash(8453n, SAFE, { ...tx, nonce: 4n })).to.not.equal(hash);
    expect(safeTxHash(84532n, SAFE, tx)).to.not.equal(hash);
    expect(safeTxHash(8453n, OTHER, tx)).to.not.equal(hash);
  });

  it('packs signatures sorted by owner and refuses a duplicate, a short or a mismatched one', async function () {
    const tx = safeCallTx(OTHER, 0n, '0x', 0n);
    const hash = safeTxHash(8453n, SAFE, tx);
    const sign = (w: { signTypedData: Wallet["signTypedData"] }) => w.signTypedData(safeTxDomain(8453n, SAFE), SAFE_TX_TYPES, tx);
    const sigs = [
      { owner: A.address, signature: await sign(A) },
      { owner: B.address, signature: await sign(B) },
      { owner: C.address, signature: await sign(C) },
    ];
    const packed = ethers.getBytes(packSafeSignatures(hash, sigs));
    expect(packed.length).to.equal(195);
    const order = [...sigs].sort((x, y) => (BigInt(x.owner) < BigInt(y.owner) ? -1 : 1)).map((s) => s.owner);
    for (let i = 0; i < 3; i++) {
      expect(ethers.recoverAddress(hash, ethers.hexlify(packed.slice(65 * i, 65 * (i + 1))))).to.equal(order[i]);
    }
    expect(() => packSafeSignatures(hash, [sigs[0], sigs[0]])).to.throw(/Two signatures/);
    expect(() => packSafeSignatures(hash, [{ owner: A.address, signature: '0x1234' }])).to.throw(/not 65 bytes/);
    expect(() => packSafeSignatures(hash, [{ owner: A.address, signature: sigs[1].signature }])).to.throw(/does not recover/);
  });

  it('writes a Transaction Builder file whose checksum leaves out the name and covers everything else', function () {
    const base = { chainId: 8453n, safe: SAFE, createdAt: 1, name: 'one', description: 'd', tx: { to: OTHER, value: '0', data: '0x1234' } };
    const file = txBuilderFile(base);
    expect(file.version).to.equal('1.0');
    expect(file.chainId).to.equal('8453');
    expect(file.meta.createdFromSafeAddress).to.equal(ethers.getAddress(SAFE));
    expect(file.transactions).to.deep.equal([{ to: ethers.getAddress(OTHER), value: '0', data: '0x1234' }]);
    expect(file.meta.checksum).to.equal(txBuilderChecksum(file));
    expect(txBuilderFile({ ...base, name: 'another' }).meta.checksum).to.equal(file.meta.checksum);
    expect(txBuilderFile({ ...base, tx: { ...base.tx, data: '0x1235' } }).meta.checksum).to.not.equal(file.meta.checksum);
    expect(txBuilderFile({ ...base, description: 'e' }).meta.checksum).to.not.equal(file.meta.checksum);
    // The Transaction Builder's serialisation: sorted keys, each value followed by a comma.
    const tiny = { version: '1', chainId: '1', createdAt: 0, meta: { name: 'x', description: '', createdFromSafeAddress: SAFE }, transactions: [] };
    const expected = `{["chainId","createdAt","meta","transactions","version"]"1",0,{["createdFromSafeAddress","description","name"]"${SAFE}","",null,},[],"1",}`;
    expect(txBuilderChecksum(tiny)).to.equal(ethers.keccak256(ethers.toUtf8Bytes(expected)));
  });
});
