import { expect } from 'chai';
import { ethers } from 'hardhat';

describe('AuthorityManagerBase (via CofferdamAccount4337)', () => {
  const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

  it('should deploy a passkey-first account and close the ratchet', async () => {
    const PasskeyAuthority = await ethers.getContractFactory('PasskeyAuthority');
    const passkeyAuth = await PasskeyAuthority.deploy();
    await passkeyAuth.waitForDeployment();

    // Generate a dummy P-256 public key
    const qx = ethers.randomBytes(32);
    const qy = ethers.randomBytes(32);
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'], [qx, qy]);

    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account = await Account.deploy(ENTRYPOINT_V07, await passkeyAuth.getAddress(), config);
    await account.waitForDeployment();

    // A passkey at genesis should close the ratchet
    expect(await account.upgradeLocked()).to.be.true;
    expect(await account.passkeyCount()).to.equal(1);
    expect(await account.authorityCount()).to.equal(1);
  });

  it('should deploy a session-first account with ratchet open', async () => {
    const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
    const sessionAuth = await SessionKeyAuthority.deploy(1); // LowUntrusted
    await sessionAuth.waitForDeployment();

    const [signer] = await ethers.getSigners();
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [signer.address]);

    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account = await Account.deploy(ENTRYPOINT_V07, await sessionAuth.getAddress(), config);
    await account.waitForDeployment();

    // Session key at genesis: ratchet NOT locked, no passkeys
    expect(await account.upgradeLocked()).to.be.false;
    expect(await account.passkeyCount()).to.equal(0);
    expect(await account.authorityCount()).to.equal(1);
  });
});

describe('CofferdamAccountFactory4337', () => {
  const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

  it('should compute deterministic counterfactual addresses', async () => {
    const PasskeyAuthority = await ethers.getContractFactory('PasskeyAuthority');
    const passkeyAuth = await PasskeyAuthority.deploy();
    await passkeyAuth.waitForDeployment();

    const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
    const factory = await Factory.deploy(ENTRYPOINT_V07);
    await factory.waitForDeployment();

    const qx = ethers.id('test-qx');
    const qy = ethers.id('test-qy');
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'], [qx, qy]);
    const salt = ethers.id('test-salt');

    const authorityAddress = await passkeyAuth.getAddress();
    const addr1 = await factory.getFunction('getAddress')(authorityAddress, config, salt);
    const addr2 = await factory.getFunction('getAddress')(authorityAddress, config, salt);
    expect(addr1).to.equal(addr2);
    expect(addr1).to.not.equal(ethers.ZeroAddress);
  });
});

describe('SessionKeyAuthority', () => {
  it('should verify a valid session signer signature', async () => {
    const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
    const sessionAuth = await SessionKeyAuthority.deploy(1); // LowUntrusted
    await sessionAuth.waitForDeployment();

    const [signer] = await ethers.getSigners();
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [signer.address]);

    // Sign a digest — the module computes keccak256(account, digest) then EIP-191 prefix
    const digest = ethers.id('test-digest');
    const bound = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'bytes32'],
      [ethers.ZeroAddress, digest]
    ));
    // EIP-191 personal_sign
    const ethHash = ethers.hashMessage(ethers.getBytes(bound));
    // Use raw signing key from the hardhat signer
    const signingKey = new ethers.SigningKey(
      // hardhat default signer #0 private key
      '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
    );
    const sig = signingKey.sign(ethHash);
    const signature = ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);

    const valid = await sessionKeyIsValidSignature(
      sessionAuth,
      ethers.ZeroAddress,
      digest,
      config,
      signature
    );
    expect(valid).to.be.true;
  });
});

// Helper: call isValidSignature on a module
async function sessionKeyIsValidSignature(
  module: any,
  account: string,
  digest: string,
  config: string,
  signature: string
): Promise<boolean> {
  return await module.isValidSignature(account, digest, config, signature);
}
