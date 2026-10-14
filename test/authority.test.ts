import { expect } from 'chai';
import { ethers } from 'hardhat';
import { NO_PERMISSION, permission } from './helpers/keys';

describe('AuthorityManagerBase (via CofferdamAccount4337)', () => {
  const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
  // Read only by hard recovery; any non-zero address deploys the account.
  const NULLIFIER_REGISTRY = ethers.Wallet.createRandom().address;

  async function registries(modules: string[]) {
    const [owner] = await ethers.getSigners();
    const moduleRegistry = await (await ethers.getContractFactory('CofferdamModuleRegistry')).deploy(owner.address, modules);
    const ceremonyRegistry = await (await ethers.getContractFactory('CofferdamCeremonyAttesterRegistry')).deploy(owner.address, []);
    return { moduleRegistry, ceremonyRegistry };
  }

  it('should deploy a passkey-first account with the first-High paths closed', async () => {
    const passkeyAuth = await (await ethers.getContractFactory('PasskeyAuthority')).deploy();
    const { moduleRegistry, ceremonyRegistry } = await registries([await passkeyAuth.getAddress()]);

    // Generate a dummy P-256 public key
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32'], [ethers.randomBytes(32), ethers.randomBytes(32)]);

    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account = await Account.deploy(ENTRYPOINT_V07, moduleRegistry, ceremonyRegistry, NULLIFIER_REGISTRY, 0n, 259_200n, passkeyAuth, config, NO_PERMISSION);
    await account.waitForDeployment();

    expect(await account.upgradeLocked()).to.be.true;
    expect(await account.passkeyCount()).to.equal(1);
    expect(await account.authorityCount()).to.equal(1);
  });

  it('should deploy a Managed-first account with no High yet', async () => {
    const sessionAuth = await (await ethers.getContractFactory('SessionKeyAuthority')).deploy();
    const counter = await (await ethers.getContractFactory('MockCounter')).deploy();
    const { moduleRegistry, ceremonyRegistry } = await registries([await sessionAuth.getAddress()]);

    const [signer] = await ethers.getSigners();
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [signer.address]);
    const grant = permission([[await counter.getAddress(), counter.interface.getFunction('increment')!.selector]]);

    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account = await Account.deploy(ENTRYPOINT_V07, moduleRegistry, ceremonyRegistry, NULLIFIER_REGISTRY, 0n, 259_200n, sessionAuth, config, grant);
    await account.waitForDeployment();

    expect(await account.upgradeLocked()).to.be.false;
    expect(await account.passkeyCount()).to.equal(0);
    expect(await account.authorityCount()).to.equal(1);
  });
});

describe('SessionKeyAuthority', () => {
  it('should verify a valid session signer signature', async () => {
    const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
    const sessionAuth = await SessionKeyAuthority.deploy();
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
