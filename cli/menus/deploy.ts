import { ethers } from 'ethers';
import { select } from '@inquirer/prompts';
import { loadConfig, updateConfig, DEFAULT_ENTRYPOINT } from '../lib/config';
import { PrefundedWallet, createSigner } from '../lib/wallets';
import { deployContract } from '../lib/artifacts';
import { printHeader, printKV } from '../lib/format';

const ENTRYPOINT_V07 = DEFAULT_ENTRYPOINT;

export async function deployMenu(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const choices = [
    { name: 'Deploy all base contracts (auth + self)', value: 'all' },
    { name: 'Deploy auth framework only', value: 'auth' },
    { name: 'Deploy Self.xyz contracts only', value: 'self' },
    { name: 'Back', value: 'back' },
  ];

  const action = await select({ message: 'Deploy menu:', choices });

  if (action === 'back') return;

  const signer = createSigner(wallet, rpcUrl);

  switch (action) {
    case 'all':
      await deployAuth(signer);
      await deploySelf(signer);
      console.log('\n  ✓ All base contracts deployed.');
      break;
    case 'auth':
      await deployAuth(signer);
      break;
    case 'self':
      await deploySelf(signer);
      break;
  }
}

async function deployAuth(signer: ethers.Wallet): Promise<void> {
  printHeader('Deploying Auth Framework');

  const passkeyAuth = await deployContract(signer, 'auth/PasskeyAuthority');
  printKV('PasskeyAuthority', await passkeyAuth.getAddress());

  const webAuthnAuth = await deployContract(signer, 'auth/WebAuthnPasskeyAuthority');
  printKV('WebAuthnPasskeyAuthority', await webAuthnAuth.getAddress());

  const sessionUntrusted = await deployContract(signer, 'auth/SessionKeyAuthority', 1);
  printKV('SessionKeyAuthority (untrusted)', await sessionUntrusted.getAddress());

  const sessionManaged = await deployContract(signer, 'auth/SessionKeyAuthority', 2);
  printKV('SessionKeyAuthority (managed)', await sessionManaged.getAddress());

  const factory = await deployContract(signer, 'account/CofferdamAccountFactory4337', ENTRYPOINT_V07);
  printKV('CofferdamAccountFactory4337', await factory.getAddress());

  const paymaster = await deployContract(signer, 'account/CofferdamPaymaster', ENTRYPOINT_V07);
  printKV('CofferdamPaymaster (stub)', await paymaster.getAddress());

  updateConfig({
    entryPoint: ENTRYPOINT_V07,
    passkeyAuthority: await passkeyAuth.getAddress(),
    webAuthnPasskeyAuthority: await webAuthnAuth.getAddress(),
    sessionKeyAuthorityUntrusted: await sessionUntrusted.getAddress(),
    sessionKeyAuthorityManaged: await sessionManaged.getAddress(),
    accountFactory: await factory.getAddress(),
    paymaster: await paymaster.getAddress(),
  });
  console.log('\n  ✓ Auth contracts deployed and saved to config.');
}

async function deploySelf(signer: ethers.Wallet): Promise<void> {
  printHeader('Deploying Self.xyz Contracts');

  const attesterReg = await deployContract(signer, 'self/SelfAttesterRegistry', signer.address, []);
  printKV('SelfAttesterRegistry', await attesterReg.getAddress());

  let verifierAddress = process.env.SELF_VERIFIER_ADDRESS;
  if (!verifierAddress || verifierAddress === ethers.ZeroAddress) {
    const mockVerifier = await deployContract(signer, 'test/MockGroth16Verifier');
    verifierAddress = await mockVerifier.getAddress();
    printKV('MockGroth16Verifier (dev)', verifierAddress);
  }

  const scope = process.env.SELF_SCOPE || '0';
  const nullifierReg = await deployContract(
    signer,
    'self/NullifierRegistry',
    verifierAddress!,
    await attesterReg.getAddress(),
    BigInt(scope)
  );
  printKV('NullifierRegistry', await nullifierReg.getAddress());

  updateConfig({
    selfAttesterRegistry: await attesterReg.getAddress(),
    nullifierRegistry: await nullifierReg.getAddress(),
    mockGroth16Verifier: verifierAddress,
  });
  console.log('\n  ✓ Self.xyz contracts deployed and saved to config.');
}
