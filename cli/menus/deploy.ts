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

  // Raw P-256 (no RP binding): local and test networks only (decision 0016).
  const passkeyAuth = await deployContract(signer, 'auth/PasskeyAuthority');
  printKV('PasskeyAuthority (test only)', await passkeyAuth.getAddress());

  const webAuthnAuth = await deployContract(signer, 'auth/WebAuthnPasskeyAuthority');
  printKV('WebAuthnPasskeyAuthority (High)', await webAuthnAuth.getAddress());

  const partnerAuth = await deployContract(signer, 'auth/PartnerPasskeyAuthority');
  printKV('PartnerPasskeyAuthority (Partner)', await partnerAuth.getAddress());

  const sessionManaged = await deployContract(signer, 'auth/SessionKeyAuthority');
  printKV('SessionKeyAuthority (Managed)', await sessionManaged.getAddress());

  const modules = await Promise.all([passkeyAuth, webAuthnAuth, partnerAuth, sessionManaged].map((m) => m.getAddress()));
  const moduleRegistry = await deployContract(signer, 'registry/CofferdamModuleRegistry', signer.address, modules);
  printKV('CofferdamModuleRegistry', await moduleRegistry.getAddress());

  const ceremonyRegistry = await deployContract(signer, 'registry/CofferdamCeremonyAttesterRegistry', signer.address, []);
  printKV('CofferdamCeremonyAttesterRegistry', await ceremonyRegistry.getAddress());

  const factory = await deployContract(
    signer,
    'account/CofferdamAccountFactory4337',
    ENTRYPOINT_V07,
    await moduleRegistry.getAddress(),
    await ceremonyRegistry.getAddress(),
  );
  printKV('CofferdamAccountFactory4337', await factory.getAddress());

  const paymaster = await deployContract(signer, 'account/CofferdamPaymaster', ENTRYPOINT_V07);
  printKV('CofferdamPaymaster (stub)', await paymaster.getAddress());

  updateConfig({
    entryPoint: ENTRYPOINT_V07,
    passkeyAuthority: await passkeyAuth.getAddress(),
    webAuthnPasskeyAuthority: await webAuthnAuth.getAddress(),
    partnerPasskeyAuthority: await partnerAuth.getAddress(),
    sessionKeyAuthorityManaged: await sessionManaged.getAddress(),
    moduleRegistry: await moduleRegistry.getAddress(),
    ceremonyAttesterRegistry: await ceremonyRegistry.getAddress(),
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
