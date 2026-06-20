import { ethers } from 'ethers';
import { select, input, confirm } from '@inquirer/prompts';
import { loadConfig } from '../lib/config';
import { PrefundedWallet, createSigner, getWallets } from '../lib/wallets';
import { getContract } from '../lib/artifacts';
import { printHeader, printKV, fmtAddr } from '../lib/format';

interface MockPassportData {
  name: string;
  countryCode: string;
  nullifier: bigint;
}

export async function selfMenu(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();

  if (!config.selfAttesterRegistry || !config.nullifierRegistry) {
    console.log('\n  ⚠ Self.xyz contracts not deployed. Run Deploy → Self.xyz first.');
    return;
  }

  const action = await select({
    message: 'Self.xyz menu:',
    choices: [
      { name: 'Mock verifyAndBind — full mocked passport flow', value: 'mockBind' },
      { name: 'Add trusted attester', value: 'addAttester' },
      { name: 'Remove trusted attester', value: 'removeAttester' },
      { name: 'List trusted attesters', value: 'listAttesters' },
      { name: 'Check if account is bound (nullifier)', value: 'checkBound' },
      { name: 'Check nullifier → account mapping', value: 'checkNullifier' },
      { name: 'Back', value: 'back' },
    ],
  });

  if (action === 'back') return;

  const signer = createSigner(wallet, rpcUrl);

  switch (action) {
    case 'mockBind':
      await mockVerifyAndBind(signer, config, rpcUrl);
      break;
    case 'addAttester':
      await addAttester(signer, config.selfAttesterRegistry!);
      break;
    case 'removeAttester':
      await removeAttester(signer, config.selfAttesterRegistry!);
      break;
    case 'listAttesters':
      await listAttesters(signer, config.selfAttesterRegistry!);
      break;
    case 'checkBound':
      await checkBound(signer, config.nullifierRegistry!);
      break;
    case 'checkNullifier':
      await checkNullifier(signer, config.nullifierRegistry!);
      break;
  }
}

const MOCK_PASSPORTS: MockPassportData[] = [
  { name: 'Alice Johnson', countryCode: 'US', nullifier: 1000001n },
  { name: 'Bob Smith', countryCode: 'GB', nullifier: 1000002n },
  { name: 'Carlos García', countryCode: 'ES', nullifier: 1000003n },
  { name: 'Diana Müller', countryCode: 'DE', nullifier: 1000004n },
  { name: 'Erika Lindberg', countryCode: 'SE', nullifier: 1000005n },
];

function packStringToUint256(str: string): bigint {
  if (str.length === 0) return 0n;
  const hex = ethers.hexlify(ethers.toUtf8Bytes(str));
  return BigInt(hex);
}

function packCountryCode(code: string): bigint {
  return packStringToUint256(code);
}

function buildMockPubSignals(
  account: string,
  scope: bigint,
  passport: MockPassportData
): bigint[] {
  const pubSignals: bigint[] = new Array(21).fill(0n);

  pubSignals[0] = packStringToUint256(passport.name.slice(0, 32));
  pubSignals[1] = packStringToUint256(passport.name.slice(32, 64));
  pubSignals[2] = packCountryCode(passport.countryCode);
  pubSignals[7] = passport.nullifier;
  pubSignals[8] = 1n;
  pubSignals[19] = scope;
  pubSignals[20] = BigInt(account);

  return pubSignals;
}

async function mockVerifyAndBind(
  signer: ethers.Wallet,
  config: ReturnType<typeof loadConfig>,
  rpcUrl: string
): Promise<void> {
  printHeader('Mock verifyAndBind (Mocked Passport)');

  const nullifierRegistry = getContract(signer, 'self/NullifierRegistry', config.nullifierRegistry!);
  const attesterRegistry = getContract(signer, 'self/SelfAttesterRegistry', config.selfAttesterRegistry!);

  const provider = signer.provider!;
  const network = await provider.getNetwork();
  const chainId = network.chainId;
  const expectedScope = await nullifierRegistry.expectedScope();
  const registryAddr = config.nullifierRegistry!;

  printKV('Chain ID', chainId.toString());
  printKV('NullifierRegistry', fmtAddr(registryAddr));
  printKV('Expected scope', expectedScope.toString());

  const accountEntries = Object.entries(config.accounts);
  if (accountEntries.length === 0) {
    console.log('\n  ⚠ No accounts saved. Deploy a CofferdamAccount4337 first.');
    return;
  }

  const accountAddr = await select({
    message: 'Select account to bind:',
    choices: accountEntries.map(([label, addr]) => ({
      name: `${label} — ${fmtAddr(addr)}`,
      value: addr,
    })),
  });

  const isAlreadyBound = await nullifierRegistry.isAccountBound(accountAddr);
  if (isAlreadyBound) {
    console.log('\n  ⚠ Account already bound to a nullifier. Cannot rebind.');
    return;
  }

  const passportChoice = await select({
    message: 'Select mock passport:',
    choices: MOCK_PASSPORTS.map((p, i) => ({
      name: `${p.name} (${p.countryCode})`,
      value: i,
    })),
  });
  const passport = MOCK_PASSPORTS[passportChoice];

  console.log('\n  Mock passport data:');
  printKV('Name', passport.name);
  printKV('Country', passport.countryCode);
  printKV('Nullifier', passport.nullifier.toString());

  const pubSignals = buildMockPubSignals(accountAddr, expectedScope, passport);

  console.log('\n  Public signals (21 uint256):');
  for (let i = 0; i < 21; i++) {
    if (pubSignals[i] !== 0n) {
      printKV(`  [${i}]`, pubSignals[i].toString());
    }
  }

  const attesterCount = await attesterRegistry.trustedAttesterCount();
  if (attesterCount === 0n) {
    console.log('\n  ⚠ No trusted attesters. Adding current wallet as attester...');
    console.log('  (In production, this would be the cofferdam-attester Worker key)');
    const tx = await attesterRegistry.addAttester(signer.address);
    await tx.wait();
    printKV('Added attester', fmtAddr(signer.address));
  }

  const attesterSig = await signAttesterMessage(
    signer,
    chainId,
    registryAddr,
    accountAddr,
    pubSignals
  );

  console.log('\n  Attester signature:');
  printKV('Signer', fmtAddr(signer.address));
  printKV('Signature', attesterSig);

  const a: [bigint, bigint] = [1n, 2n];
  const b: [[bigint, bigint], [bigint, bigint]] = [[1n, 2n], [3n, 4n]];
  const c: [bigint, bigint] = [5n, 6n];

  const ok = await confirm({ message: 'Submit verifyAndBind transaction?' });
  if (!ok) return;

  printHeader('Submitting verifyAndBind');
  const tx = await nullifierRegistry.verifyAndBind(
    accountAddr,
    a,
    b,
    c,
    pubSignals,
    attesterSig
  );
  const receipt = await tx.wait();
  printKV('Status', receipt!.status === 1 ? '✓ Success' : '✗ Failed');
  printKV('Tx', tx.hash);

  if (receipt!.status === 1n) {
    const nullifier = await nullifierRegistry.accountToNullifier(accountAddr);
    console.log('\n  ✓ Account bound!');
    printKV('Account', fmtAddr(accountAddr));
    printKV('Nullifier', nullifier.toString());
  }
}

async function signAttesterMessage(
  signer: ethers.Wallet,
  chainId: bigint,
  registryAddr: string,
  account: string,
  pubSignals: bigint[]
): Promise<string> {
  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256[21]'],
    [chainId, registryAddr, account, pubSignals]
  );
  const msgHash = ethers.keccak256(encoded);
  const ethHash = ethers.hashMessage(ethers.getBytes(msgHash));
  const sig = signer.signingKey.sign(ethHash);
  return ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);
}

async function addAttester(signer: ethers.Wallet, addr: string): Promise<void> {
  const attesterAddr = await input({ message: 'Attester address to add:' });
  const registry = getContract(signer, 'self/SelfAttesterRegistry', addr);

  printHeader('Add Trusted Attester');
  const tx = await registry.addAttester(attesterAddr);
  await tx.wait();
  printKV('Added', attesterAddr);
  printKV('Tx', tx.hash);
  console.log('  ✓ Done');
}

async function removeAttester(signer: ethers.Wallet, addr: string): Promise<void> {
  const attesterAddr = await input({ message: 'Attester address to remove:' });
  const registry = getContract(signer, 'self/SelfAttesterRegistry', addr);

  printHeader('Remove Trusted Attester');
  const tx = await registry.removeAttester(attesterAddr);
  await tx.wait();
  printKV('Removed', attesterAddr);
  printKV('Tx', tx.hash);
  console.log('  ✓ Done');
}

async function listAttesters(signer: ethers.Wallet, addr: string): Promise<void> {
  const registry = getContract(signer, 'self/SelfAttesterRegistry', addr);

  printHeader('Trusted Attesters');
  const count = await registry.trustedAttesterCount();
  printKV('Count', count.toString());

  if (count === 0n) {
    console.log('  No attesters registered.');
    return;
  }

  console.log('\n  Checking known wallet addresses:\n');
  const wallets = getWallets();
  let found = 0;
  for (const w of wallets) {
    const isTrusted = await registry.isTrustedAttester(w.address);
    if (isTrusted) {
      printKV(`✓ ${w.label}`, fmtAddr(w.address));
      found++;
    }
  }

  if (found === 0) {
    console.log('  No known wallets are trusted attesters.');
  }

  const checkAddr = await input({ message: 'Check another address (or Enter to skip):' });
  if (checkAddr) {
    const isTrusted = await registry.isTrustedAttester(checkAddr);
    printKV(fmtAddr(checkAddr), isTrusted ? '✓ Trusted' : '✗ Not trusted');
  }
}

async function checkBound(signer: ethers.Wallet, addr: string): Promise<void> {
  const accountAddr = await input({ message: 'Account address to check:' });
  const registry = getContract(signer, 'self/NullifierRegistry', addr);

  printHeader('Check Account Binding');
  const isBound = await registry.isAccountBound(accountAddr);
  printKV('Account', fmtAddr(accountAddr));
  printKV('Bound', isBound ? '✓ Yes' : '✗ No');

  if (isBound) {
    const nullifier = await registry.accountToNullifier(accountAddr);
    printKV('Nullifier', nullifier.toString());
  }
}

async function checkNullifier(signer: ethers.Wallet, addr: string): Promise<void> {
  const nullifierStr = await input({ message: 'Nullifier (uint256):' });
  const registry = getContract(signer, 'self/NullifierRegistry', addr);

  printHeader('Check Nullifier');
  const account = await registry.nullifierToAccount(BigInt(nullifierStr));
  printKV('Nullifier', nullifierStr);
  printKV('Bound to', account === ethers.ZeroAddress ? '✗ None' : fmtAddr(account));
}
