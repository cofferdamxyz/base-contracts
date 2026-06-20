import { ethers } from 'ethers';
import { select, input, confirm } from '@inquirer/prompts';
import { loadConfig, updateConfig } from '../lib/config';
import { PrefundedWallet, createSigner, getWallets } from '../lib/wallets';
import { deployContract, getContract, loadArtifact } from '../lib/artifacts';
import { printHeader, printKV, fmtEth, fmtAddr } from '../lib/format';

export async function accountMenu(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();

  if (!config.accountFactory) {
    console.log('\n  ⚠ No account factory deployed. Run Deploy first.');
    return;
  }

  const action = await select({
    message: 'Account menu:',
    choices: [
      { name: 'Deploy a new CofferdamAccount4337', value: 'deploy' },
      { name: 'List saved accounts', value: 'list' },
      { name: 'Check account balance & authorities', value: 'inspect' },
      { name: 'Fund account with ETH', value: 'fund' },
      { name: 'Send ETH from account (via EntryPoint)', value: 'send' },
      { name: 'Deposit to EntryPoint for gas', value: 'deposit' },
      { name: 'Back', value: 'back' },
    ],
  });

  if (action === 'back') return;

  switch (action) {
    case 'deploy':
      await deployAccount(rpcUrl, wallet);
      break;
    case 'list':
      listAccounts(config);
      break;
    case 'inspect':
      await inspectAccount(rpcUrl, wallet);
      break;
    case 'fund':
      await fundAccount(rpcUrl, wallet);
      break;
    case 'send':
      await sendFromAccount(rpcUrl, wallet);
      break;
    case 'deposit':
      await depositToEntryPoint(rpcUrl, wallet);
      break;
  }
}

async function deployAccount(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  printHeader('Deploy New CofferdamAccount4337');
  const config = loadConfig();
  const signer = createSigner(wallet, rpcUrl);

  const authorityType = await select({
    message: 'Select initial authority type:',
    choices: [
      { name: 'SessionKeyAuthority (LowUntrusted) — legacy/session onboarding', value: 'session' },
      { name: 'WebAuthnPasskeyAuthority (High) — passkey-first onboarding', value: 'passkey' },
    ],
  });

  let moduleAddress: string;
  let initConfig: string;

  if (authorityType === 'session') {
    moduleAddress = config.sessionKeyAuthorityUntrusted!;
    const sessionWallets = getWallets();
    const sessionChoice = await select({
      message: 'Select session signer wallet:',
      choices: sessionWallets.map((w, i) => ({
        name: `${w.label} — ${fmtAddr(w.address)}`,
        value: i,
      })),
    });
    initConfig = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [sessionWallets[sessionChoice].address]);
  } else {
    moduleAddress = config.webAuthnPasskeyAuthority!;
    const useRandom = await confirm({ message: 'Generate random passkey X/Y?', default: true });
    let pubKeyX: string;
    let pubKeyY: string;
    if (useRandom) {
      const x = ethers.randomBytes(32);
      const y = ethers.randomBytes(32);
      pubKeyX = ethers.hexlify(x);
      pubKeyY = ethers.hexlify(y);
      console.log(`  Generated X: ${pubKeyX}`);
      console.log(`  Generated Y: ${pubKeyY}`);
    } else {
      pubKeyX = await input({ message: 'Enter passkey public key X (hex):' });
      pubKeyY = await input({ message: 'Enter passkey public key Y (hex):' });
    }
    initConfig = ethers.AbiCoder.defaultAbiCoder().encode(
      ['uint256', 'uint256'],
      [BigInt(pubKeyX), BigInt(pubKeyY)]
    );
  }

  const label = await input({ message: 'Label for this account (e.g. alice):', default: `account-${Date.now()}` });

  const account = await deployContract(
    signer,
    'account/CofferdamAccount4337',
    config.entryPoint,
    moduleAddress,
    initConfig
  );
  const accountAddr = await account.getAddress();
  printKV('Account deployed', accountAddr);
  printKV('Authority type', authorityType);

  const updated = loadConfig();
  updated.accounts[label] = accountAddr;
  updateConfig({ accounts: updated.accounts });
  console.log(`\n  ✓ Saved as "${label}"`);
}

function listAccounts(config: ReturnType<typeof loadConfig>): void {
  printHeader('Saved Accounts');
  const entries = Object.entries(config.accounts);
  if (entries.length === 0) {
    console.log('  No accounts saved. Deploy one first.');
    return;
  }
  for (const [label, addr] of entries) {
    printKV(label, addr);
  }
}

async function inspectAccount(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();
  const accountAddr = await pickAccount(config);
  if (!accountAddr) return;

  const signer = createSigner(wallet, rpcUrl);
  const provider = signer.provider!;

  printHeader(`Account: ${fmtAddr(accountAddr)}`);

  const ethBalance = await provider.getBalance(accountAddr);
  printKV('ETH balance', fmtEth(ethBalance));

  const code = await provider.getCode(accountAddr);
  printKV('Deployed', code === '0x' ? 'No' : 'Yes');

  const account = getContract(signer, 'account/CofferdamAccount4337', accountAddr);
  const entryPointAddr = await account.ENTRY_POINT();
  printKV('EntryPoint', entryPointAddr);

  const authorityCount = await account.authorityCount();
  printKV('Authority count', authorityCount.toString());

  for (let i = 0n; i < authorityCount; i++) {
    const auth = await account.getAuthority(i);
    const tierNames = ['None', 'LowUntrusted', 'LowManaged', 'High'];
    const tierName = tierNames[Number(auth.tier)] || `Unknown(${auth.tier})`;
    printKV(`  Authority #${i}`, `${fmtAddr(auth.module)} | tier=${tierName} | active=${auth.active}`);
  }

  if (config.entryPoint) {
    const ep = getContract(signer, 'interfaces/IEntryPoint', config.entryPoint);
    const epBalance = await ep.balanceOf(accountAddr);
    printKV('EntryPoint deposit', fmtEth(epBalance));
    const nonce = await ep.getNonce(accountAddr, 0);
    printKV('EntryPoint nonce', nonce.toString());
  }
}

async function fundAccount(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();
  const accountAddr = await pickAccount(config);
  if (!accountAddr) return;

  const amountStr = await input({ message: 'Amount in ETH:', default: '1.0' });
  const amount = ethers.parseEther(amountStr);

  const signer = createSigner(wallet, rpcUrl);
  printHeader('Funding Account');
  const tx = await signer.sendTransaction({ to: accountAddr, value: amount });
  await tx.wait();
  printKV('Funded', `${fmtEth(amount)} → ${fmtAddr(accountAddr)}`);
  printKV('Tx', tx.hash);
  console.log('  ✓ Done');
}

async function depositToEntryPoint(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();
  const accountAddr = await pickAccount(config);
  if (!accountAddr) return;

  const amountStr = await input({ message: 'Deposit amount in ETH:', default: '0.5' });
  const amount = ethers.parseEther(amountStr);

  const signer = createSigner(wallet, rpcUrl);
  const ep = getContract(signer, 'interfaces/IEntryPoint', config.entryPoint);

  printHeader('Depositing to EntryPoint');
  const tx = await ep.depositTo(accountAddr, { value: amount });
  await tx.wait();
  printKV('Deposited', `${fmtEth(amount)} for ${fmtAddr(accountAddr)}`);
  printKV('Tx', tx.hash);
  console.log('  ✓ Done');
}

async function sendFromAccount(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();
  const accountAddr = await pickAccount(config);
  if (!accountAddr) return;

  const signer = createSigner(wallet, rpcUrl);
  const provider = signer.provider!;

  printHeader('Send via EntryPoint v0.7');

  const ep = getContract(signer, 'interfaces/IEntryPoint', config.entryPoint);
  const account = getContract(signer, 'account/CofferdamAccount4337', accountAddr);

  const auth = await account.getAuthority(0n);
  const moduleAddr = auth.module;
  const authConfig = auth.config;
  const tier = Number(auth.tier);

  let signingWallet: PrefundedWallet;

  if (tier === 1 || tier === 2) {
    const sessionSignerAddr = ethers.AbiCoder.defaultAbiCoder().decode(['address'], authConfig)[0];
    const wallets = getWallets();
    const match = wallets.find(w => w.address.toLowerCase() === (sessionSignerAddr as string).toLowerCase());
    if (!match) {
      console.log(`\n  ⚠ Session signer ${fmtAddr(sessionSignerAddr)} not found in available wallets.`);
      console.log('  The session signer must be one of the 10 prefunded Hardhat wallets.');
      return;
    }
    signingWallet = match;
    printKV('Authority', tier === 1 ? 'SessionKey (untrusted)' : 'SessionKey (managed)');
    printKV('Module', fmtAddr(moduleAddr));
    printKV('Session signer', `${match.label} — ${fmtAddr(match.address)}`);
  } else {
    console.log('\n  ⚠ This account uses a passkey authority (WebAuthn/P256).');
    console.log('  Passkey signing is not supported in the CLI.');
    console.log('  Use a session-key account instead, or implement WebAuthn signing.');
    return;
  }

  const toAddr = await input({ message: 'Recipient address:' });
  const amountStr = await input({ message: 'Amount in ETH:', default: '0.01' });
  const amount = ethers.parseEther(amountStr);

  const accountIface = loadArtifact('account/CofferdamAccount4337').abi;
  const accountInterface = new ethers.Interface(accountIface);
  const callData = accountInterface.encodeFunctionData('execute', [toAddr, amount, '0x']);
  const nonce = await ep.getNonce(accountAddr, 0);

  const feeData = await provider.getFeeData();
  const maxFeePerGas = feeData.maxFeePerGas || ethers.parseUnits('1', 'gwei');
  const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas || ethers.parseUnits('0.5', 'gwei');

  const verificationGasLimit = 500000n;
  const callGasLimit = 200000n;
  const preVerificationGas = 100000n;

  const accountGasLimits = pack128(verificationGasLimit, callGasLimit);
  const gasFees = pack128(maxPriorityFeePerGas, maxFeePerGas);

  const userOp = {
    sender: accountAddr,
    nonce,
    initCode: '0x',
    callData,
    accountGasLimits,
    preVerificationGas,
    gasFees,
    paymasterAndData: '0x',
    signature: '0x',
  };

  const userOpHash = await ep.getUserOpHash(userOp);

  const authorityId = 0n;
  const signingKey = new ethers.SigningKey(signingWallet.privateKey);
  const bound = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32'], [accountAddr, userOpHash])
  );
  const ethHash = ethers.hashMessage(ethers.getBytes(bound));
  const sig = signingKey.sign(ethHash);
  const userSig = ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);
  const signature = ethers.solidityPacked(['uint256', 'bytes'], [authorityId, userSig]);

  const signedUserOp = { ...userOp, signature };

  printKV('Recipient', fmtAddr(toAddr));
  printKV('Amount', `${ethers.formatEther(amount)} ETH`);

  const ok = await confirm({ message: 'Submit this UserOp?' });
  if (!ok) return;

  const tx = await ep.handleOps([signedUserOp], signer.address, { gasLimit: 5000000n });
  const receipt = await tx.wait();
  printKV('Status', receipt!.status === 1 ? '✓ Success' : '✗ Failed');
  printKV('Tx', tx.hash);
}

function pack128(hi: bigint, lo: bigint): string {
  const combined = (hi << 128n) | lo;
  return ethers.zeroPadValue(ethers.toBeArray(combined), 32);
}

async function pickAccount(config: ReturnType<typeof loadConfig>): Promise<string | null> {
  const entries = Object.entries(config.accounts);
  if (entries.length === 0) {
    console.log('  No accounts saved. Deploy one first.');
    return null;
  }
  const choice = await select({
    message: 'Select account:',
    choices: entries.map(([label, addr]) => ({
      name: `${label} — ${fmtAddr(addr)}`,
      value: addr,
    })),
  });
  return choice;
}
