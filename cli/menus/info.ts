import { ethers } from 'ethers';
import { loadConfig } from '../lib/config';
import { PrefundedWallet, createSigner, getWallets } from '../lib/wallets';
import { getContract } from '../lib/artifacts';
import { printHeader, printKV, fmtEth, fmtAddr } from '../lib/format';

export async function infoMenu(rpcUrl: string, wallet: PrefundedWallet): Promise<void> {
  const config = loadConfig();
  const signer = createSigner(wallet, rpcUrl);
  const provider = signer.provider!;

  printHeader('Deployment Info');

  const chainId = (await provider.getNetwork()).chainId;
  printKV('Network', `chainId=${chainId}`);
  printKV('RPC', rpcUrl);
  printKV('Active wallet', `${wallet.label} — ${fmtAddr(wallet.address)}`);

  const balance = await provider.getBalance(wallet.address);
  printKV('Wallet balance', fmtEth(balance));

  console.log('\n  Contracts:');
  printKV('EntryPoint v0.7', config.entryPoint);
  if (config.passkeyAuthority) printKV('PasskeyAuthority', config.passkeyAuthority);
  if (config.webAuthnPasskeyAuthority) printKV('WebAuthnPasskeyAuthority', config.webAuthnPasskeyAuthority);
  if (config.sessionKeyAuthorityUntrusted) printKV('SessionKeyAuth (untrusted)', config.sessionKeyAuthorityUntrusted);
  if (config.sessionKeyAuthorityManaged) printKV('SessionKeyAuth (managed)', config.sessionKeyAuthorityManaged);
  if (config.accountFactory) printKV('AccountFactory', config.accountFactory);
  if (config.paymaster) printKV('Paymaster', config.paymaster);
  if (config.selfAttesterRegistry) printKV('SelfAttesterRegistry', config.selfAttesterRegistry);
  if (config.mockGroth16Verifier) printKV('MockGroth16Verifier', config.mockGroth16Verifier);
  if (config.nullifierRegistry) printKV('NullifierRegistry', config.nullifierRegistry);

  const accountEntries = Object.entries(config.accounts);
  if (accountEntries.length > 0) {
    console.log('\n  Saved Accounts:');
    for (const [label, addr] of accountEntries) {
      const bal = await provider.getBalance(addr);
      printKV(label, `${fmtAddr(addr)} — ${fmtEth(bal)}`);
    }
  }

  console.log('\n  Available Wallets:');
  for (const w of getWallets()) {
    const bal = await provider.getBalance(w.address);
    printKV(w.label, `${fmtAddr(w.address)} — ${fmtEth(bal)}`);
  }
}
