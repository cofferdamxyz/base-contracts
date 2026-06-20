import { ethers } from 'ethers';

export interface PrefundedWallet {
  label: string;
  address: string;
  privateKey: string;
}

const HARDFHAT_MNEMONIC = 'test test test test test test test test test test test junk';
const HARDFHAT_PATH = "m/44'/60'/0'/0";
const WALLET_COUNT = 10;

export const HARDFHAT_DEFAULT_WALLETS: PrefundedWallet[] = Array.from(
  { length: WALLET_COUNT },
  (_, i) => {
    const w = ethers.HDNodeWallet.fromMnemonic(
      ethers.Mnemonic.fromPhrase(HARDFHAT_MNEMONIC),
      `${HARDFHAT_PATH}/${i}`
    );
    return {
      label: `Account #${i}${i === 0 ? ' (deployer)' : ''}`,
      address: w.address,
      privateKey: w.privateKey,
    };
  }
);

export function getWallets(): PrefundedWallet[] {
  return HARDFHAT_DEFAULT_WALLETS;
}

export function getWallet(index: number): PrefundedWallet {
  return HARDFHAT_DEFAULT_WALLETS[index];
}

export function createSigner(wallet: PrefundedWallet, rpcUrl: string): ethers.Wallet {
  return new ethers.Wallet(wallet.privateKey, new ethers.JsonRpcProvider(rpcUrl));
}

export function shortenAddr(addr: string): string {
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}
