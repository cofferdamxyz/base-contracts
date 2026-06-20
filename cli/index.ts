import 'dotenv/config';
import { select } from '@inquirer/prompts';
import { loadConfig } from './lib/config';
import { getWallets, PrefundedWallet } from './lib/wallets';
import { printHeader } from './lib/format';
import { deployMenu } from './menus/deploy';
import { accountMenu } from './menus/account';
import { selfMenu } from './menus/self';
import { infoMenu } from './menus/info';

const DEFAULT_RPC = 'http://127.0.0.1:8545';

async function main(): Promise<void> {
  console.log('\n  ╔══════════════════════════════════════════════╗');
  console.log('  ║  Cofferdam Base Contracts — Interactive CLI  ║');
  console.log('  ╚══════════════════════════════════════════════╝\n');

  const rpcUrl = process.env.RPC_URL || process.env.BASE_SEPOLIA_RPC_URL || DEFAULT_RPC;
  const config = loadConfig();

  const wallets = getWallets();
  const walletChoice = await select({
    message: 'Select wallet:',
    choices: wallets.map((w, i) => ({
      name: `${w.label} — ${w.address.slice(0, 6)}...${w.address.slice(-4)}`,
      value: i,
    })),
  });
  const wallet = wallets[walletChoice];

  while (true) {
    const baseChoices = [
      { name: '📋 Info — show deployment info & balances', value: 'info' },
      { name: '🚀 Deploy — deploy contracts', value: 'deploy' },
      { name: '👤 Account — deploy/manage CofferdamAccount4337', value: 'account' },
      { name: '🔐 Self.xyz — attester & nullifier management', value: 'self' },
    ];

    baseChoices.push({ name: '❌ Exit', value: 'exit' });

    const action = await select({
      message: '\nMain menu:',
      choices: baseChoices,
    });

    if (action === 'exit') {
      console.log('\n  Bye!\n');
      break;
    }

    try {
      switch (action) {
        case 'info':
          await infoMenu(rpcUrl, wallet);
          break;
        case 'deploy':
          await deployMenu(rpcUrl, wallet);
          break;
        case 'account':
          await accountMenu(rpcUrl, wallet);
          break;
        case 'self':
          await selfMenu(rpcUrl, wallet);
          break;
      }
    } catch (err: any) {
      if (err.message?.includes('ExitPromptError') || err.name === 'ExitPromptError') {
        console.log('\n  Bye!\n');
        break;
      }
      console.error('\n  ✗ Error:', err.message || err);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
