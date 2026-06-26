import * as fs from 'fs';
import * as path from 'path';

export interface DeploymentConfig {
  entryPoint: string;
  passkeyAuthority?: string;
  webAuthnPasskeyAuthority?: string;
  sessionKeyAuthorityUntrusted?: string;
  sessionKeyAuthorityManaged?: string;
  accountFactory?: string;
  paymaster?: string;
  selfAttesterRegistry?: string;
  mockGroth16Verifier?: string;
  nullifierRegistry?: string;
  companyRegistry?: string;
  corporateRegistry?: string;
  escrowFactory?: string;
  usdcAddress?: string;
  accounts: Record<string, string>;
  companies?: Record<string, string>;
}

const CONFIG_PATH = path.join(__dirname, '..', '..', '.cofferdam-cli.json');

export const DEFAULT_ENTRYPOINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

export function loadConfig(): DeploymentConfig {
  if (fs.existsSync(CONFIG_PATH)) {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    return JSON.parse(raw);
  }
  return { entryPoint: DEFAULT_ENTRYPOINT, accounts: {} } as DeploymentConfig;
}

export function saveConfig(config: DeploymentConfig): void {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export function updateConfig(partial: Partial<DeploymentConfig>): DeploymentConfig {
  const config = loadConfig();
  const updated = {
    ...config,
    ...partial,
    accounts: { ...config.accounts, ...(partial.accounts || {}) },
  };
  saveConfig(updated);
  return updated;
}
