import { artifacts, ethers, network } from 'hardhat';

const ACCOUNT = 'contracts/account/CofferdamAccount4337.sol:CofferdamAccount4337';
const NO_PERMISSION = { targets: [], selectors: [], codeHashes: [], codeSelectors: [], valueCap: 0n, expiry: 0n };

export type AccountCodeFingerprint = { codeHash: string; codeSize: number; maskOffsets: number[] };

/**
 * What `CofferdamPaymaster` checks a sender against: the runtime code of the
 * accounts `factory` deploys, with the per-account immutables zeroed.
 *
 * OpenZeppelin's EIP712 writes the account's own address and its domain
 * separator into the code, so two accounts of one factory differ in those
 * words only. This simulates the factory's creation code (`eth_call`, nothing
 * is deployed) from two different senders, so at two addresses, and masks the
 * immutable words (from the compiler's `immutableReferences`) that differ.
 * It throws when a differing byte lies outside an immutable, which means the
 * factory on chain was built from other sources than this checkout.
 *
 * `highModule` must be on the factory's module registry: the account
 * constructor installs it as the genesis authority.
 */
export async function accountCodeFingerprint(factoryAddr: string, highModule: string): Promise<AccountCodeFingerprint> {
  const factory = await ethers.getContractAt('CofferdamAccountFactory4337', factoryAddr);
  const Account = await ethers.getContractFactory('CofferdamAccount4337');
  const args = Account.interface.encodeDeploy([
    await factory.ENTRY_POINT(),
    await factory.MODULE_REGISTRY(),
    await factory.CEREMONY_ATTESTERS(),
    await factory.NULLIFIER_REGISTRY(),
    await factory.RECOVERY_DELAY(),
    await factory.PROBATION_PERIOD(),
    highModule,
    '0x',
    NO_PERMISSION,
  ]);
  const data = ethers.concat([await factory.accountCreationCode(), args]);
  const simulate = async (from: string) => ethers.getBytes(await ethers.provider.call({ from, data }));
  const a = await simulate('0x000000000000000000000000000000000000c0de');
  const b = await simulate('0x000000000000000000000000000000000000beef');
  if (a.length === 0 || a.length !== b.length) throw new Error('Account creation did not return runtime code');

  const buildInfo = await artifacts.getBuildInfo(ACCOUNT);
  if (!buildInfo) throw new Error(`No build info for ${ACCOUNT}: compile first`);
  const [file, name] = ACCOUNT.split(':');
  const refs = buildInfo.output.contracts[file][name].evm.deployedBytecode.immutableReferences ?? {};
  const words = Object.values(refs).flat() as Array<{ start: number; length: number }>;

  const differs = (start: number, length: number) => a.slice(start, start + length).some((x, i) => x !== b[start + i]);
  const maskOffsets = words.filter((w) => differs(w.start, w.length)).map((w) => w.start).sort((x, y) => x - y);
  // Exactly EIP712's `_cachedThis` and `_cachedDomainSeparator`. Another
  // immutable that tracks the deployer would be masked silently, so a new
  // count means the account changed and this derivation needs a look.
  if (maskOffsets.length !== 2) throw new Error(`Expected 2 per-account words, found ${maskOffsets.length}`);
  if (words.some((w) => maskOffsets.includes(w.start) && w.length !== 32)) throw new Error('Per-account immutable is not a 32-byte word');

  const mask = (code: Uint8Array) => {
    const out = Uint8Array.from(code);
    for (const o of maskOffsets) out.fill(0, o, o + 32);
    return out;
  };
  const maskedA = mask(a);
  const maskedB = mask(b);
  if (maskedA.some((x, i) => x !== maskedB[i])) {
    throw new Error('The factory account code differs outside its immutables: it was not built from this checkout');
  }
  return { codeHash: ethers.keccak256(maskedA), codeSize: a.length, maskOffsets };
}

/**
 * The relayer the paymaster sponsors: `RELAYER_ADDRESS`, required off the
 * local networks, where it defaults to the deployer. A local test that
 * self-bundles `handleOps` from another key sets `RELAYER_ADDRESS` to it.
 */
export function paymasterRelayer(deployer: string): string {
  const raw = process.env.RELAYER_ADDRESS?.trim();
  if (raw) return ethers.getAddress(raw);
  if (network.name === 'hardhat' || network.name === 'localhost') return deployer;
  throw new Error("RELAYER_ADDRESS (the plane's RELAYER_PRIVATE_KEY address) is required");
}

/** Base mainnet by name or by chain id. */
export function isBaseMainnet(): boolean {
  return network.name === 'base' || network.config.chainId === 8453;
}

/** The paymaster is a testnet contract: mainnet gas goes through the CDP Paymaster (decision 0017). */
export function refuseMainnetPaymaster(): void {
  if (isBaseMainnet()) {
    throw new Error('CofferdamPaymaster is testnet only: mainnet gas goes through the CDP Paymaster (decision 0017)');
  }
}
