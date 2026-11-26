import { ethers } from 'hardhat';
import type { TypedDataDomain, TypedDataField } from 'ethers';

/**
 * The ceremony attestation as EIP-712 typed data (decision 0090 item 5), as
 * `CofferdamAccount4337.ceremonyHash` hashes it. The SDK's
 * `identity/ceremony.ts` is the source; `test/fixtures/ceremonyTypes.json`
 * pins it here.
 */
export const CEREMONY_DOMAIN_NAME = 'Cofferdam Ceremony';
export const CEREMONY_DOMAIN_VERSION = '1';

export const CEREMONY_TYPES: Record<string, TypedDataField[]> = {
  CeremonyAttestation: [
    { name: 'account', type: 'address' },
    { name: 'action', type: 'bytes32' },
    { name: 'newKeyHash', type: 'bytes32' },
    { name: 'partnerId', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'notBefore', type: 'uint48' },
    { name: 'expiry', type: 'uint48' },
  ],
};

export interface CeremonyMessage {
  account: string;
  action: string;
  newKeyHash: string;
  partnerId: string;
  nonce: bigint;
  notBefore: bigint;
  expiry: bigint;
}

export function ceremonyDomain(chainId: bigint, registry: string): TypedDataDomain {
  return { name: CEREMONY_DOMAIN_NAME, version: CEREMONY_DOMAIN_VERSION, chainId, verifyingContract: registry };
}

export function ceremonyDigest(domain: TypedDataDomain, message: CeremonyMessage): string {
  return ethers.TypedDataEncoder.hash(domain, CEREMONY_TYPES, message);
}

/** Sign the typed attestation as a wallet's `eth_signTypedData_v4` would. */
export function signCeremony(
  signer: { signTypedData: (d: TypedDataDomain, t: Record<string, TypedDataField[]>, v: Record<string, unknown>) => Promise<string> },
  domain: TypedDataDomain,
  message: CeremonyMessage,
): Promise<string> {
  return signer.signTypedData(domain, CEREMONY_TYPES, message as unknown as Record<string, unknown>);
}

/** Today's account's domain for its registry, on the running chain. */
export async function domainOf(account: any): Promise<TypedDataDomain> {
  const { chainId } = await ethers.provider.getNetwork();
  return ceremonyDomain(chainId, await account.CEREMONY_ATTESTERS());
}
