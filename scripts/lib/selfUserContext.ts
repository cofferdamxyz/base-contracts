/**
 * Self.xyz `userIdentifier` derivation, mirrored for Base.
 *
 * The `vc_and_disclose` circuit's `userIdentifier` public signal (index 20) is
 * NOT the user's address. Self derives it as a 160-bit commitment:
 *
 *   userContextData = abi.encodePacked(
 *     bytes32(destChainID),   // left-padded
 *     bytes32(userID),        // left-padded, hyphens stripped
 *     bytes(userDefinedData)  // raw UTF-8
 *   )
 *   userIdentifier = uint160(ripemd160(sha256(userContextData)))
 *
 * Ported from `calculateUserIdentifierHash` / `getSolidityPackedUserContextData`
 * in `self/common/src/utils/hash.ts`, and mirrored on-chain by
 * `NullifierRegistry._checkUserContext`.
 */
import { ethers } from 'ethers';

/**
 * `destChainID` declared in the app's `SelfApp` config. Self folds this into
 * the commitment, so the registry must be deployed with the same value.
 *
 * This is Self's destination-chain field, not the chain the registry lives on:
 * Cofferdam declares Celo (42220) while the registry is deployed on Base.
 * Must equal `SelfApp.chainID` in
 * `cofferdam-app/src/features/self/selfAppConfig.ts`.
 */
export const COFFERDAM_SELF_DEST_CHAIN_ID = 42220;

/** Mirrors `getSolidityPackedUserContextData`. */
export function buildUserContextData(
  destChainId: number | bigint,
  userId: string,
  userDefinedData = ''
): string {
  const userIdHex = userId.replace(/-/g, '');
  return ethers.solidityPacked(
    ['bytes32', 'bytes32', 'bytes'],
    [
      ethers.zeroPadValue(ethers.toBeHex(destChainId), 32),
      ethers.zeroPadValue(userIdHex.startsWith('0x') ? userIdHex : `0x${userIdHex}`, 32),
      ethers.toUtf8Bytes(userDefinedData),
    ]
  );
}

/** Mirrors `calculateUserIdentifierHash`. */
export function calculateUserIdentifierHash(
  destChainId: number | bigint,
  userId: string,
  userDefinedData = ''
): bigint {
  const contextData = buildUserContextData(destChainId, userId, userDefinedData);
  return BigInt(ethers.ripemd160(ethers.sha256(contextData)));
}
