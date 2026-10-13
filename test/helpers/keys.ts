import { ethers } from 'hardhat';
import { p256 } from '@noble/curves/p256';

// Tier enum values (contracts/interfaces/IAuthorityModule.sol)
export const TIER = { None: 0, LowUntrusted: 1, LowManaged: 2, High: 3, Partner: 4 } as const;

export const coder = ethers.AbiCoder.defaultAbiCoder();

export const PERMISSION_TYPE = 'tuple(address[] targets, bytes4[] selectors, uint256 valueCap, uint48 expiry)';

export type Permission = { targets: string[]; selectors: string[]; valueCap: bigint; expiry: bigint };

export const NO_PERMISSION: Permission = { targets: [], selectors: [], valueCap: 0n, expiry: 0n };

export function permission(
  calls: Array<[string, string]>,
  opts: { valueCap?: bigint; expiry?: bigint } = {},
): Permission {
  return {
    targets: calls.map(([t]) => t),
    selectors: calls.map(([, s]) => s),
    valueCap: opts.valueCap ?? 0n,
    expiry: opts.expiry ?? 0n,
  };
}

export function permissionHash(p: Permission): string {
  return ethers.keccak256(coder.encode([PERMISSION_TYPE], [p]));
}

/** A server-held bridge key, signing the way SessionKeyAuthority expects. */
export function sessionKey() {
  const wallet = ethers.Wallet.createRandom();
  const key = new ethers.SigningKey(wallet.privateKey);
  return {
    address: wallet.address,
    config: coder.encode(['address'], [wallet.address]),
    sign(account: string, digest: string): string {
      const bound = ethers.keccak256(coder.encode(['address', 'bytes32'], [account, digest]));
      const sig = key.sign(ethers.hashMessage(ethers.getBytes(bound)));
      return ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);
    },
  };
}

/** A raw P-256 key, signing the way PasskeyAuthority expects (test networks only). */
export function rawPasskey() {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false); // 0x04 || x || y
  return {
    config: coder.encode(['bytes32', 'bytes32'], [pub.slice(1, 33), pub.slice(33, 65)]),
    sign(digest: string): string {
      const sig = p256.sign(ethers.getBytes(digest), priv, { lowS: true }); // P256.verify rejects high s
      return ethers.concat([ethers.toBeHex(sig.r, 32), ethers.toBeHex(sig.s, 32)]);
    },
  };
}

export function rpIdHash(rpId: string): string {
  return ethers.sha256(ethers.toUtf8Bytes(rpId));
}

/**
 * A platform passkey on `rpId`, producing WebAuthn assertions the way
 * OpenZeppelin's WebAuthn library (and so WebAuthnPasskeyAuthority and
 * PartnerPasskeyAuthority) expects.
 */
export function webauthnKey(rpId = 'cofferdam.xyz') {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false);
  const qx = ethers.hexlify(pub.slice(1, 33));
  const qy = ethers.hexlify(pub.slice(33, 65));
  return {
    rpId,
    /** High config: abi.encode(qx, qy). */
    config: coder.encode(['bytes32', 'bytes32'], [qx, qy]),
    /** Partner config: abi.encode(qx, qy, rpIdHash, partnerId, partnerSigner). */
    partnerConfig(partnerId: string, partnerSigner: string): string {
      return coder.encode(
        ['bytes32', 'bytes32', 'bytes32', 'bytes32', 'address'],
        [qx, qy, rpIdHash(rpId), partnerId, partnerSigner],
      );
    },
    /** Assertion over `challenge` (32 bytes), as the authenticator would sign it. */
    sign(challenge: string, opts: { uv?: boolean; signedRpId?: string } = {}): string {
      const uv = opts.uv ?? true;
      const flags = uv ? 0x05 : 0x01; // UP (+ UV)
      const authenticatorData = ethers.concat([
        rpIdHash(opts.signedRpId ?? rpId),
        ethers.toBeHex(flags, 1),
        '0x00000001',
      ]);
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: Buffer.from(ethers.getBytes(challenge)).toString('base64url'),
        origin: `https://${opts.signedRpId ?? rpId}`,
        crossOrigin: false,
      });
      const message = ethers.sha256(
        ethers.concat([authenticatorData, ethers.sha256(ethers.toUtf8Bytes(clientDataJSON))]),
      );
      const sig = p256.sign(ethers.getBytes(message), priv, { lowS: true });
      return coder.encode(
        ['bytes32', 'bytes32', 'uint256', 'uint256', 'bytes', 'string'],
        [
          ethers.toBeHex(sig.r, 32),
          ethers.toBeHex(sig.s, 32),
          clientDataJSON.indexOf('"challenge"'),
          clientDataJSON.indexOf('"type"'),
          authenticatorData,
          clientDataJSON,
        ],
      );
    },
  };
}

export function packSig(authorityId: bigint | number, userSig: string): string {
  return ethers.solidityPacked(['uint256', 'bytes'], [authorityId, userSig]);
}

export function userOp(sender: string, callData: string, signature: string) {
  return {
    sender,
    nonce: 0n,
    initCode: '0x',
    callData,
    accountGasLimits: ethers.ZeroHash,
    preVerificationGas: 0n,
    gasFees: ethers.ZeroHash,
    paymasterAndData: '0x',
    signature,
  };
}
