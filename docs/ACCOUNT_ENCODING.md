# CofferdamAccount4337 — On-Chain Encoding Reference

> **Purpose**: A complete specification of the calldata, storage layout, event
> topics, and signature formats used by the Cofferdam ERC-4337 account system.
> This document is intended for security auditors, integrators, and developers
> building inspection/debugging tooling. It is the on-chain companion to
> `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` §2.5 (tiered-authority model).

## 1. Contract Inventory

| Contract | Source | Role |
|---|---|---|
| `CofferdamAccount4337` | `contracts/account/CofferdamAccount4337.sol` | ERC-4337 smart account; holds authorities, validates UserOps, executes calls |
| `CofferdamAccountFactory4337` | `contracts/account/CofferdamAccountFactory4337.sol` | CREATE2 factory for counterfactual deployment |
| `AuthorityManagerBase` | `contracts/account/AuthorityManagerBase.sol` | Abstract base: authority registry, ratchet, tier gating |
| `CofferdamPaymaster` | `contracts/account/CofferdamPaymaster.sol` | Stub verifying paymaster (dev/test only) |
| `WebAuthnPasskeyAuthority` | `contracts/auth/WebAuthnPasskeyAuthority.sol` | High-tier: verifies WebAuthn assertions (P-256/ES256) |
| `PasskeyAuthority` | `contracts/auth/PasskeyAuthority.sol` | High-tier: verifies raw P-256 signatures |
| `SessionKeyAuthority` | `contracts/auth/SessionKeyAuthority.sol` | Low-tier (LowUntrusted or LowManaged): verifies ECDSA session-signer signatures |

### 1.1 Canonical Addresses (Base Sepolia)

| Name | Address |
|---|---|
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| CofferdamAccountFactory4337 | `0x35CeBf87f5DAE7be7cf755067d30fC65Fa541F3D` |
| CofferdamPaymaster | `0x5ffb8bA851DCf7A592B85fc2567e72449214204e` |
| WebAuthnPasskeyAuthority | `0x279Cf7DF840a76EE9EcC1C177698E6EaB490Eea8` |
| PasskeyAuthority | `0x25338619e03e92511feB63cc66Dfd9CAFB5654E6` |
| SessionKeyAuthority (LowUntrusted) | `0xc76337F62D298831deEeE8f4063567884680A14b` |
| SessionKeyAuthority (LowManaged) | `0x4780DEc3E132E835C36895BFBbb71Bb63C638e54` |

## 2. Factory Calldata — `deployAccount` / `getAddress`

### 2.1 Function Signature

```solidity
function deployAccount(
    IAuthorityModule initialModule,
    bytes memory initialConfig,
    bytes32 salt
) public returns (CofferdamAccount4337)
```

**Selector**: `0x98408a26` (keccak256("deployAccount(address,bytes,bytes32)")[:4])

### 2.2 Calldata Layout

```
┌──────────────────────────────────────────────────────────────────┐
│ 4 bytes    │ selector           │ 0x98408a26                      │
├──────────────────────────────────────────────────────────────────┤
│ 32 bytes   │ initialModule      │ address (left-padded to 32)     │
├──────────────────────────────────────────────────────────────────┤
│ offset ptr │ initialConfig ptr  │ pointer to dynamic bytes data   │
├──────────────────────────────────────────────────────────────────┤
│ 32 bytes   │ salt               │ bytes32                         │
├──────────────────────────────────────────────────────────────────┤
│ 32 bytes   │ config length      │ uint256 (byte length)           │
├──────────────────────────────────────────────────────────────────┤
│ N bytes    │ config data        │ abi-encoded config blob         │
└──────────────────────────────────────────────────────────────────┘
```

### 2.3 CREATE2 Address Computation

```
address = keccak256(0xff, factory, salt, keccak256(initCode))[12:]

where initCode = abi.encodePacked(
    type(CofferdamAccount4337).creationCode,
    abi.encode(ENTRY_POINT, initialModule, initialConfig)
)
```

The same `(initialModule, initialConfig, salt)` always produces the same
address. This enables gas-sponsored deployment before the user has any
on-chain presence.

### 2.4 `getAddress` (view-only counterfactual check)

Same selector pattern but function `getAddress(address,bytes,bytes32)` →
selector `0xb8f13896`. Returns the computed address without deploying.

## 3. Account Storage Layout

`CofferdamAccount4337` inherits `AuthorityManagerBase`. Storage is laid out
sequentially from slot 0.

### 3.1 Slot Map

| Slot | Variable | Type | Notes |
|---|---|---|---|
| 0 | `_authorities` mapping base | `mapping(uint256 => Authority)` | Solidity mapping — no direct slot value; entries at `keccak256(key . slot)` |
| 1 | `authorityCount` | `uint256` | Total authorities ever added (does not decrement on revoke) |
| 2 | `passkeyCount` | `uint8` (packed) | Active High-tier count; decremented on revoke |
| 2 | `upgradeLocked` | `bool` (packed) | Packed in same slot as `passkeyCount`; `passkeyCount` in low byte, `upgradeLocked` in next byte |
| 3+ | (unused) | — | Reserved for future storage |

### 3.2 Packed Slot 2 Encoding

```
Slot 2: 0x...0000 0b01
                   ^^
                   │ └─ passkeyCount (uint8): 1
                   └─── upgradeLocked (bool): true

Example: 0x0000000000000000000000000000000000000000000000000000000000000101
         passkeyCount = 1, upgradeLocked = true
```

### 3.3 Authority Mapping Storage

Each `Authority` struct occupies a mapping slot computed as:

```
authoritySlot = keccak256(abi.encode(authorityId, 0))
```

The `Authority` struct layout within that slot:

```
┌─────────────────────────────────────────────────────────────────┐
│ Offset │ Field   │ Type    │ Size  │ Description                 │
├─────────────────────────────────────────────────────────────────┤
│ 0      │ module  │ address │ 20 B  │ IAuthorityModule contract   │
│ 20     │ tier    │ uint8   │ 1 B   │ Tier enum (0-3)             │
│ 21     │ active  │ bool    │ 1 B   │ Active flag                 │
│ 32     │ config  │ bytes   │ dyn.  │ Offset to dynamic config    │
└─────────────────────────────────────────────────────────────────┘
```

The dynamic `config` bytes are stored at:
```
configDataSlot = keccak256(abi.encode(authoritySlot, 2))
```
(Standard Solidity storage layout for dynamic bytes in a struct.)

### 3.4 Tier Enum Values

| Value | Name | Meaning |
|---|---|---|
| 0 | `None` | Unset / invalid |
| 1 | `LowUntrusted` | Leakable credential (password, OAuth). Ratchet-locked after passkey enrolment. |
| 2 | `LowManaged` | IdP-brokered (Polis SSO). NOT ratchet-locked; coexists with passkey. |
| 3 | `High` | Hardware passkey (P-256, Secure Enclave/StrongBox). Full control. |

## 4. Authority Config Encoding

The `config` blob is module-specific opaque bytes. Each module defines its
own encoding:

### 4.1 WebAuthnPasskeyAuthority / PasskeyAuthority

```
config = abi.encode(bytes32 qx, bytes32 qy)
```

- **Length**: 64 bytes (padded)
- `qx`: X coordinate of the P-256 public key
- `qy`: Y coordinate of the P-256 public key
- The key is non-exportable hardware material (iOS Secure Enclave / Android StrongBox)

### 4.2 SessionKeyAuthority

```
config = abi.encode(address sessionSigner)
```

- **Length**: 32 bytes (padded)
- `sessionSigner`: Server-held ECDSA (secp256k1) key address
- The consumer server signs the userOpHash with this key after authenticating
  the user through legacy flows (password, OAuth, OIDC)

## 5. Signature Formats

### 5.1 ERC-4337 `validateUserOp` Signature

The `userOp.signature` field is decoded by the account as:

```
signature = abi.encodePacked(uint256 authorityId, bytes userSignature)
```

- **First 32 bytes**: `authorityId` (selects which authority to use)
- **Remaining bytes**: `userSignature` (passed to the module's
  `isValidSignature`)

The account extracts these via inline assembly (`calldataload`), not ABI
decode, for gas efficiency.

### 5.2 WebAuthnPasskeyAuthority Signature

```
userSignature = abi.encode(WebAuthn.WebAuthnAuth)
```

Where `WebAuthnAuth` is:

```solidity
struct WebAuthnAuth {
    bytes32 r;           // P-256 signature r
    bytes32 s;           // P-256 signature s
    uint256 challengeIndex;  // Position of challenge in clientDataJSON
    uint256 typeIndex;       // Position of type in clientDataJSON
    bytes authenticatorData; // WebAuthn authenticator data (37+ bytes)
    string clientDataJSON;   // WebAuthn client data JSON
}
```

The WebAuthn **challenge** must be the raw 32 bytes of the `digest`
(the userOpHash). The module Base64URL-encodes it and matches it against
`clientDataJSON`. User-Verified (UV) flag is always required.

### 5.3 PasskeyAuthority Signature

```
userSignature = r (32 bytes) || s (32 bytes)
```

- **Length**: exactly 64 bytes
- Raw P-256 signature over the 32-byte `digest` (no WebAuthn envelope)

### 5.4 SessionKeyAuthority Signature

```
userSignature = r (32 bytes) || s (32 bytes) || v (1 byte)
```

- **Length**: exactly 65 bytes
- ECDSA signature over EIP-191 personal_sign of `keccak256(account, digest)`
- `v` must be 27 or 28; `s` must be ≤ secp256k1 half-order (EIP-2)

### 5.5 ERC-1271 `isValidSignature`

Same encoding as §5.1 — `abi.encodePacked(uint256 authorityId, bytes userSig)`.
Returns `0x1626ba7e` (magic value) on success, `0xffffffff` on failure.

### 5.6 ERC-6492 Counterfactual Signature

Before deployment, signatures are wrapped:

```
abi.encodePacked(
    0x6492649264926492649264926492649264926492,  // magicBytes (20 bytes)
    address(factory),                              // CofferdamAccountFactory4337
    bytes(factoryCallData),                        // initCode for deployAccount
    bytes(erc1271Signature)                        // this account's signature format
)
```

The verifying party detects the wrapper, deploys the account if needed, then
calls `isValidSignature`. See [EIP-6492](https://eips.ethereum.org/EIPS/eip-6492).

## 6. Events

### 6.1 `AccountDeployed` (Factory)

```solidity
event AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt);
```

- **Topic 0**: `keccak256("AccountDeployed(address,address,bytes32)")`
  = `0xf0acda094aefca0f382f1150baa03e8c050833d76fb46857830a24f2c5abcdcb`
- **Topic 1**: `account` (indexed)
- **Topic 2**: `initialModule` (indexed)
- **Data**: `salt` (bytes32)

### 6.2 `AuthorityAdded` (Account)

```solidity
event AuthorityAdded(uint256 indexed authorityId, address indexed module, Tier tier, bytes32 kind);
```

- **Topic 0**: `keccak256("AuthorityAdded(uint256,address,uint8,bytes32)")`
  = `0x39a9287670c352474ebcf1c78b9dd1c455d0ef9d157c330a0730b61aa8c4c6a2`
- **Topic 1**: `authorityId` (indexed)
- **Topic 2**: `module` (indexed)
- **Topic 3**: `tier` (indexed, uint8)
- **Data**: `kind` (bytes32)

### 6.3 `AuthorityRevoked` (Account)

```solidity
event AuthorityRevoked(uint256 indexed authorityId);
```

- **Topic 0**: `keccak256("AuthorityRevoked(uint256)")`
- **Topic 1**: `authorityId` (indexed)

### 6.4 `FirstPasskeyEnrolled` (Account)

```solidity
event FirstPasskeyEnrolled(uint256 indexed lowAuthorityId, uint256 indexed passkeyAuthorityId);
```

- **Topic 0**: `keccak256("FirstPasskeyEnrolled(uint256,uint256)")`
- **Topic 1**: `lowAuthorityId` (indexed)
- **Topic 2**: `passkeyAuthorityId` (indexed)

### 6.5 `RatchetFired` (Account)

```solidity
event RatchetFired();
```

- **Topic 0**: `keccak256("RatchetFired()")`

## 7. Kind Hashes

Each `IAuthorityModule` exposes a `kind()` pure view returning a `bytes32`
identifier. Known values:

| Kind String | keccak256 Hash | Module(s) |
|---|---|---|
| `"passkey"` | `0xf8be3eb0...` | `PasskeyAuthority`, `WebAuthnPasskeyAuthority` |
| `"session"` | `0x...` | `SessionKeyAuthority` (LowUntrusted) |
| `"polis_sso"` | `0x...` | `SessionKeyAuthority` (LowManaged) |

Compute: `keccak256(abi.encodePacked(kindString))` or `ethers.id(kindString)`.

## 8. Key Function Selectors

| Function | Selector |
|---|---|
| `deployAccount(address,bytes,bytes32)` | `0x98408a26` |
| `getAddress(address,bytes,bytes32)` | `0xb8f13896` |
| `ENTRY_POINT()` | `0x94430fa5` |
| `validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes),bytes32,uint256)` | ERC-4337 IAccount standard |
| `execute(address,uint256,bytes)` | `0x9d2e8e15` |
| `executeBatch(address[],uint256[],bytes[])` | `0x7e3e5a9a` |
| `getAuthority(uint256)` | `0x75904d3f` |
| `addAuthority(uint256,address,bytes)` | `0x5b1e1e8e` |
| `revokeAuthority(uint256,uint256)` | `0x34f2247f` |
| `enrollFirstPasskey(uint256,address,bytes)` | `0x606558a3` |
| `isValidSignature(bytes32,bytes)` | `0x1626ba7e` (ERC-1271) |

## 9. EntryPoint Interaction

### 9.1 Validation Flow

```
Bundler → EntryPoint.handleOps([userOp], beneficiary)
  → EntryPoint calls account.validateUserOp(userOp, userOpHash, missingFunds)
    → Account decodes authorityId from signature[0:32]
    → Account calls _authenticate(authorityId, userOpHash, signature[32:])
      → Module.isValidSignature(account, userOpHash, config, userSig)
    → Account returns validationData (0 = success)
  → EntryPoint calls account.execute(target, value, data) [if validation passed]
```

### 9.2 Gas Payment

- **With paymaster**: The paymaster's `validatePaymasterUserOp` sponsors the
  UserOp. The paymaster must have sufficient ETH deposited to the EntryPoint.
- **Without paymaster**: The account must have ETH deposited to the
  EntryPoint via `EntryPoint.depositTo{value: amount}(accountAddress)`.
- **Direct deploy**: The deployer EOA pays gas for the factory
  `deployAccount` call directly (not via ERC-4337).

## 10. Security Invariants

These invariants are enforced on-chain and should be verified during audits:

1. **EntryPoint-only execution**: `execute`, `executeBatch`, `validateUserOp`
   require `msg.sender == ENTRY_POINT`. No EOA can call these directly.

2. **One-way ratchet**: Once `upgradeLocked == true`, no `LowUntrusted`
   authority can ever be re-activated or added. The ratchet fires on:
   - Genesis with a High-tier authority (passkey-first onboarding)
   - `enrollFirstPasskey` call (legacy-first → passkey upgrade)

3. **Passkey cap**: `passkeyCount <= MAX_PASSKEYS (3)`. The 4th passkey
   addition reverts with `PasskeyCapReached()`.

4. **Tier gating**: `LowUntrusted` may ONLY call `enrollFirstPasskey` (zero
   value). All other management/execution requires `High` or `LowManaged`.

5. **Signature binding**: Each operation type has a unique domain-separation
   tag (`TAG_EXECUTE`, `TAG_ADD_AUTHORITY`, etc.) preventing cross-operation
   signature replay.

6. **CREATE2 idempotency**: `deployAccount` is a no-op if the account already
   exists at the computed address (`extcodesize > 0`).

## 11. Inspector Tool

A Hardhat script for reading on-chain account state is provided at
`scripts/inspect-account.ts`.

### 11.1 Usage

```bash
# Inspect an account on Base Sepolia
ACCOUNT=0xABf27176feCB5f1Be3acB40c235D26fEea504E98 yarn inspect:account --network baseSepolia

# Inspect with deployment transaction analysis
ACCOUNT=0xABf27176feCB5f1Be3acB40c235D26fEea504E98 \
TX=0x7afa2ffdc46ad223b30382342398314b3e08fe2187d324d93865da23d84e176f \
yarn inspect:account --network baseSepolia

# On local anvil fork
ACCOUNT=0xABf27176feCB5f1Be3acB40c235D26fEea504E98 yarn inspect:account --network localhost
```

### 11.2 Output

The inspector prints:
- **Basic**: deployment status, balance, nonce, code size
- **Account config**: EntryPoint address (with correctness check), authority
  count, passkey count, ratchet status
- **Authorities**: per-authority module address, tier, kind, active status,
  decoded config (P-256 pubkey or session signer)
- **Security summary**: active passkey/low-tier counts, ratchet state,
  anomaly warnings
- **Deployment tx** (if `--tx` provided): block, gas, status, decoded events
  (AccountDeployed, AuthorityAdded)
- **Interpretation**: human-readable assessment of the account's onboarding
  path and security posture

## 12. Audit References

- **Shannon** (planned): https://github.com/KeygraphHQ/shannon
- **OpenZeppelin WebAuthn**: `@openzeppelin/contracts/utils/cryptography/WebAuthn.sol`
- **OpenZeppelin P256**: `@openzeppelin/contracts/utils/cryptography/P256.sol`
- **ERC-4337 v0.7**: EntryPoint at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- **EIP-6492**: Counterfactual contract signatures
- **EIP-1271**: Contract signature validation
- **EIP-2**: Signature malleability guard (SessionKeyAuthority)
- **RIP-7212**: P-256 precompile at `0x100` (Base Fjord/Azul)
