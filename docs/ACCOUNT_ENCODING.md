# CofferdamAccount4337 — On-Chain Encoding Reference

> **Purpose**: A complete specification of the calldata, storage layout, event
> topics, and signature formats used by the Cofferdam ERC-4337 account system.
> This document is intended for security auditors, integrators, and developers
> building inspection/debugging tooling. It is the on-chain companion to
> `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` §2.5 (tiered-authority model) and
> decisions 0015 and 0016 in the `cofferdam` repository.

## 1. Contract Inventory

| Contract | Source | Role |
|---|---|---|
| `CofferdamAccount4337` | `contracts/account/CofferdamAccount4337.sol` | ERC-4337 smart account; holds authorities and permissions, validates UserOps, executes calls |
| `CofferdamAccountFactory4337` | `contracts/account/CofferdamAccountFactory4337.sol` | CREATE2 factory; pins the EntryPoint and both registries into every account |
| `AuthorityManagerBase` | `contracts/account/AuthorityManagerBase.sol` | Abstract base: authority registry, permissions, passkey cap, last-High guard |
| `CofferdamModuleRegistry` | `contracts/registry/CofferdamModuleRegistry.sol` | Allowlist of authority modules an account may install (owner: Cofferdam Safe) |
| `CofferdamCeremonyAttesterRegistry` | `contracts/registry/CofferdamCeremonyAttesterRegistry.sol` | Keys that co-sign first-High enrolment and Partner recovery (a `SelfAttesterRegistry`) |
| `CofferdamPaymaster` | `contracts/account/CofferdamPaymaster.sol` | Verifying paymaster (decision 0014) |
| `WebAuthnPasskeyAuthority` | `contracts/auth/WebAuthnPasskeyAuthority.sol` | High: WebAuthn assertion, `rpIdHash == sha256("cofferdam.xyz")`, UV required |
| `PartnerPasskeyAuthority` | `contracts/auth/PartnerPasskeyAuthority.sol` | Partner: WebAuthn assertion on the partner's RP (rpIdHash in config), UV required |
| `SessionKeyAuthority` | `contracts/auth/SessionKeyAuthority.sol` | Managed (`LowManaged`): employer bridge ECDSA key |
| `PasskeyAuthority` | `contracts/auth/PasskeyAuthority.sol` | High: raw P-256, no RP binding. Test networks only; never listed in the mainnet registry |

### 1.1 Canonical Addresses (Base Sepolia)

Deployed 2026-10-14 with `scripts/deploy-auth.ts` (decision 0016 account
layer) from the CofferdamDev deployer, which owns both registries and the
paymaster on testnet. `CofferdamCeremonyAttesterRegistry` has no attester
yet, so first-High upgrades and Partner recoveries are paused until one is
added. Source of truth: `deployments/baseSepolia.json`.

| Name | Address |
|---|---|
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| CofferdamAccountFactory4337 | `0xC0F4EEd3EF9a17382Dac877468a8fA0Cc397bF3E` |
| CofferdamModuleRegistry | `0x2C974835449AF2E5bFA76eeE151a2222Ce0f3eD1` |
| CofferdamCeremonyAttesterRegistry | `0x28824840A8f5a764E797578291FD4377Ca13126b` |
| CofferdamPaymaster | `0xa24651292DFd346A4da0298583b114543771d867` |
| WebAuthnPasskeyAuthority (High, pinned to `cofferdam.xyz`) | `0xB20d91Cc70cDDbccF57fA9CA9C16FDb01978A471` |
| PartnerPasskeyAuthority (Partner) | `0x41c9bCaB8D074FdC364455479E31496cb689a349` |
| SessionKeyAuthority (Managed) | `0xD468774BDE3E2a1705b51791424432abD01CbaCE` |
| PasskeyAuthority (raw P-256, testnet only) | `0xebe2d02a07859a50Ae9f3f54B9F327aeD0EB6F93` |

The pre-0016 deployment (factory `0x35CeBf87…1F3D`, WebAuthn authority
`0x279Cf7DF…Eea8`, paymasters `0x5ffb8bA8…204e` and `0xe73fec9b…0aF`) is
retired; accounts created through it are orphaned and are not migrated.

## 2. Factory Calldata — `deployAccount` / `getAddress`

### 2.1 Function Signature

```solidity
struct Permission {
    address[] targets;       // targets[i] may be called with selectors[i]
    bytes4[]  selectors;
    bytes32[] codeHashes;    // any contract whose code hash is codeHashes[i] may be called with codeSelectors[i]
    bytes4[]  codeSelectors;
    uint256   valueCap;  // max ETH per call; 0 for Partner and for any grant made without High
    uint48    expiry;    // returned as validUntil; 0 = none (Managed only)
}

function deployAccount(
    IAuthorityModule initialModule,
    bytes memory initialConfig,
    Permission memory initialPermission,
    bytes32 salt
) public returns (CofferdamAccount4337)
```

**Selector**: `0xbcb51ab1` (`deployAccount(address,bytes,(address[],bytes4[],bytes32[],bytes4[],uint256,uint48),bytes32)`)

`initialPermission` must be empty (all four arrays `[]`, `valueCap = 0`,
`expiry = 0`) for a High genesis and non-empty for a Partner or Managed
genesis (§10.5).

### 2.2 Calldata Layout

Standard ABI encoding: four head words (`initialModule`, offset of
`initialConfig`, offset of `initialPermission`, `salt`), then the config bytes,
then the permission tuple (two array offsets, `valueCap`, `expiry`, then each
array's length and elements).

### 2.3 CREATE2 Address Computation

```
address = keccak256(0xff, factory, salt, keccak256(initCode))[12:]

where initCode = abi.encodePacked(
    type(CofferdamAccount4337).creationCode,
    abi.encode(ENTRY_POINT, MODULE_REGISTRY, CEREMONY_ATTESTERS,
               initialModule, initialConfig, initialPermission)
)
```

The same `(initialModule, initialConfig, initialPermission, salt)` always
produces the same address for a given factory. The registries are factory
immutables, so a factory with other registries yields other addresses. Because
the permission is part of the address, a deployer cannot swap a wider grant
into a counterfactual address the user has already seen.

### 2.4 `getAddress` (view-only counterfactual check)

`getAddress(address,bytes,(address[],bytes4[],bytes32[],bytes4[],uint256,uint48),bytes32)` →
selector `0xa8ace465`. Returns the computed address without deploying.

## 3. Account Storage Layout

`CofferdamAccount4337` inherits `AuthorityManagerBase, EIP712`. Storage is laid
out sequentially from slot 0. `ENTRY_POINT`, `MODULE_REGISTRY` and
`CEREMONY_ATTESTERS` are immutables (in code, not storage).

### 3.1 Slot Map

| Slot | Variable | Type | Notes |
|---|---|---|---|
| 0 | `_authorities` | `mapping(uint256 => Authority)` | Entries at `keccak256(abi.encode(id, 0))` |
| 1 | `authorityCount` | `uint256` | Authorities ever added (does not decrement on revoke) |
| 2 | `passkeyCount` | `uint8` (low byte) | Active High-tier count |
| 2 | `upgradeLocked` | `bool` (next byte) | True once a High authority has existed |
| 3 | `_permissions` | `mapping(uint256 => Permission)` | Entries at `keccak256(abi.encode(id, 3))` |
| 4 | `_nameFallback` | `string` | OpenZeppelin `EIP712` (unused: name fits a ShortString) |
| 5 | `_versionFallback` | `string` | OpenZeppelin `EIP712` (unused) |
| 6 | `ceremonyNonce` | `uint256` | Ceremony co-signs spent (§5.7) |

### 3.2 Packed Slot 2 Encoding

```
Example: 0x0000000000000000000000000000000000000000000000000000000000000101
         passkeyCount = 1 (byte 0), upgradeLocked = true (byte 1)
```

### 3.3 Authority Mapping Storage

```
authoritySlot = keccak256(abi.encode(authorityId, 0))

authoritySlot + 0: module (bytes 0-19) | tier (byte 20) | active (byte 21)
authoritySlot + 1: config (dynamic bytes; long data at keccak256(authoritySlot + 1))
```

### 3.4 Permission Mapping Storage

```
permissionSlot = keccak256(abi.encode(authorityId, 3))

permissionSlot + 0: targets.length   (elements at keccak256(permissionSlot + 0))
permissionSlot + 1: selectors.length (elements packed 8 per slot at keccak256(permissionSlot + 1))
permissionSlot + 2: codeHashes.length (elements at keccak256(permissionSlot + 2))
permissionSlot + 3: codeSelectors.length (elements packed 8 per slot at keccak256(permissionSlot + 3))
permissionSlot + 4: valueCap
permissionSlot + 5: expiry (uint48)
```

A code-hash entry is for contracts deployed per job, such as a
`CofferdamSpotEscrow` from the `EscrowFactory`, whose address does not exist
when the grant is made. The account reads the target's `EXTCODEHASH` only when
no address entry matches (ERC-7562 allows it for a deployed contract). Every
`CofferdamSpotEscrow` with the same USDC and the same `selfWitnessed` flag
has the same code hash, so a B2B witness grant names one hash and a consumer
one another; the escrow's own role checks (`msg.sender == witness`) still
decide who may act on a given job. Never name a proxy's code hash: every proxy
of that shape shares it whatever it points to.

Read it with `getPermission(authorityId)`. High authorities have an empty
permission. A Partner recovery (§5.8) copies the old authority's permission to
the new id.

### 3.5 Tier Enum Values

| Value | Name | Meaning |
|---|---|---|
| 0 | `None` | Unset / invalid |
| 1 | `LowUntrusted` | Retired (decision 0016). No module of this tier can be installed. Kept so the numbering does not move. |
| 2 | `LowManaged` | Employer IdP bridge (Polis SSO), server-held key. Scoped by a `Permission`; coexists with High. |
| 3 | `High` | `cofferdam.xyz` passkey (P-256, UV), only on Cofferdam surfaces. Full control. |
| 4 | `Partner` | The user's passkey on a partner app's RP. Scoped by a `Permission`, zero value. |

The account records the module's `tier()` when the authority is added and
never asks the module again.

## 4. Authority Config Encoding

The `config` blob is module-specific opaque bytes:

### 4.1 WebAuthnPasskeyAuthority / PasskeyAuthority

```
config = abi.encode(bytes32 qx, bytes32 qy)        // 64 bytes
```

`qx`, `qy`: the P-256 public key. The RP is not in the config:
`WebAuthnPasskeyAuthority` accepts only `rpIdHash == sha256("cofferdam.xyz")`
(`0x93c1df9b80c22525d5c6a23dd4ee07f3d0accfbc2634c4d97c9c7587653764e2`,
`COFFERDAM_RP_ID_HASH`).

### 4.2 PartnerPasskeyAuthority

```
config = abi.encode(
    bytes32 qx, bytes32 qy,      // the partner-RP passkey's public key
    bytes32 rpIdHash,            // sha256 of the partner's RP ID
    bytes32 partnerId,           // the partner, as named in ceremony co-signs
    address partnerSigner        // the partner backend key that vouches for recoveries
)                                // exactly 160 bytes (CONFIG_LENGTH)
```

`decodeConfig(config)` on the module returns the five fields.

### 4.3 SessionKeyAuthority

```
config = abi.encode(address sessionSigner)          // 32 bytes
```

`sessionSigner`: the employer bridge's ECDSA (secp256k1) key. The module is
`LowManaged` only; a consumer-server key is never an account authority.

## 5. Signature Formats

### 5.1 ERC-4337 `validateUserOp` Signature

```
signature = abi.encodePacked(uint256 authorityId, bytes userSignature)
```

- **First 32 bytes**: `authorityId`; `RECOVERY_AUTHORITY_ID`
  (`type(uint256).max`) selects the Partner recovery format (§5.8).
- **Remaining bytes**: `userSignature`, passed to the module's
  `isValidSignature`.

Return values:

| Case | Result |
|---|---|
| Unknown or inactive authority, call the tier may not make | revert |
| Module rejects the signature | `1` (`SIG_VALIDATION_FAILED`) |
| High, accepted | `0` |
| Partner / Managed, accepted | `uint256(permission.expiry) << 160` (`validUntil`; 0 = none) |
| `enrollFirstHigh` by its own signer, accepted | `0` (not bound by the grant's expiry, so an expired partner grant never strands funds) |

### 5.2 WebAuthnPasskeyAuthority / PartnerPasskeyAuthority Signature

```
userSignature = abi.encode(
    bytes32 r, bytes32 s,
    uint256 challengeIndex, uint256 typeIndex,
    bytes authenticatorData, string clientDataJSON
)
```

The flat encoding OpenZeppelin `WebAuthn.tryDecodeAuth` expects. The WebAuthn
challenge is the raw 32-byte digest. `authenticatorData` must be at least 37
bytes; its first 32 bytes (`rpIdHash`) must equal `COFFERDAM_RP_ID_HASH`
(High) or the config's `rpIdHash` (Partner). User Verification is required.

### 5.3 PasskeyAuthority Signature

```
userSignature = r (32 bytes) || s (32 bytes)        // raw P-256 over the digest, low-s
```

### 5.4 SessionKeyAuthority Signature

```
userSignature = r (32 bytes) || s (32 bytes) || v (1 byte)
```

ECDSA over EIP-191 `personal_sign` of `keccak256(abi.encode(account, digest))`;
`v` is 27 or 28 and `s` ≤ secp256k1 half-order (EIP-2).

### 5.5 ERC-1271 `isValidSignature`

Same encoding as §5.1. Returns `0x1626ba7e` on success, `0xffffffff` on
failure. Only an active **High** authority can produce a valid ERC-1271
signature (decision 0016); Partner and Managed always get `0xffffffff`.

The authority signs `replaySafeHash(digest)`: the EIP-712 hash of
`CofferdamAccountMessage(bytes32 hash)` under
`{name: "Cofferdam Account", version: "1", chainId, verifyingContract: account}`
(also exposed via ERC-5267 `eip712Domain()`), so a signature is valid for one
account on one chain only.

### 5.6 ERC-6492 Counterfactual Signature

```
abi.encodePacked(
    abi.encode(address(factory), bytes(factoryCallData), bytes(erc1271Signature)),
    0x6492649264926492649264926492649264926492649264926492649264926492
)
```

The verifier deploys the account if needed, then calls `isValidSignature`.
Because ERC-1271 is High only, a counterfactual Partner or Managed account has
no valid ERC-1271 signature. See [EIP-6492](https://eips.ethereum.org/EIPS/eip-6492).

### 5.7 First High: `enrollFirstHigh`

```solidity
struct CeremonyAttestation { uint48 notBefore; uint48 expiry; bytes signature; }

function enrollFirstHigh(
    uint256 signerId,              // the Partner / Managed authority signing this userOp
    IAuthorityModule highModule,   // a listed High module
    bytes highConfig,              // abi.encode(qx, qy)
    bytes highAssertion,           // §5.2, over firstHighChallenge(ceremonyNonce)
    CeremonyAttestation attestation
) returns (uint256 highAuthorityId)
```

Three signatures in one userOp:

1. `userOp.signature = abi.encodePacked(signerId, <Partner/Managed signature over userOpHash>)`;
   validation requires `signerId` in the call data to equal the signing id.
2. `highAssertion`: the new passkey over
   `firstHighChallenge(nonce) = keccak256(abi.encode(keccak256("cofferdam-first-high-v1"), chainid, account, nonce))`.
3. `attestation.signature`: a key in `CofferdamCeremonyAttesterRegistry` signs,
   EIP-191 (`personal_sign`, 65 bytes), the 32-byte
   ```
   ceremonyHash(action, newKeyHash, partnerId, nonce, notBefore, expiry) =
     keccak256(abi.encode(keccak256("cofferdam-ceremony-v1"), chainid, account,
                          action, newKeyHash, partnerId, nonce, notBefore, expiry))
   ```
   with `action = keccak256("enroll-first-high")`, `newKeyHash = keccak256(highConfig)`,
   `partnerId` = the signer's config `partnerId` (0 for Managed), `nonce = ceremonyNonce`.
   The call reverts unless `notBefore ≤ block.timestamp ≤ expiry`. The plane
   sets `notBefore` 72 hours after a Partner recovery (decision 0016 cooldown).

Every successful ceremony increments `ceremonyNonce`, so a co-sign is
single-use.

### 5.8 Partner Recovery: `replacePartnerAuthority`

Only while no High exists. Replaces a lost partner-RP passkey with a new one
for the same partner, RP, partner backend key and permission.

```solidity
struct PartnerRecovery { uint48 recoveredAt; bytes signature; }

function replacePartnerAuthority(
    uint256 oldId,
    bytes newConfig,                   // §4.2; same rpIdHash, partnerId, partnerSigner as old
    PartnerRecovery recovery,
    CeremonyAttestation attestation    // action = keccak256("replace-partner"), newKeyHash = keccak256(newConfig)
) returns (uint256 newId)
```

- `userOp.signature = abi.encodePacked(RECOVERY_AUTHORITY_ID, <new passkey's assertion over userOpHash>)`.
- Validation (no external state, ERC-7562-safe): the call data must be
  `replacePartnerAuthority`; `oldId` must be an active Partner; both configs
  160 bytes with equal `rpIdHash`, `partnerId`, `partnerSigner`;
  `recovery.signature` must be the old config's `partnerSigner` over the
  EIP-191 hash of
  `partnerRecoveryHash(oldId, keccak256(newConfig), recoveredAt) = keccak256(abi.encode(keccak256("cofferdam-partner-recovery-v1"), chainid, account, oldId, newConfigHash, recoveredAt))`
  (otherwise revert); the new key's assertion, checked by the old authority's
  module against `newConfig`, else `SIG_VALIDATION_FAILED`.
- Execution checks the ceremony co-sign (§5.7), deactivates `oldId` and adds
  the new authority with the same module, tier and permission.

## 6. Events

| Event | Emitted by | Topic 0 |
|---|---|---|
| `AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt)` | Factory | `0xf0acda094aefca0f382f1150baa03e8c050833d76fb46857830a24f2c5abcdcb` |
| `AuthorityAdded(uint256 indexed authorityId, address indexed module, Tier tier, bytes32 kind)` | Account | `0x39a9287670c352474ebcf1c78b9dd1c455d0ef9d157c330a0730b61aa8c4c6a2` |
| `AuthorityRevoked(uint256 indexed authorityId)` | Account | `0xa0c11c88bc1270673387b343f0863efe1027d42dab56a9904d7770273aa2f731` |
| `PermissionGranted(uint256 indexed authorityId, bytes32 permissionHash, uint48 expiry)` | Account | `0xbeb185971c04fe30cf9261567660699df92c7ccc6cddec005acf7460082a5c79` |
| `FirstHighEnrolled(uint256 indexed signerAuthorityId, uint256 indexed highAuthorityId)` | Account | `0xf3a7166bd3ffe995d3d2f6bcf566d01e4a051e751587776b1ebb18c13bc72ebe` |
| `PartnerAuthorityReplaced(uint256 indexed oldAuthorityId, uint256 indexed newAuthorityId)` | Account | `0xa453a5029382d12d0d52c11069451ce5615ed1a9aadc7c427ba1f5a2dd7e70e0` |

`tier` in `AuthorityAdded` is not indexed (data, with `kind`).
`permissionHash = keccak256(abi.encode(permission))` with the `Permission`
tuple type of §2.1; it lets an indexer prove which grant a user approved.
`FirstPasskeyEnrolled` and `RatchetFired` no longer exist.

`CofferdamModuleRegistry` emits `ModuleAllowed(address indexed)`,
`ModuleDisallowed(address indexed)` and the two-step ownership events.

## 7. Kind Hashes

| Kind String | keccak256 Hash | Module |
|---|---|---|
| `"passkey"` | `0xf8be3eb00046723b30a0eadbcaacdfe1834a1086432fa32fdf925834c8a4c67c` | `WebAuthnPasskeyAuthority`, `PasskeyAuthority` |
| `"partner_passkey"` | `0x199044ddde58738ed9e18d77aa84df26d05aa242b37f9970d61e46758d8fd80b` | `PartnerPasskeyAuthority` |
| `"polis_sso"` | `0x577197dd8d37fc7560ed27760a013174367780bac0755a54364b0aae01d8f988` | `SessionKeyAuthority` |

Compute: `ethers.id(kindString)`. The old `"session"` kind is gone with the
`LowUntrusted` tier.

## 8. Key Function Selectors

| Function | Selector |
|---|---|
| `deployAccount(address,bytes,(address[],bytes4[],bytes32[],bytes4[],uint256,uint48),bytes32)` | `0xbcb51ab1` |
| `getAddress(address,bytes,(address[],bytes4[],bytes32[],bytes4[],uint256,uint48),bytes32)` | `0xa8ace465` |
| `ENTRY_POINT()` | `0x94430fa5` |
| `MODULE_REGISTRY()` | `0xb95ddb52` |
| `CEREMONY_ATTESTERS()` | `0xd76f8c3b` |
| `validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32,uint256)` | `0x19822f7c` |
| `execute(address,uint256,bytes)` | `0xb61d27f6` |
| `executeBatch(address[],uint256[],bytes[])` | `0x47e1da2a` |
| `getAuthority(uint256)` | `0xffae2c5b` |
| `getPermission(uint256)` | `0xffb5e276` |
| `addAuthority(address,bytes,(address[],bytes4[],bytes32[],bytes4[],uint256,uint48))` | `0x84beee01` |
| `revokeAuthority(uint256)` | `0x40405afc` |
| `enrollFirstHigh(uint256,address,bytes,bytes,(uint48,uint48,bytes))` | `0xba670010` |
| `firstHighChallenge(uint256)` | `0x5b1909f1` |
| `replacePartnerAuthority(uint256,bytes,(uint48,bytes),(uint48,uint48,bytes))` | `0xee198220` |
| `partnerRecoveryHash(uint256,bytes32,uint48)` | `0xbf7e7804` |
| `ceremonyHash(bytes32,bytes32,bytes32,uint256,uint48,uint48)` | `0xce7cb29f` |
| `ceremonyNonce()` | `0x72ffd414` |
| `replaySafeHash(bytes32)` | `0xce1506be` |
| `isValidSignature(bytes32,bytes)` | `0x1626ba7e` (ERC-1271) |

## 9. EntryPoint Interaction

### 9.1 Validation Flow

```
Bundler → EntryPoint.handleOps([userOp], beneficiary)
  → account.validateUserOp(userOp, userOpHash, missingFunds)
    → authorityId = signature[0:32]
    → RECOVERY_AUTHORITY_ID → partner recovery checks (§5.8)
    → otherwise: unknown/inactive → revert
                 module.isValidSignature(account, userOpHash, config, sig[32:]) false → 1
                 call policy of the recorded tier (§10.4) → revert, or validUntil
  → account.execute / executeBatch / management call
```

Registry reads happen only when an authority is added (execution), never in
validation, so ERC-7562 storage rules hold.

### 9.2 Gas Payment

- **With paymaster**: `CofferdamPaymaster` sponsors the UserOp (decision 0014).
- **Without paymaster**: the account pays from its EntryPoint deposit or balance.
- **Direct deploy**: the deployer EOA pays for `deployAccount`.

## 10. Security Invariants

1. **EntryPoint-only execution**: `execute`, `executeBatch`, `validateUserOp`
   and `replacePartnerAuthority` require `msg.sender == ENTRY_POINT`;
   `addAuthority`, `revokeAuthority` and `enrollFirstHigh` also accept a
   self-call (from a High `execute`).
2. **Module allowlist**: every authority, genesis included, uses a module
   listed in `MODULE_REGISTRY` at the time it is added; a module reporting
   `None` or `LowUntrusted` is refused. Delisting a module stops new installs,
   not existing authorities.
3. **Passkey cap and last High**: `passkeyCount <= MAX_PASSKEYS (3)`; revoking
   the last active High reverts `LastHighAuthority()`.
4. **Tier gating** (checked in `validateUserOp` against `userOp.callData`):
   - `High` may make any call.
   - `Partner` and `LowManaged` may `execute` / `executeBatch` only calls whose
     `(target, selector)`, or whose target's `(codeHash, selector)`, is in
     their `Permission`, never to the account
     itself, with value ≤ `valueCap`; and may call `enrollFirstHigh` naming
     themselves while no High exists. Anything else reverts
     `TierNotPermitted(tier)` or `CallNotPermitted(target, selector)`.
   - Only `High` adds or revokes authorities (`addAuthority`, `revokeAuthority`).
5. **Permission shape** (checked when granted): 1 to 16 pairs counting
   address and code-hash entries; no zero target; never the account itself; no
   code hash that is 0, `keccak256("")` (an account without code) or the
   account's own; no asset-moving selector (`transfer`, `approve`,
   `transferFrom`, `increaseAllowance`, `permit`, `setApprovalForAll`, ERC-721
   / ERC-1155 `safeTransferFrom` / `safeBatchTransferFrom`, ERC-777 `send` /
   `operatorSend` / `authorizeOperator`, ERC-1363 `transferAndCall` /
   `approveAndCall`, Permit2 `approve` / `transferFrom`); expiry 0 or in the
   future. Partner: `valueCap == 0` and `expiry != 0`. Managed: `valueCap > 0`
   only when granted by a High signer.
6. **First High needs Cofferdam and the user**: `enrollFirstHigh` requires the
   scoped signer, the new `cofferdam.xyz` passkey's assertion and an
   in-window ceremony co-sign, all bound to this account, chain and
   `ceremonyNonce`.
7. **One-way High**: once a High has existed, `upgradeLocked` is set for good;
   `enrollFirstHigh` and `replacePartnerAuthority` revert `HighAlreadyExists()`.
8. **Recovery keeps the grant**: a Partner recovery needs the partner backend's
   vouch, the new key's signature and a Cofferdam co-sign; it cannot change
   the partner, RP, backend key or permission.
9. **ERC-1271 is High only** and replay-safe per account and chain (§5.5).
10. **CREATE2 idempotency**: `deployAccount` returns the existing account if
    code is already at the address.

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
- **Account config**: EntryPoint (with correctness check), module and ceremony
  registries, authority count, passkey count, High-has-existed flag,
  `ceremonyNonce`
- **Authorities**: per-authority module, tier, kind, active status, decoded
  config (P-256 key, partner RP/id/backend key, or bridge signer) and, for
  Partner and Managed, the permission
- **Security summary**: active High / Partner / Managed counts and warnings
- **Deployment tx** (if `TX` is set): block, gas, status, decoded events
- **Interpretation**: the account's onboarding path and security posture

## 12. Audit References

- **Shannon** (planned): https://github.com/KeygraphHQ/shannon
- **OpenZeppelin WebAuthn**: `@openzeppelin/contracts/utils/cryptography/WebAuthn.sol`
- **OpenZeppelin P256**: `@openzeppelin/contracts/utils/cryptography/P256.sol`
- **ERC-4337 v0.7**: EntryPoint at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- **ERC-7562**: validation storage rules
- **EIP-6492**: Counterfactual contract signatures
- **EIP-1271**: Contract signature validation
- **EIP-2**: Signature malleability guard (SessionKeyAuthority)
- **RIP-7212**: P-256 precompile at `0x100` (Base Fjord/Azul)
