# base-contracts

Cofferdam's smart contracts on Base. The public core is the ERC-4337 account layer — `CofferdamAccount4337` behind the CREATE2 `CofferdamAccountFactory4337`, with tiered authority modules (High passkey, Partner passkey, Managed session key), co-signed ceremonies, probation for new device keys and hard recovery — plus the Self.xyz registries that bind a passport nullifier to an account (Base Sepolia), and the provider-agnostic identity registry that replaces them on Base mainnet with ZKPassport proofs (workspace decision 0080; only the throwaway test generation `zkp-test-1` is live on Base mainnet, deployed 2026-11-15 under the M2 dev-key exception, see Deploy). The enterprise contracts (company registries, escrows) are a private submodule. Accounts are not upgradeable: a change to the account or the factory is a new generation with new addresses, and moving funds between generations is a user-signed migration (workspace decision 0025; the SDK generation table and sponsored move come first, an on-chain successor and sweep before mainnet).

## Layout

```
contracts/
  account/      CofferdamAccount4337, AuthorityManagerBase, CofferdamAccountFactory4337, CofferdamPaymaster
  auth/         WebAuthnPasskeyAuthority, PasskeyAuthority, PartnerPasskeyAuthority, SessionKeyAuthority
  registry/     CofferdamModuleRegistry, CofferdamCeremonyAttesterRegistry
  self/         NullifierRegistry, SelfAttesterRegistry, Verifier_vc_and_disclose, ISelfGroth16Verifier, SelfPublicSignals
  identity/     CofferdamIdentityRegistry, IIdentityEvidenceAdapter; zkpassport/ ZKPassportEvidenceAdapter, IZKPassportRootVerifier,
                CofferdamZKPassportPepperAdapter, IZKPassportDirect, ZKPassportSubVerifierChecks (Apache-2.0, ported from ZKPassport)
  handles/      CofferdamHandleAnchor (workspace decision 0086; built, not deployed)
  spike/        c1-one-time-account/: a gas measurement only (one-time receive accounts, ERC-4337 against EIP-7702); never deployed
  interfaces/   IAuthorityModule, IEntryPoint (v0.7), IB20Factory
  test/         mocks: MockCounter, MockEntryPoint, MockGroth16Verifier, MockTierModule, MockUSDC, MockZKPassport, MockZKPassportDirect;
                ZKPassportExampleConsumer (ZKPassport's dashboard example, a fork cross-check only)
  enterprise/   private submodule cofferdamxyz/enterprise-contracts (proprietary)
scripts/        deploy-self, deploy-auth (lib/accountLayer), deploy-identity, move-paymaster-deposit, inspect-account,
                rotate-self-attester, deploy-escrow, deploy-all (local only), create-safe, safe-exec, verify,
                deploy-handle-anchor (Base Sepolia only; lib/handleAnchorDeploy); lib/chain (mainnet guards),
                lib/identity (digest and evidence encodings), lib/handleAnchor (the anchor's EIP-712 types and Safe actions),
                lib/rpcRetry (every RPC network: a read answered with neither result nor error is asked again; sends never are);
                spike/c1-one-time-account/measure.ts (local anvil fork only)
deployments/    baseSepolia.json (source of truth for Sepolia addresses), localhost.json;
                on Base mainnet one file per generation, <network>.<GENERATION>.json (base.<GENERATION>.json for a
                Ledger generation; baseDevTest.zkp-test-1.json for the dev-key exception's)
test/           Hardhat tests (TypeScript); fork/ runs on a fork of Base mainnet; fixtures/ pins encodings for the SDK
typechain-types/  generated, tracked
cli/            interactive CLI for a local node
```

## Contracts

| Contract | Role |
|---|---|
| `CofferdamAccount4337` | the account: authorities by tier, `Permission`-scoped Partner and Managed calls, `enrollFirstHigh`, `replacePartnerAuthority`, probation, `recoverHigh` / `finalizeRecovery` / `cancelRecovery`; ERC-1271 for High only |
| `AuthorityManagerBase` | authority registry, permissions, at most 3 passkeys, the last High unrevokable |
| `CofferdamAccountFactory4337` | CREATE2 factory; pins the EntryPoint, both registries, the `NullifierRegistry`, `RECOVERY_DELAY` and `PROBATION_PERIOD` |
| `CofferdamPaymaster` | Sepolia only: sponsors an op only when `tx.origin` is the plane's relayer and the sender runs the factory's account code (workspace decision 0071); owner-only withdrawals and relayer change; no script deploys it on mainnet, where the CDP paymaster sponsors |
| `WebAuthnPasskeyAuthority` | High: WebAuthn assertion, `rpIdHash` pinned to `cofferdam.xyz`, user verification required |
| `PasskeyAuthority` | raw P-256 signatures; test networks only |
| `PartnerPasskeyAuthority` | Partner: the user's passkey on a partner app's RP, zero value, within its `Permission` |
| `SessionKeyAuthority` | Managed: an employer bridge ECDSA key, within its `Permission` |
| `CofferdamModuleRegistry` | the modules an account may install |
| `CofferdamCeremonyAttesterRegistry` | keys that co-sign ceremonies (first High, Partner re-key, hard recovery) |
| `NullifierRegistry` | binds a passport nullifier to one account (`verifyAndBind`); `rebind` / `finalizeRebind` / `cancelRebind`; `provenNullifier` for hard recovery |
| `SelfAttesterRegistry` | the Self attester allow-list `NullifierRegistry` checks |
| `CofferdamIdentityRegistry` | decision 0080: binds one identifier to one account, called by the account itself; every proof is bound to an action digest over a tag, the chain, the registry, the account and its nonce here; `bind`, `relink` (retires the old identifier, which never binds again; refused while a rebind of it is pending), `requestRebind` / `finalizeRebind` / `cancelRebind` (decision 0022's delay); a retired identifier stays claimable by `requestRebind`, vetoed by the account that retired it or ruled by the owner (`ruleRetiredClaim`, decision 0080 P4); one identifier kind and scope; evidence checked by adapters the owner adds behind a timelock; pause and test allowlist; `isAccountBound` and the `check` pre-flight view. Today's accounts bind against it, but their `recoverHigh` needs Self's `provenNullifier` and reverts |
| `ZKPassportEvidenceAdapter` | decision 0080, T5: checks a compressed-EVM proof through ZKPassport's `RootVerifier` with the version, domain `cofferdam.xyz`, scope, validity and `devMode` false pinned; the identifier type (and, salted, the OPRF key) pinned; bound `user_address`, chain and `custom_data` (the digest as 0x hex) decoded by the version's helper, pinned at deployment so a swap by ZKPassport fails closed; exactly one bind section; minimum age and expiry margin (the helper's exact-bound checks); refuses disclosure (document bytes, nationality or issuing-country inclusion, birth-date ranges, upper bounds on age or expiry); from circuits 0.23.0, whose outer proof ends with the verification method, reads the trailing inputs by that layout and accepts only government-signed documents (methods 100 to 199, never a device-attested camera read; ruling S7) |
| `CofferdamZKPassportPepperAdapter` | decision 0080, the pepper (P1, ruled 2026-11-18): a chip proof from Cofferdam's in-app prover whose identifier is salted under Cofferdam's own OPRF key. ZKPassport's `SubVerifier` accepts salted proofs only under its global key (a fork read of 2026-11-19 shows `RootVerifier` refusing any other with "Invalid OPRF public key"), so this adapter calls the outer circuit's UltraHonk verifier itself and repeats every other check of `SubVerifier.verify`: both pauses, the version's sub-verifier, both registry roots at the proof's date, the validity, domain and scope, the committed inputs against the parameter commitments, the identifier type (salted only); the key must be its pinned `OPRF_KEY_HASH`, never ZKPassport's global key. Stricter than the sub-verifier: the outer verifiers are pinned per vkey hash at deployment and must still be listed by the live sub-verifier (a withdrawn or swapped one fails closed); circuits 0.23.0 or later only; the eMRTD chip (method 100) only (the founder, 2026-11-19: "only passport with chips for now"), since Aadhaar (101) passes ZKPassport only with their app's face match and 102 and 103 are not verifiable (within ruling S7's 100 to 199); only the age, expiry and bind sections, once each. Keeps `ZKPassportEvidenceAdapter`'s pinned helper, bound account, chain and digest, minimum age and expiry margin. Same identifier kind as a salted `ZKPassportEvidenceAdapter` under the same key, so a later adapter through `RootVerifier` (if ZKPassport accepts a per-service key) is an adapter swap. The contract's NatSpec maps each sub-verifier check to where it is made. Not deployed: `deploy-identity.ts` takes it on a fork or a testnet only |
| `CofferdamHandleAnchor` | decision 0086, rule 3: per `handleId` (keccak256 of `cofferdam-handle-v1:` and the label) the handle key (`owner`), a `serial` that rises with each fresh claim, and the ERC-5564 scheme 1 meta-address; no account, inbox or label. `claim` with a registrar's and the owner's EIP-712 signatures, refused for 365 days after a release; the owner's `transferOwner` (co-signed by the new key), `setMetaAddress` and `release` wait 72 hours, one at a time, and the owner may `cancel`; `advance` (owner, new key and registrar) applies at once; registrars `hold`, `renewHold` and `veto` (a 14-day freeze; a hold refuses a record with a pending change); `unfreeze` by owner and registrar. Owned by the Safe (two-step, timelocked transfer): adding a registrar, `rekey` and `forceRelease` wait the contract's own 72-hour timelock, removing a registrar and `liftFreeze` are immediate. One per-handle nonce in every signed struct; the types are the SDK's `identity/handle.ts`, pinned by `test/fixtures/handleAnchorTypes.json`. Delays are constructor parameters, and on chain 8453 only 0086's values deploy. Reads no identity registry. `scripts/deploy-handle-anchor.ts` deploys it on Base Sepolia only (not run: a deploy waits on 0086 questions 15 and 16) |
| `Verifier_vc_and_disclose` | Self's Groth16 verifier for the disclose circuit, vendored unchanged |
| `IB20Factory` | interface only; no contract uses it |
| Enterprise (private) | `CofferdamCompanyRegistry` (domain-proof company registration), `CofferdamCorporateRegistry` (org root, witnesses, pause), `CofferdamSpotEscrow` (per-job escrow with witness check-in/check-out and an arbiter dispute window), `CofferdamPayrollEscrow` (calendar payroll), `EscrowFactory` (CREATE2 per-job escrows), `CofferdamSubTreasuryFactory`, `CofferdamWalletBind`, and the enterprise CLI |

The two company registries have no access control yet; they must not reach a public deployment in this state.

## Build and test

yarn only; never `npm install`.

```bash
git submodule update --init --recursive   # only with access to the private enterprise repository
yarn install
yarn compile          # also regenerates typechain-types/; commit it with any ABI change
yarn test
yarn typecheck        # yarn typecheck:enterprise covers the submodule
```

The public core compiles and tests without the submodule; `test/spot-escrow-witness.test.ts` exercises the enterprise escrow and needs it. Cloud clones never fetch it.

Base mainnet fork: `yarn test:fork` runs `test/fork/zkpassport-fork.test.ts` and `test/fork/pepper-adapter-fork.test.ts` on an in-process fork that keeps chain id 8453 (ZKPassport's verifier answers only on mainnet); `ZKP_PARAMS_FILE` points it at a real proof's Solidity parameters kept outside the repository, never committed. The pepper's fork test reads circuits 0.23.0's twelve outer verifiers from the live sub-verifier, deploys `CofferdamZKPassportPepperAdapter` on the fork, and shows a forged proof clearing every check of the adapter and reaching the outer verifier, which refuses it; no real proof salted under a Cofferdam key exists yet. `BASE_FORK=1 npx hardhat test test/fork/handle-anchor-fork.test.ts` runs the handle anchor on the same fork under a real Safe v1.4.1, through every `anchor-*` Safe action. `yarn node:start:base` runs base-anvil forking Base mainnet on `:8546` for deploy dry runs (`--network baseFork`).

Local chain: `yarn node:start` runs [base-anvil](https://github.com/base/base-anvil) forking Base Sepolia on `:8545`; `yarn deploy:all:local` deploys the full stack there (with a mock verifier, so never on a public network); `yarn cli` explores it. `ACCOUNT=0x… yarn inspect:account --network baseSepolia` prints a deployed account's authorities, pins and state.

## Deploy

`deploy-identity.ts` deploys the registry with `ZKPassportEvidenceAdapter` by default, or with `ZKP_ADAPTER=pepper` the pepper adapter: salted, circuits 0.23.0 by default, `ZKP_OPRF_KEY_HASH` (Cofferdam's key hash, never ZKPassport's global one), the outer verifiers from `ZKP_OUTER_VKEY_HASHES` or the 0.23.0 table in `scripts/lib/identity.ts`, each read back from the sub-verifier. It runs on a local fork of Base mainnet (`--network baseFork`) or a testnet (mocks, with no `ZKP_ROOT_VERIFIER`) and refuses Base mainnet itself.

Base Sepolia, signed by the CofferdamDev key in the untracked `.env`: `yarn deploy:self:sepolia` when the registry changes, then `yarn deploy:auth:sepolia`, then `yarn paymaster:move:sepolia`, then move the pins in the API, attester and app. See `docs/runbooks/sepolia-deploys.md` in the cofferdam workspace repository.

The handle anchor (decision 0086) deploys on Base Sepolia only, and not before 0086's questions 15 and 16 are ruled: `yarn safe:create:sepolia` once (a Safe v1.4.1 that the CofferdamDev key signs for, recorded as `CofferdamSafe`), then `HANDLE_REGISTRAR_ADDRESS=<the plane's registrar key> yarn deploy:handle-anchor:sepolia` (`DRY_RUN=1` first). The anchor is owned by that Safe (`HANDLE_ANCHOR_SAFE` overrides) from its first block; the registrar is the plane's own hot key, refused when it is the deployer, the CofferdamDev wallet, the recorded paymaster's relayer or `RELAYER_ADDRESS`, the Safe or one of its signers, or a contract; the deployer holds no role on the anchor. Sepolia's delays are short so a device test finishes in a session: `HANDLE_CHANGE_DELAY_SECONDS` 600, `HANDLE_FREEZE_SECONDS` 1800, `HANDLE_QUARANTINE_SECONDS` 86400, `HANDLE_SAFE_DELAY_SECONDS` 600 by default, each within the contract's bounds. The script refuses chain 8453, a fork included (the mainnet anchor waits on the Ledger and the production Safe; `mainnetDelaysRefusal` pins 0086's values for its script), refuses to replace a recorded anchor without `HANDLE_ANCHOR_REDEPLOY=1`, records `CofferdamHandleAnchor` (with its `txHash`, `blockNumber` and `deployer`) and `CofferdamHandleAnchorSafe` and prints the plane's `HANDLE_ANCHOR_ADDRESS` and `HANDLE_ANCHOR_FROM_BLOCK` as soon as the deploy mines, then reads the anchor back. `VERIFY_KEYS=CofferdamHandleAnchor yarn verify:sepolia` (VERIFY_KEYS is required on Sepolia) verifies it on Basescan (by the recorded creation transaction), and `yarn safe:exec:sepolia` runs its `anchor-*` Safe actions.

Base mainnet signs with the Ledger only (Hardhat Ledger plugin, `LEDGER_ADDRESS`): the `base` network takes no private key, and the scripts' guards read the chain id from the node, so a fork dry run runs them. Self, the escrow demo, `deploy-all` and the paymaster refuse chain 8453; every delay is at least 72 hours; each generation has its own deployments file (`GENERATION`). The one departure is the temporary M2 dev-key exception (the founder, 2026-11-14; MVP only, never production): with `MAINNET_DEV_KEY_EXCEPTION=zkp-test-1` and `GENERATION=zkp-test-1`, the `baseDevTest` network signs with the CofferdamDev wallet, and the generation is owned by a Safe v1.4.1 that wallet signs for (`scripts/create-safe.ts`, checked on chain), or by the wallet itself; any other generation, signer, owner or network on 8453 is refused (`scripts/lib/devKeyException.ts`). Only that throwaway test generation is deployed there (2026-11-15, `deployments/baseDevTest.zkp-test-1.json`). `scripts/safe-exec.ts` (`yarn safe:exec:base-dev`, `safe:exec:fork` for a dry run) sends the identity registry's owner actions through a threshold-1 Safe: the pause drill, the adapter propose-and-cancel drill on a never-activated copy of the adapter, an adapter for another ZKPassport circuits version (`adapter-propose` deploys a copy pinned to `ZKP_CIRCUITS_VERSION` and RootVerifier's helper for it, recorded as `ZKPassportEvidenceAdapterV0_22_0` and the like; `adapter-activate` after the timelock, within the grace; `adapter-propose` again once a proposal has expired; `adapter-cancel` withdraws one; each refuses a recorded adapter that no longer pins its version or RootVerifier's helper for it), `setTestAccount` (`ALLOWED` 1 or 0, nothing else), and pause or unpause; and the handle anchor's owner actions (`anchor-*`: registrar schedule, add and remove, rekey and forceRelease schedule and execute, cancel a scheduled operation, lift a freeze, ownership transfer, cancel and accept; `HANDLE_ANCHOR`, `HANDLE_LABEL` or `HANDLE_ID`, `NEW_OWNER`, `META_ADDRESS`, `QUARANTINE`, `SAFE_OP_ID`, `NEW_SAFE`). Effects are read back at the block that mined them; a pause drill that stops part-way says whether it left the registry paused. ZKPassport's app chooses the circuits version it proves in, and RootVerifier checks a proof under its own, so a registry needs an adapter for each version the app proves in. An adapter for 0.23.0 or later must be deployed from base-contracts 0.23.0-aware code or later: earlier code reads that layout's identifier as its type and refuses every proof. `scripts/verify.ts` (`yarn verify:base-dev`; `yarn verify:base` with `GENERATION` and `DEPLOYER` for a Ledger generation) verifies a generation on Basescan from the chain itself: for each recorded contract it finds the deployer's creation transaction, checks it starts with the bytecode compiled here, decodes the constructor arguments from the rest and submits them through Etherscan's v2 API with one Etherscan.io key (`ETHERSCAN_API_KEY`); `CHECK_ONLY=1`, or no key, runs the checks alone. It signs nothing. See `docs/runbooks/mainnet-deploys.md`.

## Key facts

- Current Sepolia addresses are in `deployments/baseSepolia.json`, written by the deploy scripts. `cofferdam-api/src/chain/deployments.ts` mirrors them by hand; the SDK holds no address table. Never edit an address in one place only.
- EntryPoint v0.7 at its canonical address; RIP-7212 P-256 precompile for passkey verification. Solidity 0.8.28, `viaIR`, Cancun.
- The Sepolia layer pins `RECOVERY_DELAY` 0 and `PROBATION_PERIOD` 600 seconds; mainnet deploys refuse less than 72 hours for both, for the identity registry's rebind and adapter delays too, and require a registry owner (the Cofferdam Safe; the founder's Ledger for the throwaway test generation, or, under the M2 dev-key exception, a Safe the CofferdamDev wallet signs for).
- `NullifierRegistry` pins the scope of `cofferdam.xyz` × `cofferdam-bind-v1` and Self's destination chain 42220, both immutable.
- Contract names follow the `Cofferdam*` ladder in the workspace `rules/cofferdam-sdk.md`.

## Documentation

Design documentation lives in the cofferdam workspace repository under `docs/` and will be published at docs.cofferdam.xyz: `docs/architecture/contracts.md` (contracts, generations, the deployments table), `docs/architecture/identity.md` (tiers, ceremonies, recovery), `docs/architecture/account-encoding.md`, `docs/runbooks/sepolia-deploys.md`, `docs/runbooks/mainnet-deploys.md`, `decisions/0080-zkpassport-replaces-self-built-on-base-mainnet.md`.

## License

Split by directory; each file's SPDX header is authoritative:

- `contracts/account/`, `auth/`, `registry/`, `self/`, `identity/`, `interfaces/`, `test/`: MIT.
- `contracts/identity/zkpassport/ZKPassportSubVerifierChecks.sol`: Apache-2.0, ported from ZKPassport's `SubVerifier.sol` and `DateUtils.sol` with their notice and the changes listed.
- `contracts/self/Verifier_vc_and_disclose.sol`: GPL-3.0, vendored from Self.xyz.
- `contracts/enterprise/`: proprietary; see `contracts/enterprise/LICENSE` in the private submodule.
