# base-contracts

Cofferdam's smart contracts on Base. The public core is the ERC-4337 account layer — `CofferdamAccount4337` behind the CREATE2 `CofferdamAccountFactory4337`, with tiered authority modules (High passkey, Partner passkey, Managed session key), co-signed ceremonies, probation for new device keys and hard recovery — plus the Self.xyz registries that bind a passport nullifier to an account. The enterprise contracts (company registries, escrows) are a private submodule. Accounts are not upgradeable: a change to the account or the factory is a new generation with new addresses, and moving funds between generations is a user-signed migration (workspace decision 0025; the SDK generation table and sponsored move come first, an on-chain successor and sweep before mainnet).

## Layout

```
contracts/
  account/      CofferdamAccount4337, AuthorityManagerBase, CofferdamAccountFactory4337, CofferdamPaymaster
  auth/         WebAuthnPasskeyAuthority, PasskeyAuthority, PartnerPasskeyAuthority, SessionKeyAuthority
  registry/     CofferdamModuleRegistry, CofferdamCeremonyAttesterRegistry
  self/         NullifierRegistry, SelfAttesterRegistry, Verifier_vc_and_disclose, ISelfGroth16Verifier, SelfPublicSignals
  interfaces/   IAuthorityModule, IEntryPoint (v0.7), IB20Factory
  test/         mocks: MockCounter, MockEntryPoint, MockGroth16Verifier, MockTierModule, MockUSDC
  enterprise/   private submodule cofferdamxyz/enterprise-contracts (proprietary)
scripts/        deploy-self, deploy-auth (lib/accountLayer), move-paymaster-deposit, inspect-account,
                rotate-self-attester, deploy-escrow, deploy-all (local only)
deployments/    baseSepolia.json (source of truth for Sepolia addresses), localhost.json
test/           Hardhat tests (TypeScript)
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

Local chain: `yarn node:start` runs [base-anvil](https://github.com/base/base-anvil) forking Base Sepolia on `:8545`; `yarn deploy:all:local` deploys the full stack there (with a mock verifier, so never on a public network); `yarn cli` explores it. `ACCOUNT=0x… yarn inspect:account --network baseSepolia` prints a deployed account's authorities, pins and state.

## Deploy

Base Sepolia, signed by the CofferdamDev key in the untracked `.env`: `yarn deploy:self:sepolia` when the registry changes, then `yarn deploy:auth:sepolia`, then `yarn paymaster:move:sepolia`, then move the pins in the API, attester and app. See `docs/runbooks/sepolia-deploys.md` in the cofferdam workspace repository.

## Key facts

- Current Sepolia addresses are in `deployments/baseSepolia.json`, written by the deploy scripts. `cofferdam-api/src/chain/deployments.ts` mirrors them by hand; the SDK holds no address table. Never edit an address in one place only.
- EntryPoint v0.7 at its canonical address; RIP-7212 P-256 precompile for passkey verification. Solidity 0.8.28, `viaIR`, Cancun.
- The Sepolia layer pins `RECOVERY_DELAY` 0 and `PROBATION_PERIOD` 600 seconds; mainnet deploys refuse less than 72 hours for both and require the Cofferdam Safe as registry owner.
- `NullifierRegistry` pins the scope of `cofferdam.xyz` × `cofferdam-bind-v1` and Self's destination chain 42220, both immutable.
- Contract names follow the `Cofferdam*` ladder in the workspace `rules/cofferdam-sdk.md`.

## Documentation

Design documentation lives in the cofferdam workspace repository under `docs/` and will be published at docs.cofferdam.xyz: `docs/architecture/contracts.md` (contracts, generations, the deployments table), `docs/architecture/identity.md` (tiers, ceremonies, recovery), `docs/architecture/account-encoding.md`, `docs/runbooks/sepolia-deploys.md`.

## License

Split by directory; each file's SPDX header is authoritative:

- `contracts/account/`, `auth/`, `registry/`, `self/`, `interfaces/`, `test/`: MIT.
- `contracts/self/Verifier_vc_and_disclose.sol`: GPL-3.0, vendored from Self.xyz.
- `contracts/enterprise/`: proprietary; see `contracts/enterprise/LICENSE` in the private submodule.
