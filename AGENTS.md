# AGENTS Instructions — base-contracts

## Scope

Cofferdam's Base contracts: the ERC-4337 account layer (`contracts/account/`,
`contracts/auth/`, `contracts/registry/`), the Self.xyz registries (`contracts/self/`) and the
interfaces, all MIT, plus the proprietary enterprise module as the private git
submodule `contracts/enterprise/` (`cofferdamxyz/enterprise-contracts`,
decision 0002). Hardhat with TypeScript tests. Design and the byte-level
encoding live in the workspace: `docs/architecture/contracts.md` and
`docs/architecture/account-encoding.md`.

## Rules

- yarn only; never `npm install`. `yarn compile`, `yarn test` and
  `yarn typecheck` before a commit.
- `typechain-types/` is tracked: regenerate it (compile) and commit it with
  any ABI change.
- The enterprise submodule is private: cloud clones do not receive it and must
  not try to fetch it. The public core compiles without it, but
  `test/spot-escrow-witness.test.ts` needs it (no guard yet), so `yarn test`
  fails in a clone without the submodule.
- Deployed addresses live in `deployments/baseSepolia.json` and are mirrored
  in the API (`cofferdam-api/src/chain/deployments.ts`), the attester's
  registry pin, the app env and `docs/architecture/contracts.md`; the SDK
  holds no address table. Accounts are immutable: a change to a deployed
  contract is a redeploy (a new generation for the account layer, decision
  0025), every mirror updated in the same pass, and a workspace decision.
  Procedure: `docs/runbooks/sepolia-deploys.md`.
- Contract naming follows `Cofferdam*` (`rules/cofferdam-sdk.md`);
  identity rules are `rules/cofferdam-identity.md`, both in the `cofferdam`
  repository (`../` on the Mac, `../cofferdam/` in a cloud session).
- `README.md` here and the workspace `docs/` describe behaviour; update them in the same pass.
