# AGENTS Instructions — base-contracts

## Scope

Cofferdam's Base contracts: the ERC-4337 account layer (`contracts/account/`,
`contracts/auth/`, `contracts/registry/`), the Self.xyz registries (`contracts/self/`) and the
interfaces, all MIT, plus the proprietary enterprise module as the private git
submodule `contracts/enterprise/` (`cofferdamxyz/enterprise-contracts`,
`ADR-001-CORE-ENTERPRISE-SPLIT.md`). Hardhat with TypeScript tests;
`docs/ACCOUNT_ENCODING.md` describes the account encoding.

## Rules

- yarn only; never `npm install`. `yarn compile`, `yarn test` and
  `yarn typecheck` before a commit.
- `typechain-types/` is tracked: regenerate it (compile) and commit it with
  any ABI change.
- The enterprise submodule is private: cloud clones do not receive it and must
  not try to fetch it; the public core compiles and tests without it.
- Deployed addresses live in `deployments/baseSepolia.json` and are mirrored
  in the SDK (`SEPOLIA_DEPLOYMENTS`) and the API. A change to a deployed
  contract is a redeploy (`scripts/deploy-*.ts`), the SDK and API address
  update and a workspace decision; never edit an address in one place.
- Contract naming follows the `Cofferdam*` ladder in `rules/cofferdam-sdk.md`;
  identity rules are `rules/cofferdam-identity.md`, both in the `cofferdam`
  repository (`../` on the Mac, `../cofferdam/` in a cloud session).
- `README.md` and `docs/` describe behaviour; update them in the same commit.
