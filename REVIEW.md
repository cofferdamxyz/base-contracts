# REVIEW.md — base-contracts

Read with `AGENTS.md` and the workspace `docs/architecture/contracts.md` and `account-encoding.md`. Everything under `contracts/` is **high risk**: deployed accounts are immutable, and a change is a redeploy and, for the account layer, a new generation (decision 0025). Here failure means **funds or authority move in a way nobody signed for**.

## What failure looks like

- An authority path that lets a Partner or Managed key, a session, or a Cofferdam key do what only the account's High signers may do (sends to an address, withdrawals, off-ramps; decisions 0026 and 0028), or an admin or keeper path into an account or a company's funds.
- The escrow arbiter acting outside `disputeWindow` or between parties other than funder and worker (decision 0027).
- A change to an encoding (passkey config, genesis `Permission`, account salt) without the SDK's encoder changing in the same pass.
- Reentrancy, an unchecked external call or return value, an unbounded loop over user-controlled data, a missing event on a state change.
- An ABI change without regenerated `typechain-types/`; a deployed address changed in `deployments/` without every mirror (the API's `src/chain/deployments.ts`, the attester pin, the app env, `contracts.md`) and a workspace decision.
- A test that only runs with the private `contracts/enterprise/` submodule presented as checked from the cloud, where it is absent.

## Skip

- `typechain-types/` contents (check only that they were regenerated), `artifacts/`, `cache/`.

## How to report

- Every finding names a file and line and quotes the code or text that is wrong. A guess from a name or a path is not a finding.
- Tag each one **Important** (wrong behaviour, a broken rule above, a security or money risk), **Nit** (at most three per review; style alone is never one) or **Pre-existing** (true, but not introduced by this diff; never blamed on it).
- Flag a class of bug once with every instance, not one finding per line. Do not repeat a finding already answered in an earlier round; after the second round read only the new diff.
- Start the summary with the count ("2 Important, 1 Nit, 1 Pre-existing"), and say "Nothing to fix" plainly when that is the result.
- Name the risk tier the diff falls in (workspace `docs/runbooks/code-review.md`).
