@AGENTS.md

## Workspace

This is a Cofferdam product repository. On the Mac it is checked out inside the
`cofferdam` workspace repository (`cofferdamxyz/cofferdam`), whose `AGENTS.md`,
`rules/` and `.claude/skills/` are at `../`. In a cloud session (claude.ai/code,
the Claude mobile app, Projects) the clones sit side by side, so the same files
are at `../cofferdam/`. Read the workspace `AGENTS.md` first whenever it is
present, and the `rules/<area>.md` for the area you touch.

## Validate here

`yarn compile`, `yarn test`, `yarn typecheck`; commit the regenerated
`typechain-types/`. The private `contracts/enterprise/` submodule is absent in
cloud clones and must not be fetched there; the public core builds without it,
but the escrow witness test needs it.

## Delegated git (cloud session, Projects thread, Lockkeeper)

Never commit on `main`. Commit on the session branch with `git commit -s` and
a `Co-Authored-By: Claude <model> <noreply@anthropic.com>` trailer naming the
model that wrote the change, push that branch at every stopping point, and
open a draft pull request against `main` at the first push (`gh api` REST or
the session's Create PR control; `gh pr` is blocked in the cloud). Never mark
it ready, never merge, never enable auto-merge. The founder lands branches
locally and closes the pull request (workspace decision 0013). Interactive
sessions on the Mac commit on `main` and never push unless asked.
