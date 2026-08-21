# ADR-001 — Split Cofferdam escrow primitives from the enterprise module

**Status:** Accepted 2026-08-03
**Supersedes:** the "wire `isWitnessDelegated` into `CofferdamSpotEscrow`" plan recorded in `TODO.md`

---

## 1. Context

`CofferdamSpotEscrow` currently serves two products that share almost no authority model:

| | Enterprise track | Consumer track |
|---|---|---|
| Who hires | A DNS-proven company | A private individual |
| Role separation | Finance / HR / Supervisor deliberately **disjoint** | All collapse into one hirer |
| Witness authority | Delegated by the company via registry | Self-sovereign |
| Org root, payroll, sub-treasury, pause | Yes | Meaningless |
| Escrow creation | Allowlisted callers | Must be open to any person |

The **mechanics are identical** — state machine, USDC custody, `awardWorker`, attest-start,
attest-end-and-release, `checkInTimeout`, Rule D, kill fee, dispute → resolve → dispute-timeout.
The **authority model is completely different**. That is the seam.

### 1.1 Evidence the shared contract is already straining

- **`EscrowFactory.createSpotEscrow` is `onlyAuthorized`.** A private individual cannot create an
  escrow unless Cofferdam allowlists every hirer or signs every job. **Consumer Spot cannot ship
  through this factory.** This is decisive and structural, not stylistic.
- **`selfWitnessed` is a symptom.** Shipped 2026-08-02 and correct for the shared contract, but it
  is a runtime boolean recording *which product this is*. In a consumer-native contract the hirer is
  structurally the witness, so the flag — and the take-back trap it fixes — both cease to exist.
- **The docs needed "unless" clauses in five places.** `setWitness` JSDoc, SDK README §4.3 + §4.7a,
  and two spots in `base-contracts/README.md` all had to branch on product identity. Prose that
  branches like that is describing two contracts wearing one name.

### 1.2 The dependency direction that was about to be inverted

- **Cofferdam primitives** — identity, escrow state machine, attestation, arbitration. Org-neutral.
- **Enterprise module** — company registry, org tree, delegation, sub-treasuries, payroll, pause.

Enterprise may depend on primitives. **Primitives must never depend on enterprise.** The previous
plan had `CofferdamSpotEscrow` import `CofferdamCorporateRegistry`, which would have made a private
individual hiring a plumber transitively depend on the corporate registry.

### 1.3 Sentinel-gated security is a known bug class here

Gating enforcement on `companyAnchor == 0` is conditional security keyed on a zero value. That is
exactly how the drain bug shipped: `require(_newWitness != worker)` looked sound, but `worker` is
`address(0)` in `Funded`, so the check silently collapsed. A B2B escrow constructed with a zero
anchor would skip delegation checks and be indistinguishable from a consumer escrow. This must be a
type distinction the compiler enforces, not a runtime value.

### 1.4 The repository boundary already exists — and cuts the wrong way

`contracts/enterprise` is a **git submodule** (`heads/main`, own `.git`), so today:

- `CofferdamSpotEscrow.sol`, both registries, `EscrowFactory.sol`, and `SPOT_ESCROW_RULES.md` live in
  the **private** repo.
- `base-contracts/test/` lives in the **public** parent and tests contracts from the private
  submodule.
- **The public test suite cannot run without private access.** Any future open-sourcing of the
  primitives is blocked by this, not by licensing.

---

## 2. Decisions

### D1 — Location and repository boundary

- `contracts/core/` — Cofferdam primitives, in the **public parent** repo.
- `contracts/enterprise/` — stays a **private submodule** until a deliberate decision to open source.
- The parent repo must **compile and test `contracts/core` with the submodule absent.** This is the
  acceptance test for the split being real.
- `SPOT_ESCROW_RULES.md` splits: worker-protection rules that apply to the primitive move to the
  parent; company-specific rules stay private.

### D2 — Naming

| Now | Becomes | Repo |
|---|---|---|
| — | `CofferdamEscrowCore` | public |
| — | `CofferdamEscrowCoreFactory` | public |
| `CofferdamSpotEscrow` | `CofferdamEnterpriseSpotEscrow` | private |
| `CofferdamPayrollEscrow` | `CofferdamEnterprisePayrollEscrow` | private |
| `CofferdamCompanyRegistry` | `CofferdamEnterpriseCompanyRegistry` | private |
| `CofferdamCorporateRegistry` | `CofferdamEnterpriseCorporateRegistry` | private |
| `EscrowFactory` | `CofferdamEnterpriseEscrowFactory` | private |

### D3 — `CofferdamEscrowCore` roles: four, no recruiter

`recruiter` is an enterprise concept and does not appear in the primitive.

| Role | Notes |
|---|---|
| `hirer` | **Fused with funder — not configurable.** The fee model requires a single known payer. Also awards the worker and manages the witness, since they own the job. |
| `worker` | The person awarded / selected. Sole payout destination. |
| `witness` | **Defaults to `hirer`.** Delegable to a stand-in and freely resumable. |
| `arbiter` | Neutral. Must differ from all three. May be a contract (future juror pool). |

Consequences:

- **`selfWitnessed` is deleted.** Hirer-as-witness is structural, so there is no flag and no
  take-back trap.
- **No `witness != funder` rule.** There is no separation of duties to protect when the hirer is
  definitionally both.
- The witness still **cannot redirect funds** — `checkOut` pays `worker` unconditionally. Delegation
  transfers timing authority only, never destination authority. This is what makes handing the role
  to a neighbour acceptable.

### D4 — Enterprise inherits the core; money logic is written once

`CofferdamEnterpriseSpotEscrow extends CofferdamEscrowCore`, which is legal under §1.2 (enterprise
may depend on primitives). The core exposes `virtual` authority hooks — `_assertCanAward`,
`_assertCanSetWitness`, `_assertCanAttest` — defaulting to `msg.sender == hirer`. Enterprise
overrides them with recruiter + registry-delegation checks.

Rationale: **worker protections must never diverge.** If Rule D lives in two files, a fix lands in
one and consumer workers silently get weaker protection than enterprise ones. The cost is three
`virtual` internal asserts in the primitive; the alternative cost is duplicated custody logic.

### D5 — Delegation is validated on grant, never on use

Checked at the two points authority is **granted** — construction and `setWitness`. Never at
`checkIn` or `checkOut`.

Checking at `checkIn` creates a wage-theft path: witness installed while delegated → revoked before
the worker arrives → `checkIn` reverts → worker turned away by an invisible revocation → check-in
window lapses → `reclaimNoShow` returns everything to the funder. **Revocation must never block a
worker from starting.**

Safe because the witness cannot redirect funds: a stale-but-once-valid witness releasing to the
correct worker is not a loss, so there is nothing to protect by re-checking at use time.

### D6 — Fee model (source: `financial/COFFERDAM_REVENUE.md` §1, §3)

- **2% of notional unlocked, 1% veCOFF-locked floor, no cap.** Spot carries a **$1 minimum** binding
  at its **$50 contract floor**.
- **The rate is a parameter, never a constant.** The veCOFF discount ladder lands later; hardcoding
  2% forces a redeploy.
- **Rate and originator are snapshotted immutably at construction.** An escrow funded under one rate
  must never settle under another.
- **The down-only doctrine becomes a contract invariant.** The rate setter may only ever *decrease*.
  This turns a documented promise into something verifiable on-chain.
- **The originator must be recorded.** The ¼ partner rev-share (OffshoreSync first) is routed by
  which app originated the volume, so the escrow has to know. This is an independent argument for
  the consumer factory being gated: the gate is what identifies the originator.

> Note: with the $50 floor enforced at creation, 2% of $50 is exactly $1, so the $1 minimum never
> binds independently. One floor check plus the 2% formula covers the published card. **Confirm this
> is intended before relying on it.**

### D7 — Consumer factory: gated, atomic create-and-fund, rate-limited

- **Atomic `createAndFund`.** No unfunded consumer escrow can exist, which removes the spam surface
  almost entirely — the fee and the $50 floor then do the anti-abuse work, because spam costs real
  money.
- **Rate limiting keys on the Self.xyz nullifier, not the address.** Per-address limits are trivially
  sybilled with a fresh address. Cofferdam already has one-human-one-nullifier; this is the same
  primitive the arbitration juror pool will use.
- Rate limiting is therefore a **secondary safety net**, not the primary defence.

---

## 3. Consequences

**Accepted costs**

- Every CREATE2 address moves. Cheap now: neither registry is deployed, and only one demo
  `CofferdamSpotEscrow` plus `EscrowFactory` exist on Base Sepolia. Nothing on mainnet.
- The SDK escrow client splits. Per the demand-driven guideline this is a *gain* — the consumer
  client is what OffshoreSync and the Cofferdam app need, and it stops carrying enterprise concepts
  it never uses.
- A cross-repo file move: the primitive leaves the private submodule for the public parent. Git
  history does not follow automatically; decide whether to port it or start clean.
- Docs sweep in the same pass, per the working guideline in `TODO.md`.

**Unaffected**

- **Arbitration.** `policy.arbiter` is just an address, so Cofferdam-now and the randomised juror
  pool later serve both tracks with zero coupling. The milestone survives intact.
- **Enterprise registry work** — anchor/domainHash keying, the registration guard that never fires,
  access tiers, unified pause with payout asymmetry. All enterprise-internal, unblocked, still the
  right first move.

---

## 4. Open items

- [ ] Confirm the $1-minimum reading in D6 — is it redundant given the $50 floor, or is the floor
      expected to move independently?
- [ ] `ENTERPRISE_MODULE_PLAN.md` (~line 4013) still cites **"flat 0.5%, no cap (rev-7)"**, retired
      by `COFFERDAM_REVENUE.md` rev-8.1 (2% / 1%). Stale rate in a planning doc.
- [ ] Decide git-history handling for the primitive's move out of the submodule.
- [ ] Rate-limit window and threshold per nullifier.
- [ ] Whether enterprise escrow creation stays a platform allowlist or moves to `companyAdmin`
      gating once anchors exist.
