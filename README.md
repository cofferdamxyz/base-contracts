# Cofferdam — Base Contracts

Cofferdam onchain contracts for Base. ERC-4337 account abstraction with tiered
passkey authority, session-key legacy bridge, and Self.xyz sybil resistance.

## License Split

This repository contains two licensing tiers:

- **Open-source base contracts** (`contracts/account/`, `contracts/auth/`,
  `contracts/interfaces/`, `contracts/self/`, `contracts/test/`) — MIT License.
  These are the account abstraction primitives: `CofferdamAccount4337`,
  `AuthorityManagerBase`, passkey/session authorities, Self.xyz registries.

- **Proprietary enterprise contracts** (`contracts/enterprise/`) —
  PROPRIETARY. This is a **Git submodule** pointing to
  [`cofferdamxyz/enterprise-contracts`](https://github.com/cofferdamxyz/enterprise-contracts)
  (private repo). It contains the enterprise payroll escrow contracts: company
  registries, spot/payroll escrows, sub-treasury factory, wallet bind, and the
  enterprise CLI for Workday CSV import, org tree building, wallet provisioning,
  and escrow lifecycle management. See `contracts/enterprise/LICENSE` for terms.

### Cloning with the enterprise submodule

```bash
# Clone with submodule included (requires SSH key access to the private repo)
git clone --recursive git@github.com:cofferdamxyz/base-contracts.git

# If already cloned, initialize the submodule
git submodule update --init --recursive
```

> **Contributors:** The `contracts/enterprise/` submodule is private. If you get
> a permission denied error, ensure your SSH key is linked to a GitHub account
> with access to the `cofferdamxyz/enterprise-contracts` repository. The
> open-source base contracts work fully without the submodule — it's only needed
> for enterprise payroll and escrow development.

## Architecture

```
contracts/
├── interfaces/                          # MIT — chain-agnostic ABIs
│   ├── IAuthorityModule.sol             # Tiered auth ABI
│   ├── IEntryPoint.sol                  # ERC-4337 EntryPoint v0.7 minimal interface
│   └── IB20Factory.sol                  # B20 + PolicyRegistry interfaces
├── account/                             # MIT — ERC-4337 account layer
│   ├── AuthorityManagerBase.sol         # Authority registry + one-way ratchet
│   ├── CofferdamAccount4337.sol         # ERC-4337 account (validateUserOp + execute)
│   ├── CofferdamAccountFactory4337.sol  # CREATE2 counterfactual factory
│   └── CofferdamPaymaster.sol           # Stub verifying paymaster, EntryPoint v0.7 4-arg postOp (→ CDP in production)
├── auth/                                # MIT — authority modules
│   ├── PasskeyAuthority.sol             # P-256 raw signature (RIP-7212 precompile)
│   ├── WebAuthnPasskeyAuthority.sol     # Full WebAuthn assertion verification
│   └── SessionKeyAuthority.sol          # ECDSA session-signer bridge (legacy auth)
├── self/                                # MIT — Self.xyz sybil resistance
│   ├── SelfAttesterRegistry.sol         # Trusted Self.xyz TEE attester allow-list
│   ├── NullifierRegistry.sol            # Passport nullifier → account binding
│   ├── ISelfGroth16Verifier.sol         # Groth16 verifier interface
│   └── SelfPublicSignals.sol            # Public signal index constants
├── test/                                # MIT — test mocks
│   ├── MockCounter.sol
│   └── MockGroth16Verifier.sol
└── enterprise/  ← GIT SUBMODULE (proprietary, github.com/cofferdamxyz/enterprise-contracts)
    ├── LICENSE                          # Proprietary license terms
    ├── README.md                        # Full enterprise module documentation
    ├── company/                         # Company registration + org tree
    │   ├── CofferdamCompanyRegistry.sol     # Domain-proof company wallet deployment
    │   └── CofferdamCorporateRegistry.sol   # Merkle OrgRoot + pauseCompany + witnesses
    ├── escrow/                          # Spot + Payroll escrow contracts
    │   ├── IEscrow.sol                      # Shared interface + EscrowStateChanged event
    │   ├── CofferdamSpotEscrow.sol          # Gig/temp escrow (check-in/out, Self.xyz)
    │   ├── CofferdamPayrollEscrow.sol       # Calendar-based payroll (Merkle-gated)
    │   └── EscrowFactory.sol                # Deploys Spot or Payroll escrows
    ├── treasury/                        # P2 — role-bound sub-treasuries
    │   └── CofferdamSubTreasuryFactory.sol  # Spending caps per role
    ├── wallet/                          # P2 — wallet binding
    │   └── CofferdamWalletBind.sol          # SSO-proof linking of existing accounts
    └── enterprise-cli/                  # Interactive CLI for testing on Anvil
        ├── lib/                             # CSV import, provisioning, Merkle, wallets
        └── menus/                           # Deploy, company, orgtree, spot, payroll, state
```

## Key Addresses

| Contract | Address |
|---|---|
| ERC-4337 EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| RIP-7212 P-256 precompile | `0x0000000000000000000000000000000000000100` |
| USDC (Base Sepolia) | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| USDC (Base mainnet) | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |

Deployed Cofferdam contract addresses are written per-network by the deploy
scripts to `deployments/<network>.json` (e.g. `deployments/baseSepolia.json`).
The account/factory/paymaster/authority stack used by the
`cofferdam-sdk` example demos lives in
`examples/capacitor-minimal/.env.local` (`VITE_NATIVE_TESTNET_*`).

## Quickstart

```bash
# Install dependencies
yarn install

# Copy env
cp .env.example .env

# Compile
yarn compile

# Start local base-anvil node (forks Base Sepolia)
# Requires base-anvil — see Local Node section below
yarn node:start

# In another terminal: deploy everything to local node
yarn deploy:all:local

# Run tests (uses hardhat in-memory node)
yarn test

# Deploy to Base Sepolia
yarn deploy:all:sepolia

# Launch enterprise CLI (requires submodule — see License Split below)
yarn enterprise:cli
```

### Local Node — base-anvil

This repo uses [base-anvil](https://github.com/base/base-anvil) for local
development instead of standard `hardhat node`. base-anvil is a fork of Foundry's
Anvil with Base-specific precompiles (B20, RIP-7212 P-256, etc.) and OP-stack
rollup features. This means local testing behaves closer to production Base.

**Install:**

```bash
curl -L https://raw.githubusercontent.com/base/base-anvil/HEAD/foundryup/install | bash
base-foundryup --install v1.1.0
```

**Start:**

```bash
# Forks Base Sepolia by default (configurable via BASE_SEPOLIA_RPC_URL)
yarn node:start
# Or: base-anvil --fork-url https://sepolia.base.org --port 8545
```

The node runs on `http://127.0.0.1:8545` with anvil's default pre-funded
accounts (account #0: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` with
10,000 ETH). All `deploy:*:local` and `cli` commands work against this node.

## Base MCP Integration

This repo is designed to work with the [Base MCP](https://docs.base.org/ai-agents/quickstart)
skill for onchain operations. The skill provides:

- **Wallet operations** — check balances, send tokens, swap
- **Batched contract calls (EIP-5792)** — `send_calls` for multi-step deployments
- **Approval flow** — every write returns an approval URL for Base Account
- **Plugin system** — Morpho, Moonwell, Uniswap, Aerodrome, etc.

### Setup

Add Base MCP to your AI assistant:

```bash
# Claude Code
claude mcp add --transport http base-mcp https://mcp.base.org

# Cursor — add to .cursor/mcp.json
{
  "mcpServers": {
    "base-mcp": { "url": "https://mcp.base.org" }
  }
}
```

### Using Base MCP with these contracts

After deploying to Base Sepolia, use `send_calls` to interact with the deployed
contracts through the ERC-4337 EntryPoint:

```
1. get_wallets → address
2. Construct UserOperation (callData = CofferdamAccount4337.execute target)
3. send_calls(chain="base-sepolia", calls=[{to: EntryPoint, data: handleOps}])
4. User approves → get_request_status(requestId)
```

See:
- [SKILL.md](https://docs.base.org/ai-agents/skills/SKILL.md) — session flow + onboarding
- [Batched calls reference](https://docs.base.org/ai-agents/skills/references/batch-calls.md) — EIP-5792 patterns
- [Approval mode](https://docs.base.org/ai-agents/skills/references/approval-mode.md) — write transaction flow
- [Custom plugins](https://docs.base.org/ai-agents/skills/references/custom-plugins.md) — extending with new protocols

## Post-Quantum Migration Path

The `IAuthorityModule` ABI is crypto-agile: a future `DilithiumAuthorityModule`
(ML-DSA-65) or `SPHINCSPlusAuthorityModule` (SLH-DSA-128s) plugs in behind the
same interface with no changes to `CofferdamAccount4337`. The tiered-authority
model supports phased migration — see `BASE_CONVERSION.md` §12.

### Gas considerations

| Signature scheme | Size | Gas impact |
|---|---|---|
| P-256 (current) | 64 B | ~6,900 verification (RIP-7212, Azul pricing) |
| Dilithium (ML-DSA-65) | ~2.7 KB | ~50k+ calldata + verification |
| SPHINCS+ (SLH-DSA-128s) | ~8 KB | ~150k+ calldata |
| Hybrid (P-256 + Dilithium) | ~2.8 KB | ~57k+ (verify both) |

## Base Preinstalled Contracts

Base has several contracts preinstalled at genesis — no deployment needed:

| Contract | Address |
|---|---|
| **ERC-4337 v0.7 EntryPoint** | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| ERC-4337 v0.7 SenderCreator | `0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C` |
| ERC-4337 v0.6 EntryPoint (legacy) | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` |
| Create2Deployer | `0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2` |
| CreateX | `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` |
| Multicall3 | `0xcA11bde05977b3631167028862bE2a173976CA11` |
| Safe | `0x69f4D1788e39c87893C980c06EdF4b7f686e2938` |

See [Base Preinstalls](https://docs.base.org/base-chain/specs/protocol/execution/evm/preinstalls) for the full list.

## B20 Native Token Standard (Beryl Hardfork)

[B20](https://docs.base.org/base-chain/specs/upgrades/beryl/b20) is Base's native token standard — ERC-20 compatible but implemented as Rust precompiles (faster, cheaper). **Beryl activates on Sepolia 2026-06-18 and mainnet 2026-06-25.**

B20 ships with a built-in compliance toolkit directly relevant to Cofferdam payroll:

| B20 Feature | Cofferdam Use Case |
|---|---|
| **Stablecoin variant** (6 decimals, fiat currency code) | USDC-equivalent for payroll settlement |
| **Transfer policies** (allowlist/blocklist via PolicyRegistry) | KYC-gated transfers — only verified workers/companies |
| **Freeze-and-seize** (`burnBlocked`) | Regulatory compliance, sanctioned account handling |
| **Memos** (`transferWithMemo`) | Payroll period references attached to settlement tx |
| **Supply caps** | Controlled token issuance |
| **Granular pause** (TRANSFER/MINT/BURN independently) | Emergency halt without locking all functionality |
| **Role-based access** (MINT/BURN/PAUSE/METADATA) | Separation of duties: treasury, payroll, compliance |
| **ERC-2612 Permit** (built-in) | Gasless token approvals — no separate Permit2 needed |
| **Rebase multiplier** (Asset variant) | RWA tokenization for future invoice/receivable financing |

### B20 vs ERC-20 USDC for Cofferdam

| Dimension | ERC-20 USDC (current) | B20 Stablecoin |
|---|---|---|
| Transfer gas | ~50k (storage + events) | Lower (Rust precompile) |
| Compliance | Custom contract logic | Built-in policies, freeze-seize |
| Payroll memo | Off-chain indexing | On-chain `transferWithMemo` |
| Pause | Whole contract | Granular (TRANSFER only) |
| Approvals | Separate Permit2 or custom | Built-in ERC-2612 |
| Circle integration | Native USDC (Fiat→USDC) | Would need B20 bridge or native issuance |

**Decision pending**: Whether to use existing ERC-20 USDC (Circle-issued, battle-tested) or deploy a B20 Stablecoin for Cofferdam payroll. B20's compliance features are compelling but Circle's USDC has liquidity and fiat on/off-ramp. A hybrid approach (USDC for settlement, B20 for compliance-gated payroll tokens) is also possible.

## Enterprise Module — Locked Design (rev-8)

> **Status:** LOCKED. This section supersedes the earlier analysis in
> `ENTERPRISE_MODULE_PLAN.md` (rev-7.4) and the "Base Simplification
> Analysis". The architecture below is the canonical design for the Cofferdam
> Enterprise Module on Base. Implementation is phased (§Phasing below) but the
> contract interfaces and provisioning flow are frozen.
>
> **Implementation:** P1 contracts are built and functional in the
> [`contracts/enterprise/`](https://github.com/cofferdamxyz/enterprise-contracts)
> submodule (private). The enterprise CLI provides a full simulation on Anvil:
> Workday CSV batch import, brick-by-brick manual org tree building, deterministic
> wallet provisioning, Merkle tree construction, on-chain root publishing, and
> complete spot/payroll escrow lifecycles. See
> [`contracts/enterprise/README.md`](contracts/enterprise/README.md) for full
> documentation with concrete examples.

### Design Principles (locked)

1. **The company wallet is not a passkey account.** It is deployed on-chain via
   `CofferdamCompanyRegistry` using **proof of domain ownership** (DNS/TXT
   record) as the gate mechanism. The IT admin proves control of `company.com`;
   Cofferdam deploys the company wallet. No human signs with a passkey for the
   company wallet — it is an institutional account managed via the Merkle-rooted
   org chart and role-bound sub-treasuries.

2. **USDC minting is off-chain and hidden from the public Base chain.** The
   company links its own Circle Digital Asset Account (DAA). Funds flow
   `Company USD ops → enterprise's own Circle DAA (Circle mints + holds custody)
   → on-chain USDC withdrawal to company wallet → role-bound sub-treasuries`.
   The Base chain sees USDC transfers, not mint/burn events. Cofferdam is never
   in the custody path.

3. **The company wallet is the root of the Merkle org tree.** Each tenant has a
   single `OrgRoot { root, generation, updatedAt }` entry in
   `CofferdamCorporateRegistry`. Leaves `(pseudonym, role, supervisor,
   costCenter, validFrom, validUntil, idpSourceRef)` are constructed directly
   from Ory Polis group memberships + supervisor relationships — Polis is the
   source of truth, not a relay. The on-chain root reveals zero org-chart
   structure — no headcount, no role distribution, no supervisor chain. Base
   Ledger keeps the org tree private at the operator level.

4. **Ory Polis is the bridge from web2 to web3.** Polis SSO provides both the
   identity layer and the org-chart data. At company onboarding, Cofferdam reads
   `user@domain.com → Role` mappings directly from Polis groups, constructs
   Merkle leaves, and updates the root in one batch tx. Workers are provisioned
   with **tier 2 (LowManaged) accounts by default** — these have spending
   flexibility (session key can move USDC) without requiring a passkey upfront.
   This gives maximum onboarding friction reduction: the worker clicks an invite,
   logs in via SSO, gets a counterfactually-deployed AA wallet, and is
   immediately mapped to their Merkle leaf. They can receive USDC, co-sign
   escrows per role, and take actions on company escrows with zero web3
   knowledge.

5. **Existing Cofferdam users can bind their account.** A worker who already
   has a Cofferdam account (tier 1 LowUntrusted or tier 3 High passkey) can link
   it to their enterprise identity via **Cofferdam Wallet Bind** — they prove
   ownership of `user@domain.com` via SSO login, and their existing wallet
   address is mapped to the company's Merkle leaf instead of provisioning a new
   account. This avoids duplicate wallets and preserves the user's existing
   passkey/authority configuration. The upgrade path is seamless: a tier 2
   SSO-provisioned account can upgrade to tier 3 (passkey) at any time, and
   further to sovereign identity via Self.xyz nullifier binding.

6. **Escrow workflows are configurable per company.** Instead of hardcoding
   "recruiter → finance → manager → worker → witness", companies define their
   own step sequence at escrow deployment via `EscrowPolicy`. A company that
   doesn't need manager approval simply omits that step. Three presets (Spot,
   Shift, Rotation) ship as defaults; companies customize from there.

7. **Net-amount-only settlement.** Gross-to-net calculation, tax tables,
   garnishment, benefits accrual, year-end forms — all delegated to the
   customer's existing payroll infrastructure (ADP, Gusto, Workday, Deel,
   Paychex). Cofferdam ingests a net-pay file or API push, fans it out into
   per-employee escrow funding, and segregates withholding totals. This is an
   integration sale, not a replacement sale.

8. **Off-boarding preserves funds, revokes enterprise capability.** When a
   worker is deactivated in Polis (SCIM `user.deactivated` event), Cofferdam
   removes their Merkle leaf and updates the root. The worker **keeps their
   wallet and any funds in it** — they can still move USDC, swap, and off-ramp.
   They simply lose access to that company's escrows, sub-treasuries, and
   role-bound actions. If the worker had bound a pre-existing Cofferdam account,
   the wallet bind is severed but the account remains fully functional as a
   personal wallet. This is a capability revocation, not a fund freeze — the
   worker's money is always theirs.

9. **Self.xyz binding is decoupled from enterprise onboarding.** Polis SSO
   gives the worker a tier 2 AA wallet at first login — sufficient for every
   company-internal on-chain action. Self.xyz nullifier binding happens later,
   opt-in, inside the Cofferdam app. Binding unlocks the sovereign upgrade path:
   cross-tenant pseudonym unlinkability, portable identity that survives
   leaving the employer, and sovereign KYC/AML at off-ramp. A worker who is
   off-boarded with a Self.xyz-bound account retains full sovereign identity
   and can continue using Cofferdam independently of any company.

### Company Provisioning Flow (locked)

```
1. IT admin proves domain ownership (DNS/TXT record) → Cofferdam
2. CofferdamCompanyRegistry.deployCompany(domainProof)
   → deploys Company Wallet on Base (institutional, not passkey)
3. Circle DAA linked off-chain (USDC mint/burn hidden from public chain)
4. Polis group sync: user@domain.com → Role → Merkle leaf
   → one batch tx updates OrgRoot in CofferdamCorporateRegistry
5. Cofferdam sends invite emails to all user@domain.com addresses

── New worker (no existing Cofferdam account) ──────────────────────────────
6a. Worker clicks invite → Polis SSO login
7a. Tier 2 (LowManaged) AA wallet auto-provisioned, deploys counterfactually
    on first UserOp (ERC-4337)
8a. Wallet address mapped to Merkle leaf (role, supervisor, cost center)
9a. CDP Paymaster sponsors gas — worker never needs ETH
10a. Worker sees dashboard: pending escrows, payroll, role-bound actions
11a. Upgrade path: tier 2 → tier 3 (passkey) → Self.xyz (sovereign) — opt-in

── Existing Cofferdam user (wallet bind) ───────────────────────────────────
6b. Worker clicks invite → Polis SSO login → proves user@domain.com ownership
7b. Worker provides existing Cofferdam wallet address (or connects via SDK)
8b. Cofferdam Wallet Bind: existing address mapped to Merkle leaf
    → no new account deployed, existing authorities preserved
9b. Worker's existing tier (1/2/3) and passkey/session config unchanged
10b. Enterprise capabilities layered on top of existing wallet

── Off-boarding (worker deactivated in Polis) ──────────────────────────────
1. Polis SCIM `user.deactivated` event → Cofferdam
2. Merkle leaf removed, OrgRoot updated in one batch tx
3. Worker's wallet and funds preserved — USDC still movable
4. Enterprise capabilities revoked: escrows, sub-treasuries, role actions
5. If wallet-bound: bind severed, personal wallet remains fully functional
6. If Self.xyz-bound: sovereign identity retained, Cofferdam works independently
```

### Two Escrow Types: Spot vs Payroll

Cofferdam has two distinct escrow contracts serving different use cases.
They share the same USDC settlement rail and `EscrowStateChanged` event schema,
but differ fundamentally in who the worker is and how payment is triggered.

#### `CofferdamSpotEscrow` — temporary / gig work

For vacancy fills, contractors, and one-off assignments. The worker is **not
an employee** — they don't have a company email, they're not in Polis, and they
don't exist in the company's Merkle org tree.

- **Identity**: Self.xyz nullifier binding (sovereign, not company-provisioned)
- **Check-in / check-out**: yes — but **called by the witness, never the worker**.
  Both are `onlyWitness`. The worker does not self-attest; that is the whole
  point of the trust model (see `escrow/SPOT_ESCROW_RULES.md` §1).
- **Funding**: one-time per assignment, **funder-only**
- **Witness**: **required** (non-zero), company-appointed, and replaceable by
  the recruiter via `setWitness` — including **mid-job**, while the worker is
  already checked in, so a supervisor rotating off shift can hand over without
  affecting the worker or any deadline. Whoever was physically present: a site
  supervisor, a shift lead, a ship's captain, a clinic manager. **May not be the
  funder** in a B2B escrow — enforced on-chain — so the party holding the money
  never certifies the work. The exception is the consumer shape, where one hirer
  is funder, recruiter and witness at once; that sets the immutable
  `selfWitnessed` flag and is the only case where the funder may retake the
  witness seat (otherwise a hirer who delegated while away could never resume).
  A witness can never redirect funds: `checkOut()` always pays the awarded
  worker, so the role carries timing authority only.
- **Who can be the worker**: anyone with a Cofferdam account + Self.xyz binding
- **Marketplace integration**: Cofferdam marketplace vacancies create Spot escrows on hire

```solidity
struct SpotEscrowPolicy {
    address funder;          // company finance wallet; only it may fund/refund
    address recruiter;       // company HR; awards the worker, sets the witness
    bytes32 workerNullifier; // Self.xyz nullifier (not a Merkle leaf)
    uint32  checkInTimeout;  // after this, the FUNDER may reclaimNoShow() in full
    uint32  checkOutTimeout; // after this, the WORKER may self-claim when the
                             // witness never checks them out (anti-wage-theft)
    address witness;         // required, non-zero; != `funder` unless selfWitnessed
    address arbiter;         // required, non-zero; neutral dispute resolver.
                             // Must differ from funder, recruiter AND witness —
                             // resolveDispute is unilateral 0-100% over the funds.
                             // May be a contract (future arbitration pool).
    uint16  killFeeBps;      // funder-cancellation fee to the worker, 500–2500
    uint256 amount;          // agreed pay; if non-zero, fund() must match exactly
    bytes32 termsHash;       // pointer to the off-chain terms the worker accepted
    uint64  jobStartTime;    // 0 = check-in window runs from creation
    uint32  disputeWindow;   // 0 = no deadline; else worker may claim a stuck dispute
}
```

Flow: `funder.FUND → recruiter.AWARD_WORKER → witness.CHECK_IN → witness.CHECK_OUT → RELEASE`

`checkOut()` transfers the full funded amount to the worker **in the same
transaction** — there is no separate approve or settle step.

> **Note on `checkOutTimeout`.** It protects the *worker*, not the company. The
> witness is company-appointed, so the risk of witness inaction has to sit with
> the company: once the timeout passes, `claimAfterCheckoutTimeout()` is
> permissionless and pays the worker. It is not an abandonment penalty.

#### `CofferdamPayrollEscrow` — recurring calendar-based payroll

For existing employees transitioning from fiat to crypto settlement. The worker
**is an employee** — they have `user@domain.com`, they're in Polis, and they're
in the company's Merkle org tree.

- **Identity**: Merkle leaf membership (company-provisioned via Polis/SCIM)
- **Check-in / check-out**: **no** — the pay period is defined by calendar dates,
  not by worker actions. The employee is already working; they don't need to
  "check in" to get their salary.
- **Funding**: recurring per pay period (weekly, biweekly, monthly)
- **Witness**: not applicable (no third-party verification needed for payroll)
- **Who can be the worker**: only workers in the company's Merkle org tree
- **Trigger**: time-based — `payPeriodStart` / `payPeriodEnd` define the window

```solidity
struct PayrollEscrowPolicy {
    bytes32 workerRole;      // Merkle leaf role hash (must be in org tree)
    uint48  payPeriodStart;  // unix seconds — period begins
    uint48  payPeriodEnd;    // unix seconds — period ends
    uint32  releaseDelay;    // seconds after payPeriodEnd before auto-release
    uint32  disputeWindow;   // dispute window after release
    bool    managerApproval; // company can require manager sign-off before release
}
```

Flow: `finance.FUND → [manager.APPROVE] → auto.RELEASE_AFTER(payPeriodEnd + releaseDelay)`

#### Shared policy primitives

```solidity
// Standardized event for all escrow transitions (both Spot and Payroll)
event EscrowStateChanged(
    uint256 indexed escrowId,
    uint8   fromState,
    uint8   toState,
    address indexed actor,
    uint64  timestamp,
    bytes32 proofHash
);
```

#### Why separate contracts

A Spot escrow is a marketplace transaction — a company fills a vacancy with a
contractor who may never work for them again. The contractor doesn't get a
company email, doesn't enter the org chart, and proves identity via Self.xyz.
Mixing this with payroll creates unnecessary complexity: check-in/check-out is
meaningless for salaried employees, and Merkle membership is meaningless for
gig workers who don't have `user@domain.com`.

Separate contracts also means separate audit trails, separate gas profiles
(Spot is low-frequency, Payroll is high-batch), and separate risk models.

### Treasury Top-Up Flow (Circle DAA Integration)

The company wallet is funded via the enterprise's own Circle Digital Asset
Account (DAA). Cofferdam never touches the custody path — Circle handles KYB,
AML, custody, and fiat↔USDC conversion at par. The flow:

```
1. Enterprise onboarded to Circle via Partner Onboarding API
   → Circle performs KYB/AML, creates DAA in the enterprise's name
   → Cofferdam receives a DAA API key (server-side, never in client)

2. Enterprise wires USD to their Circle DAA
   → Circle mints USDC 1:1 (no spread, no fee)
   → Enterprise selects Base as the DAA payout chain
   → USDC withdrawn to company wallet on Base (native USDC, not bridged)

3. Company wallet balance = on-chain USDC on Base
   → Finance officer views balance in Cofferdam dashboard
   → Can fund escrows, set Spend Permissions, batch payroll

4. Payroll funding cycle:
   a. Finance officer uploads net-pay file (from ADP/Gusto/Workday)
   b. Cofferdam pre-flight: checks company wallet USDC balance vs total due
   c. If sufficient: executeBatch() funds all escrows in one UserOp
   d. If insufficient: priority queue (overdue first, then seniority)
      → partial batch executes what's funded, rest queued
   e. Finance officer sees shortfall alert → wires more USD to Circle DAA

5. Off-ramp (worker → local fiat):
   → Worker withdraws USDC to Coinbase / MoonPay / Valora
   → Or redeems via Circle (USDC → USD → bank) if they have a Circle account
   → Cofferdam never in the off-ramp path
```

Key properties:
- **Non-custodial**: Cofferdam smart contracts govern disbursement, but no
  Cofferdam key can move enterprise funds arbitrarily. Escrow release is
  governed solely by contract logic + the `EscrowPolicy` step sequence.
- **No spread**: Circle Mint converts USD↔USDC at 1:1 with $0 fee. Cofferdam's
  revenue is a router fee billed to the enterprise, not a spread on payroll.
- **Native USDC on Base**: Circle issues native USDC on Base
  (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`), not a bridged wrapper.
  Settlement is final on Base L2, no L1 wait.
- **CCTP for cross-chain**: If an enterprise needs USDC on another chain
  (e.g. for a worker on a different L2/L1), Circle's burn-and-mint CCTP handles
  it — no third-party bridge.

### Dispute Resolution

Every `EscrowStep` includes a `disputeWindow` (seconds). After a step
completes, a designated dispute authority can revert the transition within the
window. Zero means no dispute window (trusted flow). For production escrows,
Cofferdam recommends:

- **Check-out → Release**: 48h dispute window. A manager or Cofferdam
  arbitration multisig (Cofferdam + company + neutral) can revert if the
  worker disputes the settlement amount.
- **Fund → Approve**: 24h dispute window. Finance can claw back if the funding
  amount was incorrect.
- **Auto-release (timeout)**: 72h dispute window. Longer because the worker
  wasn't expecting manual release and may not be monitoring.

### Emergency Controls

`CofferdamCorporateRegistry.pauseCompany(domain)` — circuit breaker that
freezes all escrows for a company. Triggered if:
- Domain proof is revoked (company loses their domain)
- Security breach detected (compromised session key)
- Regulatory hold (court order)

This is **company-level**, not worker-level. Individual worker off-boarding
removes their Merkle leaf but doesn't pause the company.

### Base Primitives Adopted

| Enterprise concept | Base/Cofferdam primitive |
|---|---|
| Company wallet | `CofferdamCompanyRegistry` (domain-proof gated, institutional) |
| Treasury top-up | Circle DAA → native USDC on Base (non-custodial, at par) |
| Recruiter / automated actions | Session key (LowUntrusted tier) or Spend Permissions |
| Finance officer | Passkey authority (High tier) — signs UserOp to fund escrow |
| Manager approval | Optional `EscrowStep` — disabled if not needed |
| Worker identity | `NullifierRegistry` binding (Self.xyz, opt-in) |
| Worker check-in/out | Worker's own `CofferdamAccount4337` calls escrow directly |
| Gas for workers | CDP Paymaster (ERC-7677, hosted) sponsors UserOps |
| AI agent payments | x402 via session key — agent pays for APIs using company USDC |
| Payroll batch | `executeBatch()` with pre-flight balance check + priority queue |
| Spending limits | Base Spend Permissions or `SessionKeyAuthority` with caps |
| Dispute resolution | `EscrowStep.disputeWindow` + Cofferdam arbitration multisig |
| Emergency freeze | `CofferdamCorporateRegistry.pauseCompany(domain)` |
| Transfer compliance | B20 PolicyRegistry (allowlist/blocklist) — Phase 3 |
| Payroll privacy | Base Ledger (confidential, off-explorer) — Phase 3 |
| Cross-chain USDC | Circle CCTP (burn-and-mint, no third-party bridge) |

### Contract Inventory

| Contract | Status | Notes |
|---|---|---|
| `CofferdamAccount4337` | ✅ Built | ERC-4337 account with tiered authority |
| `CofferdamAccountFactory4337` | ✅ Built | CREATE2 deterministic deployment |
| `CofferdamPaymaster` | ✅ Stub | Dev/test only — production uses CDP. `postOp` uses the EntryPoint **v0.7** 4-arg signature (`mode, context, actualGasCost, actualUserOpFeePerGas`); the v0.6 3-arg shape reverts (`PostOpReverted`) under v0.7 |
| `PasskeyAuthority` | ✅ Built | P-256 via RIP-7212 precompile |
| `WebAuthnPasskeyAuthority` | ✅ Built | Full WebAuthn assertion verification |
| `SessionKeyAuthority` | ✅ Built | ECDSA session-signer bridge (legacy auth) |
| `NullifierRegistry` | ✅ Built | Self.xyz passport nullifier → account binding |
| `SelfAttesterRegistry` | ✅ Built | TEE attester allowlist |
| `MockGroth16Verifier` | ✅ Built | Always-true verifier for mock testing |
| `IB20Factory` | ✅ Interface | B20 + PolicyRegistry interfaces |
| `CofferdamCompanyRegistry` | ✅ Built | `contracts/enterprise/company/` — proprietary submodule. Domain-proof company registration + pause |
| `CofferdamCorporateRegistry` | ✅ Built | `contracts/enterprise/company/` — proprietary submodule. Merkle OrgRoot + witness delegation + `pauseCompany` |
| `CofferdamSpotEscrow` | ✅ Built | `contracts/enterprise/escrow/` — proprietary submodule. Gig/temporary escrow, check-in/out, Self.xyz identity |
| `CofferdamPayrollEscrow` | ✅ Built | `contracts/enterprise/escrow/` — proprietary submodule. Calendar-based payroll, Merkle-gated, no check-in/out |
| `EscrowFactory` | ✅ Built | `contracts/enterprise/escrow/` — proprietary submodule. Deploys Spot or Payroll escrows per use case |
| `CofferdamSubTreasuryFactory` | ⚠️ P2 Skeleton | `contracts/enterprise/treasury/` — proprietary submodule. Role-bound sub-treasuries (Spend Permissions first) |
| `CofferdamWalletBind` | ⚠️ P2 Skeleton | `contracts/enterprise/wallet/` — proprietary submodule. SSO-proof linking of existing Cofferdam accounts |
| Enterprise CLI | ✅ Built | `contracts/enterprise/enterprise-cli/` — Workday CSV import, manual org tree builder, wallet provisioning, escrow lifecycle |

### Architecture Diagram

```
┌──────────────── Cofferdam app (RN) + cofferdam-pages (web) ─────────────────┐
│  Passkey (Secure Enclave / StrongBox, P-256)  ──►  Base Account SDK          │
│  Self.xyz NFC passport  ──►  TEE prover (cofferdam-prover)                   │
│  cofferdam-attester (Worker)  ──►  session attestation + nullifier bind sig │
└───────────────┬──────────────────────────────────────────────┬─────────────┘
                │                                                │
                ▼                                                ▼
┌──────────────────────────── Base (L2, chainId 8453) ─────────────────────────┐
│                                                                              │
│  COMPANY     = CofferdamCompanyRegistry (domain-proof gated, institutional)  │
│       └─ Merkle OrgRoot in CofferdamCorporateRegistry (role verification)   │
│       └─ Treasury: Circle DAA → native USDC on Base (non-custodial, at par) │
│       └─ Top-up: USD wire → Circle mints → withdraw to company wallet       │
│       └─ Payroll: executeBatch() with pre-flight balance + priority queue   │
│       └─ Sub-treasuries: Spend Permissions (P1) or Safe (P2, if needed)     │
│       └─ Emergency: pauseCompany(domain) circuit breaker                    │
│                                                                              │
│  WORKER      = CofferdamAccount4337 (ERC-4337) — AuthorityManagerBase       │
│       └─ owners: P-256 passkeys (RIP-7212) + Session keys (LowUntrusted)   │
│       └─ Provisioned via SCIM → Merkle leaf → SSO invite → auto-deploy      │
│       └─ Gas sponsored by CDP Paymaster (worker never needs ETH)            │
│                                                                              │
│  IDENTITY    = NullifierRegistry + SelfAttesterRegistry (opt-in, not gate)  │
│  SPOT ESCROW = CofferdamSpotEscrow (gig/temp, check-in/out, Self.xyz)       │
│  PAY ESCROW  = CofferdamPayrollEscrow (calendar, Merkle-gated, no check-in) │
│  GAS         = CDP Paymaster (hosted, ERC-7677) — NO custom contract         │
│  COMPLIANCE  = B20 PolicyRegistry (allowlist/blocklist) — for B20 tokens     │
│  LEDGER      = Base Ledger (confidential payroll, off-explorer) — Phase 3   │
│  AI AGENTS   = x402 via session key (capped USDC Spend Permissions)          │
│                                                                              │
│  ELIMINATED:  Custom paymaster contract, Merkle privacy (Base Ledger),      │
│              Safe factory deployment, hardcoded escrow workflows             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Phasing (simplified)

| Phase | Contracts | Base Primitives | What we drop |
|---|---|---|---|
| **P1** | `CofferdamCompanyRegistry`, `CofferdamCorporateRegistry` (Merkle root + `pauseCompany`), `CofferdamSpotEscrow`, `CofferdamPayrollEscrow`, `EscrowFactory`, Circle DAA integration (Partner Onboarding + top-up flow) | ERC-4337 EntryPoint v0.7, CDP sponsored gas, native USDC on Base | ~~Sub-treasories~~, ~~wallet bind~~, ~~B20~~, ~~single configurable contract~~ |
| **P2** | `CofferdamWalletBind`, Spend Permission integration, `CofferdamSubTreasuryFactory` (if needed) | Spend Permissions, Sub Accounts, ERC-7677 USDC gas payments | |
| **P3** | Base Ledger payroll module (behind interface), B20 compliance tokens | Base Ledger (confidential payroll), B20 PolicyRegistry | |
| **P4** | x402 agent Sub Accounts, AI agent escrow steps | Capped USDC Spend Permissions for AI agents, Base MCP `send_calls` | |

### Implementation Mapping on Base Primitives

Concrete plan for how each Cofferdam component maps to Base's native primitives.

#### Company Wallet Deployment (`CofferdamCompanyRegistry`)

Base preinstalls `Create2Deployer` at `0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2`.
Our registry uses CREATE2 to deterministically deploy company wallets from
domain-proof-gated initialization. The company wallet address is computable
before deployment via `computeAddress(keccak256(domain), bytecodeHash)`.

**Base constraint:** ERC-4337 smart accounts cannot use the `CREATE` opcode
for contract deployment. All deployments must use CREATE2 via the preinstalled
deployer or our own factory. `CofferdamAccountFactory4337` already does this.

#### Worker Wallet Provisioning (Tier 2 accounts)

Two approaches, both compatible with our architecture:

**Option A — `CofferdamAccountFactory4337` (P1, what we have):** Deploy a
standalone `CofferdamAccount4337` with `SessionKeyAuthority` (tier 2). The
worker's wallet is independent of the company — better for off-boarding (funds
stay with worker). Gas sponsored by CDP Paymaster.

**Option B — Base Account Sub Accounts (P2 optimization):** Use
`wallet_addSubAccount` to create a Sub Account linked to the company's Base
Account, funded via Spend Permissions:

```typescript
const subAccount = await provider.request({
  method: 'wallet_addSubAccount',
  params: [{
    account: {
      type: 'create',
      keys: [{ type: 'address', publicKey: companyWalletAddress }]
    }
  }]
});
```

Sub Accounts (ERC-7895) give the company tighter control but couple the
worker's wallet to the company's Base Account. We use Option A for P1 to
preserve the "worker keeps their wallet" off-boarding property.

#### Gas Sponsorship (CDP Paymaster)

CDP Paymaster via `paymasterService` capability in `wallet_sendCalls`:

```typescript
await provider.request({
  method: 'wallet_sendCalls',
  params: [{
    version: '1.0',
    chainId: '0x2105',
    from: workerAddress,
    calls: [{ to: escrowAddress, data: checkInCalldata }],
    capabilities: {
      paymasterService: {
        url: "https://paymaster.base.org/api/v1/sponsor"
      }
    }
  }]
});
```

CDP Paymaster allowlist is configured to sponsor:
- `CofferdamSpotEscrow.checkIn()` / `checkOut()`
- `CofferdamPayrollEscrow` (worker read-only calls)
- `CofferdamAccountFactory4337.createAccount()` (wallet deployment)

**ERC-20 Paymaster (USDC for gas):** Base supports paying gas in USDC via
ERC-7677. The company can pay gas in USDC instead of ETH — no ETH treasury
needed. Workers never see gas. See [ERC-20 Paymasters](https://docs.base.org/base-account/improve-ux/sponsor-gas/erc20-paymasters)
and [Paymaster Implementation Guide](https://docs.base.org/base-account/improve-ux/sponsor-gas/paymasters).

#### Treasury Top-Up (Circle DAA → Base)

Native USDC on Base (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`), Circle
Mint support, CCTP for cross-chain. The flow:

1. Enterprise wires USD to their Circle DAA
2. Circle mints USDC 1:1 (no spread, no fee)
3. Enterprise selects Base as the DAA payout chain
4. USDC withdrawn to company wallet on Base (native, not bridged)

**Worker off-ramp:** Workers use `base.pay()` to send USDC to any address, or
use Coinbase / MoonPay / Valora to convert to fiat. Cofferdam is never in the
off-ramp path.

#### Spend Permissions (replacing SessionKeyAuthority long-term)

Base's native `SpendPermissionManager` — EIP-712 signed, on-chain enforced:

```typescript
const permission = await requestSpendPermission({
  account: companyWalletAddress,
  spender: financeOfficerAddress,
  token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
  chainId: 8453,
  allowance: 100_000n,  // $100k per period (in token units)
  period: 2592000,       // 30 days in seconds
  provider: sdk.getProvider(),
});
```

The `SpendPermission` struct (`account`, `spender`, `token`, `allowance`,
`period`, `start`, `end`, `salt`, `extraData`) maps directly to our role-bound
sub-treasury concept. A finance officer gets a monthly cap. An AI agent gets a
smaller cap. No sub-Safe deployment needed. See [Spend Permissions](https://docs.base.org/base-account/improve-ux/spend-permissions)
and the [contract reference](https://docs.base.org/base-account/reference/onchain-contracts/spend-permissions).

**P1:** Keep `SessionKeyAuthority` (already built). **P2:** Migrate to Spend
Permissions for companies using Base Account SDK.

#### Batched Payroll (EIP-5792)

`wallet_sendCalls` with atomic batching:

```typescript
await provider.request({
  method: 'wallet_sendCalls',
  params: [{
    version: '2.0',
    atomicRequired: true,
    from: companyWalletAddress,
    calls: [
      { to: escrow1, data: fundCalldata(worker1, amount1) },
      { to: escrow2, data: fundCalldata(worker2, amount2) },
      // ... N escrows in one atomic batch
    ],
    capabilities: {
      paymasterService: { url: paymasterUrl }
    }
  }]
});
```

All escrows fund atomically — either all succeed or all fail. Capability
detection via `wallet_getCapabilities` checks if the wallet supports atomic
batching before attempting it. Fallback to sequential `eth_sendTransaction`
for EOAs.

#### Base Ledger for Payroll Privacy (P3)

Base Ledger provides a confidential transaction layer:

- **Encrypted deposits:** Recipient is encrypted on-chain, only ledger
  operator can decrypt. Deposits to the same worker are unlinkable.
- **Private balances:** Internal transfers are off-chain, hidden from
  public explorer.
- **Withdrawals:** Reveal asset + amount but **not the sender**. Deposits
  and withdrawals stay unlinkable.
- **Composable:** Deposit/withdraw are on-chain contract calls, can be
  batched with other Base actions in one transaction.

How this maps to Cofferdam payroll:

```
Company wallet → Base Ledger deposit (encrypted recipient = worker)
  → Ledger internal transfer (private, off-explorer)
  → Worker withdraws from Ledger to their wallet on Base
    (on-chain: shows USDC amount, not which company paid them)
```

This replaces our Merkle-tree privacy argument for payroll amounts. The org
chart stays private because deposits don't reveal the recipient, internal
transfers are off-chain, and withdrawals don't reveal the sender. Only the
ledger operator (Cofferdam) can see the mapping.

Base docs explicitly list "Payroll & Payouts: Run onchain payroll without
publishing what every employee or contractor earns" as a supported use case.
See [Base Ledgers — Use cases](https://docs.base.org/ledgers/overview#use-cases)
and [How it works](https://docs.base.org/ledgers/how-it-works).

#### x402 for AI Agent Payments (P4)

Base MCP supports x402 payment protocol:

1. AI agent calls x402-enabled API endpoint
2. API returns HTTP 402 with payment requirements
3. Base MCP initiates payment from agent's wallet (capped Spend Permission)
4. User approves → API receives USDC → returns response

This maps to our autonomous escrow — an AI agent with a capped Spend
Permission can pay for APIs (background checks, identity verification,
credential validation) using company USDC, without human approval per tx.

#### Implementation Priority Matrix

| Component | Base Primitive | What we build | Phase |
|---|---|---|---|
| Company wallet | `Create2Deployer` (preinstalled) | `CofferdamCompanyRegistry` (domain proof + CREATE2) | P1 |
| Worker wallets | `CofferdamAccountFactory4337` (built) | Tier 2 provisioning via Polis SSO | P1 |
| Gas | CDP Paymaster (`paymasterService` capability) | Allowlist config for escrow calls | P1 |
| USDC settlement | Native USDC on Base + Circle DAA | Circle Partner Onboarding integration | P1 |
| Spot escrow | ERC-4337 + `execute()` | `CofferdamSpotEscrow` (check-in/out, Self.xyz) | P1 |
| Payroll escrow | ERC-4337 + time-based release | `CofferdamPayrollEscrow` (calendar, Merkle-gated) | P1 |
| Batch payroll | `wallet_sendCalls` (EIP-5792 atomic) | Pre-flight balance check + priority queue | P1 |
| Dispute resolution | `EscrowStep.disputeWindow` | Cofferdam arbitration multisig | P1 |
| Emergency freeze | `CofferdamCorporateRegistry.pauseCompany` | Circuit breaker | P1 |
| Spend Permissions | `SpendPermissionManager` (native) | P2 migration from `SessionKeyAuthority` | P2 |
| Wallet bind | SSO proof + Merkle leaf update | `CofferdamWalletBind` | P2 |
| Sub-treasuries | Spend Permissions or Safe | `CofferdamSubTreasuryFactory` (if needed) | P2 |
| Payroll privacy | Base Ledger (encrypted deposit/withdraw) | Ledger integration behind interface | P3 |
| B20 compliance | B20 PolicyRegistry | Compliance tokens | P3 |
| AI agent payments | x402 + capped Spend Permissions | Agent escrow step | P4 |

#### Base Constraints to Respect

1. **No `CREATE` opcode** in ERC-4337 accounts — use CREATE2 only (we already do)
2. **ERC-6492** for counterfactual signatures — `isValidSignature` already supports this
3. **RIP-7212** P-256 precompile at `0x100` — `PasskeyAuthority` already uses this
4. **EntryPoint v0.7** at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` — already configured
5. **CDP Paymaster is ERC-7677 compliant** — no custom paymaster contract needed in production
6. **ERC-20 Paymaster** — gas can be paid in USDC, no ETH treasury required

## Base Account Integration

Cofferdam accounts are designed to be compatible with the [Base Account](https://docs.base.org/base-account/overview/what-is-base-account)
ecosystem. Base Account is an ERC-4337 Smart Wallet that gives every user
universal passkey sign-on, one-tap USDC payments, and multi-chain support.
See [What is a Base Account?](https://docs.base.org/base-account/overview/what-is-base-account).

- **ERC-6492 counterfactual signatures**: `isValidSignature` supports ERC-6492 wrapped signatures for undeployed accounts. Viem's `verifyMessage` / `verifyTypedData` handle the wrapper automatically.
- **Sub Account import**: `addOwnerAddress` / `addOwnerPublicKey` mirror the Coinbase Smart Wallet pattern, allowing Cofferdam accounts to be imported as Sub Accounts via `wallet_addSubAccount`.
- **CDP Paymaster**: Production gas sponsorship uses the Coinbase-hosted ERC-7677 paymaster via `paymasterService` capability in `wallet_sendCalls` — no onchain paymaster contract needed.
- **Spend Permissions**: Base's native `SpendPermissionManager` supports recurring period-based token allowances (EIP-712 structured, ERC-6492 compatible). Relevant for future payroll escrow replacement. See [Spend Permissions](https://docs.base.org/base-account/reference/onchain-contracts/spend-permissions).
- **Permit2**: Preinstalled at `0x000000000022D473030F116dDEE9F6B43aC78BA3` for token approvals.
- **EntryPoint v0.7**: Preinstalled at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` — used as the primary EntryPoint for all Cofferdam accounts.
- **"Login with Base" (passkey reuse)**: Users with an existing Base Account (e.g. Coinbase wallet) can onboard to Cofferdam without registering a new passkey. The flow:
  1. User authenticates via Base Account SDK (`createBaseAccountSDK` → `eth_requestAccounts`), which verifies their existing passkey.
  2. Cofferdam reads the user's passkey public key from their Base Account.
  3. A new `CofferdamAccount4337` is deployed via `CofferdamAccountFactory4337` with `WebAuthnPasskeyAuthority` using that same passkey as the High-tier authority.
  4. The Cofferdam account is independent — it has its own ratchet, authority model, and is not controlled by Coinbase. The Coinbase passkey simply becomes the Cofferdam passkey.
  5. No EIP-7702 delegation is used; the Cofferdam account is a standalone deployed smart account with no EOA backdoor.
  - **Status**: Not yet implemented. Requires Base Account SDK integration in the client app and a passkey-public-key extraction step. See [Base Account SDK](https://docs.base.org/base-account/reference/core/createBaseAccount).

## License

MIT. Copyright 2026 Cofferdam Inc.
