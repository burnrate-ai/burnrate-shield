# burnrate-shield

![version](https://img.shields.io/badge/version-0.1.0-orange) ![License](https://img.shields.io/badge/License-MIT-green) ![node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen) ![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue) ![agent-agnostic](https://img.shields.io/badge/agent-agnostic-blueviolet) ![networks](https://img.shields.io/badge/networks-EVM%20%2B%20Solana%20%2B%20NEAR-blueviolet)

> An agent-agnostic **containment layer** for AI agents that control a wallet: it inspects a proposed transaction and allows or blocks it by rules the agent cannot override — before anything reaches the chain.

## Rules (`shield.ts`)
- **provenance** — block if the action was derived from untrusted data
- **allowlist** — recipient not on the owner's allowlist
- **approval-cap** — unlimited / non-allowlisted approve
- **drain** — outflow ≥ a share of the balance (`maxFractionBps`)
- **velocity** — cumulative outflow ≥ `velocityCapBps` of the session-start balance
- **slippage** — a swap with slippage above `maxSlippageBps`
- **handover** — `setAuthority`/`assign`, SPL `delegate`, EIP-7702 `set_code`: hands account control to a non-allowlisted party (instruction-level; no balance moves in the tx)
- **bridge gate** — a bridge-out to a non-allowlisted recipient (an address allowlist does not cover a bridge)
- **deferred-exec block** — durable-nonce / deferred execution: a pre-sign guard cannot re-check it later → blocked as a class
- **dedup (idempotency)** — an exact repeat of a recent payment (same payee + asset + amount) is blocked as a replay (e.g. agent told "payment failed, pay again"). **Guard-owned:** an agent-supplied idempotency key is *not* trusted — the agent is the one being deceived — so the only way an identical repeat passes is an owner-authorized recurring payee (`recurringPayees`). Honest one-off invoices differ in amount and pass. Attack class surfaced by [Clearance](https://github.com/Selliksss/clearance)
- **strict allowlist** (`strictAllowlist`, opt-in) — for a payment agent with a fixed payee list, any payee not allowlisted (and not a recurring payee) is blocked regardless of amount; stops a small lookalike payment that sits under the drain/velocity caps (Clearance **G39**)
- **`rollbackPay(state, tx, cfg)`** — the dedup key is recorded at allow-time, before the on-chain result; if the signed send reverts, call this so the owner's honest retry is not blocked as a phantom duplicate

```ts
import { inspect, newState } from "./shield.js";
const d = inspect(tx, cfg, newState(tx.balance));
if (!d.allow) block(d.reason);
```

## NEAR adapter

`near-adapter.ts` maps a NEAR agent's wallet tool-call (`ft_transfer`, native `Transfer`, `AddKey`, bridge calls) into a `ProposedTx`, so the **same rules** gate a NEAR agent:

```ts
import { inspectNear } from "./near-adapter.js";
const d = inspectNear({ method: "ft_transfer", asset: "wrap.near",
  args: { receiver_id: "alice.near", amount: "20" }, balance: "100" }, cfg, state);
```

## Tests
```
npx tsx port-test.ts   # rule checks
npx tsx fp-test.ts     # no false positives on legitimate actions
npx tsx near-test.ts   # NEAR adapter: drain / handover / bridge / dedup all gated
```

## Ecosystem
- **[burnrate-bench](../burnrate-bench)** — independent benchmark (spec + results)

Gap status: setAuthority/assign, SPL delegate, set-code, bridge exfil and durable-nonce are CLOSED (handover / bridge gate / deferred-exec rules). Residuals and rationale: `burnrate-bench/SPEC.md` §4. Bench metric after the fix: 0.8% of modelled loss gets through (was ~49%).
