# burnrate-shield

![version](https://img.shields.io/badge/version-0.1.0-orange) ![License](https://img.shields.io/badge/License-MIT-green) ![node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen) ![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue) ![agent-agnostic](https://img.shields.io/badge/agent-agnostic-blueviolet)

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

```ts
import { inspect, newState } from "./shield.js";
const d = inspect(tx, cfg, newState(tx.balance));
if (!d.allow) block(d.reason);
```

## Tests
```
npx tsx port-test.ts   # rule checks
npx tsx fp-test.ts     # no false positives on legitimate actions
```

## Ecosystem
- **[burnrate-bench](../burnrate-bench)** — independent benchmark (spec + results)

Gap status: setAuthority/assign, SPL delegate, set-code, bridge exfil and durable-nonce are CLOSED (handover / bridge gate / deferred-exec rules). Residuals and rationale: `burnrate-bench/SPEC.md` §4. Bench metric after the fix: 0.8% of modelled loss gets through (was ~49%).
