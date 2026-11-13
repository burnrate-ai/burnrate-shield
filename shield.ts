// Burnrate Shield — a fresh, AGENT-AGNOSTIC containment layer (NOT the Solana vault).
// It sits in front of whatever signs/sends: it inspects a PROPOSED action and returns allow/block
// before anything reaches the chain. Works on any chain/wallet because it reasons about the action,
// not about a specific on-chain program. (The old vault is a Solana program and cannot guard an EVM
// wallet at all — that gap is exactly why this exists.)

export interface ProposedTx {
  kind: "eth_transfer" | "erc20_transfer" | "approve" | "swap";
  to: string;            // destination / spender / pool
  asset: string;         // "ETH", "USDC", ...
  amount: bigint;        // wei / token units (0 for a pure swap spec)
  balance: bigint;       // current balance of that asset
  unlimited?: boolean;   // approve: unlimited allowance?
  provenance?: "user" | "untrusted_data"; // where the instruction came from
  slippageBps?: number;  // swap: realized/expected price slippage in bps
}

export interface ShieldConfig {
  allowlist: Set<string>;    // lower-cased destinations the owner pre-approved
  maxFractionBps: number;    // block a single transfer >= this share of balance to a non-allowlisted dest (bps)
  maxSlippageBps?: number;   // G4: block a swap whose slippage exceeds this (bps). Default 300 (3%).
  velocityCapBps?: number;   // velocity: block once cumulative non-allowlisted outflow this session reaches
                             //           this share of the session-start balance (bps). Default 5000 (50%).
}

// Per-session state for the velocity rule. Create once per agent session and pass to every inspect().
export interface ShieldState {
  sessionStartBalance: bigint;  // balance at session start, basis for the cumulative cap
  movedOut: bigint;             // cumulative non-allowlisted outflow allowed so far this session
}

export function newState(sessionStartBalance: bigint): ShieldState {
  return { sessionStartBalance, movedOut: 0n };
}

export interface Decision { allow: boolean; reason: string; }

export function inspect(tx: ProposedTx, cfg: ShieldConfig, state?: ShieldState): Decision {
  const dest = tx.to.toLowerCase();
  const allowed = cfg.allowlist.has(dest);
  const maxSlip = cfg.maxSlippageBps ?? 300;
  const velCap = cfg.velocityCapBps ?? 5000;

  // 1. prompt-injection: a value-moving action the owner never asked for
  if (tx.provenance === "untrusted_data" && (tx.amount > 0n || tx.kind === "approve" || tx.kind === "swap")) {
    return { allow: false, reason: "action originated from untrusted data (prompt injection), not the owner" };
  }
  // 2. unlimited / non-allowlisted approval to a spender
  if (tx.kind === "approve" && (tx.unlimited || allowed === false)) {
    return { allow: false, reason: `approval to non-allowlisted / unlimited spender ${tx.to}` };
  }
  // 3. G4 — swap with excessive slippage (oracle/price manipulation, sandwich, LP-rug)
  if (tx.kind === "swap") {
    const slip = tx.slippageBps ?? 0;
    if (slip > maxSlip) {
      return { allow: false,
        reason: `swap blocked: slippage ${(slip / 100).toFixed(1)}% exceeds max ${(maxSlip / 100).toFixed(1)}%` };
    }
  }
  // 4. drain: a large share of a balance leaving to a destination the owner never approved
  if (tx.kind === "eth_transfer" || tx.kind === "erc20_transfer") {
    if (!allowed) {
      const fracBps = tx.balance === 0n ? 0 : Number((tx.amount * 10000n) / tx.balance);
      if (fracBps >= cfg.maxFractionBps) {
        return { allow: false,
          reason: `drain blocked: ${(fracBps / 100).toFixed(1)}% of ${tx.asset} to non-allowlisted ${tx.to}` };
      }
      // 5. velocity — defeats sub-threshold "drip" drains that each pass rule 4.
      if (state) {
        const prospective = state.movedOut + tx.amount;
        const basis = state.sessionStartBalance;
        const cumBps = basis === 0n ? 0 : Number((prospective * 10000n) / basis);
        if (cumBps >= velCap) {
          return { allow: false,
            reason: `velocity blocked: cumulative ${(cumBps / 100).toFixed(1)}% of session-start ${tx.asset} to non-allowlisted dests` };
        }
        state.movedOut = prospective; // record only allowed non-allowlisted outflow
      }
    }
  }
  return { allow: true, reason: "within policy" };
}
