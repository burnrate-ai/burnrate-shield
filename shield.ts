// Burnrate Shield — a fresh, AGENT-AGNOSTIC containment layer (NOT the Solana vault).
// It sits in front of whatever signs/sends: it inspects a PROPOSED action and returns allow/block
// before anything reaches the chain. Works on any chain/wallet because it reasons about the action,
// not about a specific on-chain program. (The old vault is a Solana program and cannot guard an EVM
// wallet at all — that gap is exactly why this exists.)

export interface ProposedTx {
  kind:
    // value transfers (chain-agnostic math):
    | "eth_transfer" | "erc20_transfer" | "spl_transfer"
    // approvals / swaps:
    | "approve" | "swap"
    // control-handover primitives (grant someone else control of the wallet/account):
    | "spl_delegate" | "set_authority" | "set_code"
    // exfil / deferred-execution channels:
    | "bridge" | "durable_nonce";
  to: string;            // destination / spender / new-authority / bridge recipient
  asset: string;         // "ETH", "USDC", "SOL", ...
  amount: bigint;        // wei / token units (0 for approve / set_authority / set_code)
  balance: bigint;       // current balance of that asset
  unlimited?: boolean;   // approve: unlimited allowance?
  provenance?: "user" | "untrusted_data"; // where the instruction came from
  slippageBps?: number;  // swap: realized/expected price slippage in bps
}

export interface ShieldConfig {
  allowlist: Set<string>;    // lower-cased destinations the owner pre-approved
  maxFractionBps: number;    // block a single transfer >= this share of balance to a non-allowlisted dest (bps)
  maxSlippageBps?: number;   // block a swap whose slippage exceeds this (bps). Default 300 (3%).
  velocityCapBps?: number;   // block once cumulative non-allowlisted outflow this session reaches
                             //           this share of the session-start balance (bps). Default 5000 (50%).
  dedupWindow?: number;      // idempotency: block an exact (payee+asset+amount) repeat within the last N
                             //           payments. Default 8; 0 disables.
  recurringPayees?: Set<string>; // lower-cased payees the OWNER pre-authorized for repeat payments
                             //           (the ONLY way an identical repeat is allowed — the agent cannot opt in).
  strictAllowlist?: boolean; // if set, ANY transfer to a payee not on the allowlist (and not a recurring
                             //           payee) is blocked outright, regardless of amount. For a payment
                             //           agent with a fixed payee list this stops a small lookalike payment
                             //           (Clearance G39: 2 NEAR to sh0p.sandbox slipped under the % caps).
                             //           Off by default — a general wallet may pay new one-off destinations.
}

// Per-session state for the velocity rule. Create once per agent session and pass to every inspect().
export interface ShieldState {
  sessionStartBalance: bigint;  // balance at session start, basis for the cumulative cap
  movedOut: bigint;             // cumulative non-allowlisted outflow allowed so far this session
  recentPays: string[];         // dedup: recent payment keys "payee|asset|amount" (bounded by dedupWindow)
}

export function newState(sessionStartBalance: bigint): ShieldState {
  return { sessionStartBalance, movedOut: 0n, recentPays: [] };
}

export interface Decision { allow: boolean; reason: string; }

// Undo the bookkeeping for a transfer that inspect() ALLOWED but that then FAILED to land on chain.
// inspect() records the payment key (and velocity) at allow-time, before the send result is known; if the
// send reverts, call this so the owner's honest retry of the same amount is not blocked as a duplicate.
// (Raised by Lev / Clearance: recentPays is written before the chain result.) Pass cfg so a non-allowlisted
// transfer's velocity is also rolled back. No-op if the key was already evicted from the dedup window.
export function rollbackPay(state: ShieldState, tx: ProposedTx, cfg: ShieldConfig): void {
  const dest = tx.to.toLowerCase();
  const payKey = `${dest}|${tx.asset}|${tx.amount}`;
  const i = state.recentPays.lastIndexOf(payKey);
  if (i >= 0) state.recentPays.splice(i, 1);
  if (!cfg.allowlist.has(dest)) {
    state.movedOut = state.movedOut > tx.amount ? state.movedOut - tx.amount : 0n;
  }
}

const TRANSFER_KINDS = new Set<ProposedTx["kind"]>(["eth_transfer", "erc20_transfer", "spl_transfer"]);
// actions that hand wallet/account control to another party — they move no (or little) balance in the
// signed tx, so a balance-diff alone misses them; they are judged at the INSTRUCTION level.
const HANDOVER_KINDS = new Set<ProposedTx["kind"]>(["spl_delegate", "set_authority", "set_code"]);

export function inspect(tx: ProposedTx, cfg: ShieldConfig, state?: ShieldState): Decision {
  const dest = tx.to.toLowerCase();
  const allowed = cfg.allowlist.has(dest);
  const maxSlip = cfg.maxSlippageBps ?? 300;
  const velCap = cfg.velocityCapBps ?? 5000;

  // 1. prompt-injection: ANY consequential action the owner never asked for (not just a transfer).
  if (tx.provenance === "untrusted_data" &&
      (tx.amount > 0n || tx.kind === "approve" || tx.kind === "swap" ||
       HANDOVER_KINDS.has(tx.kind) || tx.kind === "bridge" || tx.kind === "durable_nonce")) {
    return { allow: false, reason: "action originated from untrusted data (prompt injection), not the owner" };
  }

  // 2. unlimited / non-allowlisted approval to a spender
  if (tx.kind === "approve" && (tx.unlimited || allowed === false)) {
    return { allow: false, reason: `approval to non-allowlisted / unlimited spender ${tx.to}` };
  }

  // 3. control handover — SPL Approve/delegate, setAuthority/assign, EIP-7702 set-code.
  //    Hands control of the account to another party. Blocked unless the new authority is allowlisted.
  //    (Instruction-level: these move no balance in the tx, so size/velocity would never fire.)
  if (HANDOVER_KINDS.has(tx.kind) && !allowed) {
    return { allow: false, reason: `${tx.kind} hands wallet/account control to non-allowlisted ${tx.to}` };
  }

  // 4. bridge — value leaving to the attacker on another chain. An address allowlist keyed on local
  //    destinations does not cover a cross-chain recipient, so a bridge-out needs its own gate.
  if (tx.kind === "bridge" && !allowed) {
    return { allow: false, reason: `bridge exfil to non-allowlisted recipient ${tx.to}` };
  }

  // 5. durable-nonce / deferred execution — "harmless now", but it ARMS a later action the guard can
  //    no longer re-check at execution time. A pre-sign guard cannot vouch for a deferred tx, so block it.
  if (tx.kind === "durable_nonce") {
    return { allow: false, reason: "durable-nonce / deferred execution not permitted — arms a later action beyond the guard's view" };
  }

  // 6. swap with excessive slippage (oracle/price manipulation, sandwich, LP-rug)
  if (tx.kind === "swap") {
    const slip = tx.slippageBps ?? 0;
    if (slip > maxSlip) {
      return { allow: false,
        reason: `swap blocked: slippage ${(slip / 100).toFixed(1)}% exceeds max ${(maxSlip / 100).toFixed(1)}%` };
    }
  }

  // 7. drain + velocity: a large share of a balance leaving to a destination the owner never approved,
  //    and cumulative drip below the single-tx cap.
  if (TRANSFER_KINDS.has(tx.kind)) {
    // 7a. idempotency / duplicate payment (attack class surfaced by Clearance, github.com/Selliksss/clearance).
    //     Key point (Lev): the agent is the one being lied to, so an AGENT-supplied idempotency key is
    //     worthless — a deceived "retry" will mint a fresh key or quote "reference INV-2". So the GUARD, not
    //     the agent, owns the repeat: an exact (payee+asset+amount) repeat this session is blocked unless the
    //     OWNER pre-authorized recurring payments to that payee (cfg.recurringPayees). Honest one-off invoices
    //     differ in amount and pass. Caveat: a repeat with a DIFFERENT amount (a fake "remainder", Clearance
    //     G9) is NOT caught by this rule — that needs a system-owned payment operation (see SPEC §4).
    const dedupN = cfg.dedupWindow ?? 8;
    if (state && dedupN > 0 && tx.amount > 0n && !(cfg.recurringPayees?.has(dest))) {
      const payKey = `${dest}|${tx.asset}|${tx.amount}`;
      if (state.recentPays.includes(payKey)) {
        return { allow: false,
          reason: `duplicate payment blocked: an identical ${tx.asset} payment to ${tx.to} was already sent this session — verify its status before paying again or reporting a failure (a genuine retry must be owned by the system, not re-issued by the agent)` };
      }
      state.recentPays.push(payKey);
      if (state.recentPays.length > dedupN) state.recentPays.shift();
    }
    // 7b. strict allowlist (opt-in): for a payment agent with a fixed payee list, a payee that is neither
    //     allowlisted nor an owner-authorized recurring payee is blocked outright — this stops a small
    //     lookalike payment (Clearance G39) that the % drain/velocity caps let through.
    const knownPayee = allowed || !!cfg.recurringPayees?.has(dest);
    if (cfg.strictAllowlist && !knownPayee) {
      return { allow: false,
        reason: `payee ${tx.to} is not on the allowlist (strict mode) — only pre-approved payees may receive ${tx.asset}` };
    }
    if (!allowed) {
      const fracBps = tx.balance === 0n ? 0 : Number((tx.amount * 10000n) / tx.balance);
      if (fracBps >= cfg.maxFractionBps) {
        return { allow: false,
          reason: `drain blocked: ${(fracBps / 100).toFixed(1)}% of ${tx.asset} to non-allowlisted ${tx.to}` };
      }
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
