// Burnrate Shield — a fresh, AGENT-AGNOSTIC containment layer (NOT the Solana vault).
// It sits in front of whatever signs/sends: it inspects a PROPOSED action and returns allow/block
// before anything reaches the chain. Works on any chain/wallet because it reasons about the action,
// not about a specific on-chain program. (The old vault is a Solana program and cannot guard an EVM
// wallet at all — that gap is exactly why this exists.)
//
// Hardening pass (red-team R1-R12, see burnrate-attacker catalog): provenance is now FAIL-CLOSED (R11),
// inputs are validated (R12), the dedup key is recorded only AFTER the action is allowed and keyed on a
// canonical asset over an unbounded per-session set (R8/R2/R5), rollback only undoes recorded state (R9),
// and optional ceilings bound even trusted destinations and the swap/bridge value channel (R1/R4).

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
  provenance?: "user" | "owner" | "untrusted_data" | string; // where the instruction came from
  slippageBps?: number;  // swap: realized/expected price slippage in bps
}

export interface ShieldConfig {
  allowlist: Set<string>;    // lower-cased destinations the owner pre-approved
  maxFractionBps: number;    // block a single transfer >= this share of balance to a non-allowlisted dest (bps)
  maxSlippageBps?: number;   // block a swap whose slippage exceeds this (bps). Default 300 (3%).
  velocityCapBps?: number;   // block once cumulative non-allowlisted outflow this session reaches
                             //           this share of the session-start balance (bps). Default 5000 (50%).
  dedupWindow?: number;      // idempotency: >0 enables guard-owned dedup for this session (unbounded within the
                             //           session — no eviction, so a flood of blocked txs can't flush it). 0 disables.
  recurringPayees?: Set<string>; // lower-cased payees the OWNER pre-authorized for repeat payments
                             //           (the ONLY way an identical repeat is allowed — the agent cannot opt in).
  strictAllowlist?: boolean; // ANY transfer to a payee not on the allowlist (and not a recurring payee)
                             //           is blocked outright. ON BY DEFAULT. Set `false` for a general wallet.
  trustedMaxFractionBps?: number; // R1 (opt-in): a HARD ceiling applied even to an ALLOWLISTED payee — a single
                             //           transfer/bridge >= this share of balance is blocked regardless of trust.
                             //           Undefined = off (allowlisted payees are unbounded, the legacy behavior).
  maxSwapFractionBps?: number;    // R4 (opt-in): block a single swap whose input amount >= this share of balance.
                             //           Undefined = off (swaps gated by slippage only, the legacy behavior).
  trustedProvenances?: Set<string>; // R11: labels treated as owner-authored. Default {"user","owner"}. Anything
                             //           else that is EXPLICITLY set is treated as untrusted (fail-closed).
}

// Per-session state. Create once per agent session and pass to every inspect().
export interface ShieldState {
  sessionStartBalance: bigint;  // balance at session start, basis for the cumulative cap
  movedOut: bigint;             // cumulative non-allowlisted outflow allowed so far this session
  recentPays: string[];         // dedup: ordered log of RECORDED (allowed) payment keys, canonical (FIFO, capped — R13)
  seen: Set<string>;            // dedup: authoritative set of recorded keys (bounded FIFO — R2 kept flush-proof by R8, R13 caps growth)
}

// R13: cap the dedup window so a long session (or a flood of allowlisted distinct-amount pays, which skip the
// drain/velocity caps) cannot grow `seen`/`recentPays` without bound → memory DoS. Safe because R8 records a key
// ONLY after an action is ALLOWED, so evicting the oldest key costs the attacker DEDUP_WINDOW_CAP *genuine* allowed
// payments — the cheap "flush with blocked txs" vector (R2) stays closed; only a replay separated by that many
// distinct allowed pays can recur, which is operationally irrelevant for idempotency.
export const DEDUP_WINDOW_CAP = 4096;

export function newState(sessionStartBalance: bigint): ShieldState {
  return { sessionStartBalance, movedOut: 0n, recentPays: [], seen: new Set<string>() };
}

export interface Decision { allow: boolean; reason: string; }

const TRANSFER_KINDS = new Set<ProposedTx["kind"]>(["eth_transfer", "erc20_transfer", "spl_transfer"]);
const HANDOVER_KINDS = new Set<ProposedTx["kind"]>(["spl_delegate", "set_authority", "set_code"]);

// Canonicalize an asset label so "USDC", "usdc", "USDC " and fullwidth forms map to one dedup key (R5).
function canonAsset(a: string): string { return (a ?? "").normalize("NFKC").trim().toLowerCase(); }
function payKeyOf(tx: ProposedTx): string { return `${tx.to.toLowerCase()}|${canonAsset(tx.asset)}|${tx.amount}`; }

// Is this instruction NOT owner-authored? FAIL-CLOSED (R11): only labels in trustedProvenances (default
// {"user","owner"}) are trusted; any OTHER explicitly-set label ("untrusted_data", "tool", "", a typo, …)
// is untrusted. An omitted (undefined) provenance keeps the legacy "caller asserts owner origin" contract.
function isUntrusted(tx: ProposedTx, cfg: ShieldConfig): boolean {
  if (tx.provenance === undefined) return false;
  const trusted = cfg.trustedProvenances ?? new Set(["user", "owner"]);
  return !trusted.has(tx.provenance);
}

// Undo the bookkeeping for a transfer that inspect() ALLOWED (and therefore RECORDED) but that then FAILED
// to land on chain. R9: only undoes state that was actually recorded — a rollback for a key that is not in
// `seen` (fabricated, already-rolled-back, or never-allowed) is a no-op and NEVER moves movedOut. The caller
// must invoke this only on a genuine send failure (that remains an integration-contract obligation).
export function rollbackPay(state: ShieldState, tx: ProposedTx, cfg: ShieldConfig): void {
  const dest = tx.to.toLowerCase();
  const payKey = payKeyOf(tx);
  if (!state.seen.has(payKey)) return;            // not a recorded pay → nothing to undo (R9)
  state.seen.delete(payKey);
  const i = state.recentPays.lastIndexOf(payKey);
  if (i >= 0) state.recentPays.splice(i, 1);
  if (!cfg.allowlist.has(dest)) {                 // velocity was only charged for non-allowlisted outflow
    state.movedOut = state.movedOut > tx.amount ? state.movedOut - tx.amount : 0n;
  }
}

export function inspect(tx: ProposedTx, cfg: ShieldConfig, state?: ShieldState): Decision {
  const dest = tx.to.toLowerCase();
  const allowed = cfg.allowlist.has(dest);
  const maxSlip = cfg.maxSlippageBps ?? 300;
  const velCap = cfg.velocityCapBps ?? 5000;

  // 0. INPUT VALIDATION (R12) — reject malformed inputs instead of letting them slip through a comparison.
  if (tx.amount < 0n) return { allow: false, reason: "invalid negative amount" };
  if (tx.kind === "swap" && tx.slippageBps != null && !Number.isFinite(tx.slippageBps)) {
    return { allow: false, reason: "invalid non-finite slippage" };
  }

  // 1. prompt-injection: ANY consequential action not authored by the owner (R11: fail-closed provenance).
  if (isUntrusted(tx, cfg) &&
      (tx.amount > 0n || tx.kind === "approve" || tx.kind === "swap" ||
       HANDOVER_KINDS.has(tx.kind) || tx.kind === "bridge" || tx.kind === "durable_nonce")) {
    return { allow: false, reason: "action did not originate from the owner (untrusted provenance / prompt injection)" };
  }

  // 2. unlimited / non-allowlisted approval to a spender
  if (tx.kind === "approve" && (tx.unlimited || allowed === false)) {
    return { allow: false, reason: `approval to non-allowlisted / unlimited spender ${tx.to}` };
  }

  // 3. control handover — blocked unless the new authority is allowlisted (instruction-level).
  if (HANDOVER_KINDS.has(tx.kind) && !allowed) {
    return { allow: false, reason: `${tx.kind} hands wallet/account control to non-allowlisted ${tx.to}` };
  }

  // 4. bridge — value leaving to another chain. Allowlist-gated, plus an optional hard size ceiling (R1/R4).
  if (tx.kind === "bridge") {
    if (!allowed) return { allow: false, reason: `bridge exfil to non-allowlisted recipient ${tx.to}` };
    if (cfg.trustedMaxFractionBps != null && overFraction(tx, cfg.trustedMaxFractionBps)) {
      return { allow: false, reason: `bridge blocked: exceeds the trusted ceiling of ${(cfg.trustedMaxFractionBps / 100).toFixed(1)}% of balance` };
    }
  }

  // 5. durable-nonce / deferred execution — a pre-sign guard cannot vouch for a deferred tx, so block it.
  if (tx.kind === "durable_nonce") {
    return { allow: false, reason: "durable-nonce / deferred execution not permitted — arms a later action beyond the guard's view" };
  }

  // 6. swap — slippage gate + optional size ceiling on the value leaving via the swap channel (R4).
  if (tx.kind === "swap") {
    const slip = tx.slippageBps ?? 0;
    if (slip > maxSlip) {
      return { allow: false, reason: `swap blocked: slippage ${(slip / 100).toFixed(1)}% exceeds max ${(maxSlip / 100).toFixed(1)}%` };
    }
    if (cfg.maxSwapFractionBps != null && overFraction(tx, cfg.maxSwapFractionBps)) {
      return { allow: false, reason: `swap blocked: input ${(cfg.maxSwapFractionBps / 100).toFixed(1)}%+ of balance exceeds the per-swap cap` };
    }
  }

  // 7. transfers — trusted ceiling, dedup (record only on allow), strict allowlist, drain + velocity.
  if (TRANSFER_KINDS.has(tx.kind)) {
    // 7.0 overdraw / degenerate balance (R12): you cannot send more than you hold (also closes balance==0).
    if (tx.amount > tx.balance) {
      return { allow: false, reason: `transfer blocked: amount ${tx.amount} exceeds balance ${tx.balance} (invalid)` };
    }
    // 7a. hard ceiling even for an ALLOWLISTED/recurring payee (R1, opt-in): no single transfer may exceed it.
    if (cfg.trustedMaxFractionBps != null && overFraction(tx, cfg.trustedMaxFractionBps)) {
      return { allow: false, reason: `transfer blocked: exceeds the trusted ceiling of ${(cfg.trustedMaxFractionBps / 100).toFixed(1)}% of balance` };
    }

    const dedupN = cfg.dedupWindow ?? 8;
    const dedupOn = !!state && dedupN > 0 && tx.amount > 0n && !(cfg.recurringPayees?.has(dest));
    const payKey = payKeyOf(tx);

    // 7b. duplicate CHECK (not record): an exact (payee+canonicalAsset+amount) repeat this session is blocked
    //     unless the owner pre-authorized recurring payments to that payee.
    if (dedupOn && state!.seen.has(payKey)) {
      return { allow: false,
        reason: `duplicate payment blocked: an identical ${tx.asset} payment to ${tx.to} was already sent this session — verify its status before paying again (a genuine retry must be owned by the system, not re-issued by the agent)` };
    }

    // 7c. strict allowlist.
    const knownPayee = allowed || !!cfg.recurringPayees?.has(dest);
    if (cfg.strictAllowlist !== false && !knownPayee) {
      return { allow: false, reason: `payee ${tx.to} is not on the allowlist (strict mode) — only pre-approved payees may receive ${tx.asset}` };
    }

    // 7d. drain + velocity for non-allowlisted destinations.
    if (!allowed) {
      const fracBps = tx.balance === 0n ? 0 : Number((tx.amount * 10000n) / tx.balance);
      if (fracBps >= cfg.maxFractionBps) {
        return { allow: false, reason: `drain blocked: ${(fracBps / 100).toFixed(1)}% of ${tx.asset} to non-allowlisted ${tx.to}` };
      }
      if (state) {
        const prospective = state.movedOut + tx.amount;
        const basis = state.sessionStartBalance;
        const cumBps = basis === 0n ? 0 : Number((prospective * 10000n) / basis);
        if (cumBps >= velCap) {
          return { allow: false, reason: `velocity blocked: cumulative ${(cumBps / 100).toFixed(1)}% of session-start ${tx.asset} to non-allowlisted dests` };
        }
        state.movedOut = prospective; // record only allowed non-allowlisted outflow
      }
    }

    // 7e. RECORD the dedup key ONLY now, after the action has passed every gate (R8 — a blocked transfer
    //     never pollutes the window, so it can neither be flushed for free nor cause a later false-block).
    if (dedupOn) {
      state!.seen.add(payKey);
      state!.recentPays.push(payKey);
      if (state!.recentPays.length > DEDUP_WINDOW_CAP) {    // R13: bounded FIFO — evict the oldest recorded key
        const evicted = state!.recentPays.shift()!;         // (each key is unique in the window, so delete is exact)
        state!.seen.delete(evicted);
      }
    }
  }

  return { allow: true, reason: "within policy" };
}

// amount >= bps-share of balance? (shared by the trusted ceiling and the swap cap)
function overFraction(tx: ProposedTx, bps: number): boolean {
  if (tx.balance === 0n) return tx.amount > 0n;
  return Number((tx.amount * 10000n) / tx.balance) >= bps;
}
