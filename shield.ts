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
  idempotencyKey?: string; // dedup: a fresh key marks a genuinely NEW payment; a repeat without one is a replay
}

export interface ShieldConfig {
  allowlist: Set<string>;    // lower-cased destinations the owner pre-approved
  maxFractionBps: number;    // block a single transfer >= this share of balance to a non-allowlisted dest (bps)
  maxSlippageBps?: number;   // block a swap whose slippage exceeds this (bps). Default 300 (3%).
  velocityCapBps?: number;   // block once cumulative non-allowlisted outflow this session reaches
                             //           this share of the session-start balance (bps). Default 5000 (50%).
  dedupWindow?: number;      // idempotency: block an exact (payee+asset+amount) repeat within the last N
                             //           payments unless it carries a NEW idempotency key. Default 8; 0 disables.
}

// Per-session state for the velocity rule. Create once per agent session and pass to every inspect().
export interface ShieldState {
  sessionStartBalance: bigint;  // balance at session start, basis for the cumulative cap
  movedOut: bigint;             // cumulative non-allowlisted outflow allowed so far this session
  recentPays: string[];         // dedup: recent payment keys "payee|asset|amount" (bounded by dedupWindow)
  seenIdem: Set<string>;        // dedup: idempotency keys already used this session
}

export function newState(sessionStartBalance: bigint): ShieldState {
  return { sessionStartBalance, movedOut: 0n, recentPays: [], seenIdem: new Set() };
}

export interface Decision { allow: boolean; reason: string; }

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
    // 7a. idempotency / duplicate payment (attack class surfaced by Clearance, github.com/Selliksss/clearance):
    //     an exact repeat of a recent payment to the SAME payee, with no fresh idempotency key, is a replay
    //     (e.g. the agent is told "payment failed, pay again"). A genuine repeat — a new invoice or a renewal —
    //     carries a NEW idempotency key and passes, so honest same-payee tasks are not blocked.
    const dedupN = cfg.dedupWindow ?? 8;
    if (state && dedupN > 0 && tx.amount > 0n) {
      const payKey = `${dest}|${tx.asset}|${tx.amount}`;
      const freshKey = tx.idempotencyKey !== undefined && !state.seenIdem.has(tx.idempotencyKey);
      if (freshKey) {
        state.seenIdem.add(tx.idempotencyKey as string);
      } else if (state.recentPays.includes(payKey)) {
        return { allow: false,
          reason: `duplicate payment blocked: identical ${tx.asset} amount to ${tx.to} already paid this session, no new idempotency key (retry/replay)` };
      }
      state.recentPays.push(payKey);
      if (state.recentPays.length > dedupN) state.recentPays.shift();
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
