// NEAR adapter for Burnrate Shield — maps a NEAR agent's wallet tool-call into a ProposedTx so the
// SAME chain-agnostic rules (drain, velocity, approval, handover, bridge, deferred-exec, dedup) gate a
// NEAR agent. Built for Path B: run a NEAR agent bare and behind the Shield against Clearance.
//
// NEAR amounts are strings in minimal units (yoctoNEAR = 1e-24 NEAR; NEP-141 tokens use their own
// decimals). The caller supplies the current balance in the SAME units as the amount it reports.

import { inspect, ShieldConfig, ShieldState, ProposedTx, Decision } from "./shield.js";

export interface NearCall {
  method: string;                 // "ft_transfer" | "ft_transfer_call" | "Transfer" | "AddKey" | "FunctionCall" | ...
  receiverId?: string;            // the contract/account the call targets (token id, or payee for native)
  args?: Record<string, any>;     // decoded call args (receiver_id, amount, public_key, permission, msg, memo, ...)
  deposit?: string;               // attached NEAR deposit in yocto (native transfers)
  balance?: string;               // current balance of the relevant asset (same units as the amount); default "0"
  asset?: string;                 // "NEAR" or the token contract id (e.g. "wrap.near")
  provenance?: "user" | "untrusted_data";
  idempotencyKey?: string;        // dedup: e.g. an invoice id; honest repeats carry a fresh one
  bridgeIds?: string[];           // optional: known bridge/locker account ids to flag as exfil
  swapTargets?: string[];         // optional: known DEX/router ids for ft_transfer_call swaps
}

const DEFAULT_BRIDGES = ["aurora", "rainbow_bridge.near", "factory.bridge.near", "deltatrade.near"];
const DEFAULT_SWAPS = ["v2.ref-finance.near", "ref-finance.near", "v1.jumbo_exchange.near"];

// Map one NEAR tool-call to a ProposedTx, or null if it moves no value / is nothing to gate.
export function nearToProposedTx(c: NearCall): ProposedTx | null {
  const balance = BigInt(c.balance ?? "0");
  const base = { balance, provenance: c.provenance, idempotencyKey: c.idempotencyKey };
  const bridges = new Set([...(c.bridgeIds ?? []), ...DEFAULT_BRIDGES]);
  const swaps = new Set([...(c.swapTargets ?? []), ...DEFAULT_SWAPS]);

  // NEP-141 token transfer
  if (c.method === "ft_transfer" || c.method === "ft_transfer_call") {
    const token = c.asset ?? c.receiverId ?? "token";
    const to = String(c.args?.receiver_id ?? "");
    const amount = BigInt(c.args?.amount ?? "0");
    // ft_transfer_call into a DEX/router = a swap (slippage must be supplied by the caller; no quote here)
    if (c.method === "ft_transfer_call" && swaps.has(to)) {
      return { kind: "swap", to, asset: token, amount: 0n, slippageBps: Number(c.args?.slippageBps ?? 0), ...base };
    }
    // transfer to a bridge/locker = cross-chain exfil
    if (bridges.has(to)) return { kind: "bridge", to, asset: token, amount, ...base };
    return { kind: "erc20_transfer", to, asset: token, amount, ...base };
  }

  // native NEAR transfer (a Transfer action, deposit in yocto)
  if (c.method === "Transfer" || c.method === "native_transfer" || c.method === "send_near") {
    const to = String(c.receiverId ?? c.args?.receiver_id ?? "");
    const amount = BigInt(c.deposit ?? c.args?.amount ?? "0");
    if (bridges.has(to)) return { kind: "bridge", to, asset: "NEAR", amount, ...base };
    return { kind: "eth_transfer", to, asset: "NEAR", amount, ...base };
  }

  // access-key grant = handing control of the account (NEAR's authority handover)
  if (c.method === "AddKey" || c.method === "add_key" || c.method === "add_full_access_key") {
    const perm = c.args?.permission ?? c.args?.access_key?.permission;
    const fullAccess = !perm || perm === "FullAccess";
    const to = String(c.args?.public_key ?? c.receiverId ?? "new-key");
    // full-access key = owner reassignment; a function-call key to a contract = delegation
    return fullAccess
      ? { kind: "set_authority", to, asset: "NEAR", amount: 0n, ...base }
      : { kind: "spl_delegate", to: String(perm?.receiver_id ?? c.receiverId ?? to), asset: "NEAR", amount: 0n, ...base };
  }

  // DeployContract / stake / delete_key / storage_deposit / view calls — no value-move the shield models.
  return null;
}

// Convenience: map + inspect in one call. Returns allow for calls that aren't value-moving.
export function inspectNear(c: NearCall, cfg: ShieldConfig, state?: ShieldState): Decision {
  const tx = nearToProposedTx(c);
  if (!tx) return { allow: true, reason: "no value-moving action to gate" };
  return inspect(tx, cfg, state);
}
