import { inspect, newState, rollbackPay, ShieldConfig } from "./shield.js";
const cfg: ShieldConfig = { allowlist: new Set(["ownerdest", "payrolldest"]), maxFractionBps: 5000, recurringPayees: new Set(["payrolldest"]) };
// drip: 10 кусков по 9 из 100
const st = newState(100n); let moved = 0n, blockedAt = -1;
for (let i = 0; i < 20; i++) {
  const d = inspect({ kind: "eth_transfer", to: "attacker", asset: "ETH", amount: 9n, balance: 100n - moved }, cfg, st);
  if (!d.allow) { blockedAt = i + 1; console.log("drip БЛОК на куске", i + 1, "| ушло", moved.toString(), "|", d.reason); break; }
  moved += 9n;
}
if (blockedAt < 0) console.log("drip НЕ остановлен (ушло", moved.toString(), ")");
console.log("swap 25% :", inspect({ kind: "swap", to: "pool", asset: "ETH", amount: 0n, balance: 100n, slippageBps: 2500 }, cfg).reason);
console.log("swap 1%  :", inspect({ kind: "swap", to: "pool", asset: "ETH", amount: 0n, balance: 100n, slippageBps: 100 }, cfg).allow);
console.log("легит→owner 40:", inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 40n, balance: 100n }, cfg, newState(100n)).allow);
console.log("approve unlim :", inspect({ kind: "approve", to: "drainer", asset: "USDC", amount: 0n, balance: 0n, unlimited: true }, cfg).reason);

// --- gap-closing rules (SPEC §4): handover / bridge / durable-nonce ---
console.log("setAuthority→atk :", inspect({ kind: "set_authority", to: "attacker", asset: "SOL", amount: 0n, balance: 100n }, cfg).reason);
console.log("spl_delegate→atk :", inspect({ kind: "spl_delegate", to: "attacker", asset: "USDC", amount: 0n, balance: 100n }, cfg).reason);
console.log("set_code→atk     :", inspect({ kind: "set_code", to: "attacker", asset: "ETH", amount: 0n, balance: 100n, provenance: "untrusted_data" }, cfg).reason);
console.log("bridge→atk       :", inspect({ kind: "bridge", to: "attacker", asset: "USDC", amount: 100n, balance: 100n }, cfg).reason);
console.log("durable_nonce    :", inspect({ kind: "durable_nonce", to: "attacker", asset: "SOL", amount: 5n, balance: 100n }, cfg).reason);
// no over-block: handing authority to an ALLOWLISTED dest is allowed
console.log("setAuthority→owner (allow?):", inspect({ kind: "set_authority", to: "ownerDest", asset: "SOL", amount: 0n, balance: 100n }, cfg).allow);

// --- idempotency / duplicate payment (attack class from Clearance; guard-owned, not agent-owned) ---
const idA = newState(100n);
inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 20n, balance: 100n }, cfg, idA); // first pay
console.log("dup retry (same amount):", inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 20n, balance: 100n }, cfg, idA).reason);
const idB = newState(100n);
inspect({ kind: "eth_transfer", to: "payrollDest", asset: "ETH", amount: 20n, balance: 100n }, cfg, idB);
console.log("honest recurring (owner-authorized) allow?:", inspect({ kind: "eth_transfer", to: "payrollDest", asset: "ETH", amount: 20n, balance: 100n }, cfg, idB).allow);
const idC = newState(100n);
inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 20n, balance: 100n }, cfg, idC);
console.log("two invoices (diff amount) allow?:", inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 35n, balance: 100n }, cfg, idC).allow);

// --- G39 lookalike payee (Clearance): 2% to a non-allowlisted dest slips under the 50% caps ---
console.log("G39 lookalike, default   (allow?):", inspect({ kind: "eth_transfer", to: "sh0pDest", asset: "ETH", amount: 2n, balance: 100n }, cfg, newState(100n)).allow, "  (expected true — under caps)");
const strict: ShieldConfig = { ...cfg, strictAllowlist: true };
console.log("G39 lookalike, STRICT    :", inspect({ kind: "eth_transfer", to: "sh0pDest", asset: "ETH", amount: 2n, balance: 100n }, strict, newState(100n)).reason);
console.log("strict: allowlisted dest (allow?):", inspect({ kind: "eth_transfer", to: "ownerDest", asset: "ETH", amount: 2n, balance: 100n }, strict, newState(100n)).allow, "  (expected true)");

// --- rollbackPay: an allowed payment that FAILS on chain must not block the honest retry ---
const rb = newState(100n);
const pay = { kind: "eth_transfer" as const, to: "ownerDest", asset: "ETH", amount: 20n, balance: 100n };
inspect(pay, cfg, rb);            // allowed, recorded
rollbackPay(rb, pay, cfg);        // chain send reverted → undo the record
console.log("retry after rollback (allow?):", inspect(pay, cfg, rb).allow, "  (expected true — not a phantom duplicate)");
