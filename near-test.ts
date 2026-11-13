// NEAR adapter check — the same shield rules gate NEAR tool-calls.
import { inspectNear, NearCall } from "./near-adapter.js";
import { newState, ShieldConfig } from "./shield.js";

const cfg: ShieldConfig = { allowlist: new Set(["alice.near", "payroll.near"]), maxFractionBps: 5000, recurringPayees: new Set(["payroll.near"]) };
const ok = (d: { allow: boolean }) => (d.allow ? "allow" : "BLOCK");

// native drain to a non-allowlisted account
console.log("native drain → attacker :", ok(inspectNear(
  { method: "Transfer", receiverId: "attacker.near", deposit: "100", balance: "100" }, cfg, newState(100n))));

// full-access key grant = handover
console.log("add full-access key     :", ok(inspectNear(
  { method: "AddKey", args: { public_key: "ed25519:att...", permission: "FullAccess" }, balance: "100" }, cfg, newState(100n))));

// bridge-out
console.log("ft_transfer → bridge     :", ok(inspectNear(
  { method: "ft_transfer", receiverId: "wrap.near", asset: "wrap.near", args: { receiver_id: "aurora", amount: "100" }, balance: "100" }, cfg, newState(100n))));

// injection: value move from untrusted data
console.log("ft_transfer (injected)   :", ok(inspectNear(
  { method: "ft_transfer", asset: "wrap.near", args: { receiver_id: "attacker.near", amount: "30" }, balance: "100", provenance: "untrusted_data" }, cfg, newState(100n))));

// Clearance idempotency class on NEAR: "payment failed, pay alice again" — same payee, same amount, no key
const dup = newState(100n);
inspectNear({ method: "ft_transfer", asset: "wrap.near", args: { receiver_id: "alice.near", amount: "20" }, balance: "100" }, cfg, dup);
console.log("duplicate pay → alice    :", ok(inspectNear(
  { method: "ft_transfer", asset: "wrap.near", args: { receiver_id: "alice.near", amount: "20" }, balance: "100" }, cfg, dup)));

// honest recurring payroll: same payee & amount, but the OWNER authorized recurringPayees → allowed
const ren = newState(100n);
inspectNear({ method: "ft_transfer", asset: "wrap.near", args: { receiver_id: "payroll.near", amount: "20" }, balance: "100" }, cfg, ren);
console.log("honest recurring payroll :", ok(inspectNear(
  { method: "ft_transfer", asset: "wrap.near", args: { receiver_id: "payroll.near", amount: "20" }, balance: "100" }, cfg, ren)));
