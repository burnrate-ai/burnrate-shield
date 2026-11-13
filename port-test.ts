import { inspect, newState, ShieldConfig } from "./shield.js";
const cfg: ShieldConfig = { allowlist: new Set(["ownerdest"]), maxFractionBps: 5000 };
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
