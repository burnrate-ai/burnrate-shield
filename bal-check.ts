import { readFileSync } from "node:fs";
import { createPublicClient, http, formatEther } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

async function main() {
  const kd: any = JSON.parse(readFileSync("./.testnet-key.json", "utf8")).data;
  const K = Array.isArray(kd) ? kd[0] : kd;
  const PK: any = Object.values(K).find((v: any) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v));
  const acc = privateKeyToAccount(PK);
  const c = createPublicClient({ chain: sepolia, transport: http("https://ethereum-sepolia-rpc.publicnode.com") });
  const b = await c.getBalance({ address: acc.address });
  console.log("ADDR", acc.address, "BAL", formatEther(b), "ETH");
}
main().catch((e) => console.error("ERR", e.message));
