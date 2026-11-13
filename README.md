# burnrate-shield

Агент-агностичный **containment-слой** для AI-агентов, управляющих кошельком: инспектирует предлагаемую транзакцию и разрешает/блокирует по правилам, которые агент не может переопределить.

## Правила (`shield.ts`)
- **provenance** — блок, если действие выведено из untrusted-данных
- **allowlist** — получатель не в белом списке
- **approval-cap** — unlimited / non-allowlisted approve
- **drain** — вывод ≥ доли баланса (`maxFractionBps`)
- **velocity** — накопленный отток ≥ `velocityCapBps` от стартового баланса
- **slippage** — своп со slippage выше `maxSlippageBps`

```ts
import { inspect, newState } from "./shield.js";
const d = inspect(tx, cfg, newState(tx.balance));
if (!d.allow) block(d.reason);
```

## Тесты
```
npx tsx port-test.ts   # проверка правил
npx tsx fp-test.ts     # отсутствие ложных срабатываний на легитимных действиях
```

## Экосистема
- **[burnrate-bench](../burnrate-bench)** — независимый бенчмарк (спека + результаты)
- наступательная часть (красный агент) — приватна, не публикуется

Известные пробелы и порядок починки: см. `burnrate-bench/SPEC.md` §4 (setAuthority/assign, bridge-эксфил, durable-nonce).
