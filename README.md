# burnrate-shield

Агент-агностичный **containment-слой** для AI-агентов, управляющих кошельком: инспектирует предлагаемую транзакцию и разрешает/блокирует по правилам, которые агент не может переопределить.

## Правила (`shield.ts`)
- **provenance** — блок, если действие выведено из untrusted-данных
- **allowlist** — получатель не в белом списке
- **approval-cap** — unlimited / non-allowlisted approve
- **drain** — вывод ≥ доли баланса (`maxFractionBps`)
- **velocity** — накопленный отток ≥ `velocityCapBps` от стартового баланса
- **slippage** — своп со slippage выше `maxSlippageBps`
- **handover** — `setAuthority`/`assign`, SPL `delegate`, EIP-7702 `set_code`: передача контроля над аккаунтом не-allowlisted стороне (instruction-level, баланс в транзе не двигается)
- **bridge gate** — вывод через мост не на allowlisted-получателя (allowlist по локальному адресу мост не покрывает)
- **deferred-exec block** — durable-nonce / отложенное исполнение: pre-sign guard не может перепроверить транзу позже → блок как класс

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

Статус пробелов: setAuthority/assign, SPL delegate, set-code, bridge-эксфил и durable-nonce — ЗАКРЫТЫ (правила handover / bridge gate / deferred-exec block). Остаток и обоснование — `burnrate-bench/SPEC.md` §4. Метрика бенча после фикса: 0.8% ущерба проходит (было ~49%).
