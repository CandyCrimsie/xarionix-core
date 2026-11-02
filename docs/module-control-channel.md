# Outbound control channel v1

## Check-in и состояние

POST `/api/v1/module-agent/check-in`: instance_id, **integer protocol_version=1**, health=healthy/degraded/error, bounded agent_version. Last seen задаёт Core, timestamp клиента отсутствует. Connected означает свежий control heartbeat, не доказанную доступность бизнес-API. Invalid protocol получает 422 и не продлевает heartbeat.

Derived state: revoked service/instance → revoked; disabled → disabled; нет/старый heartbeat → stale; healthy fresh → connected; degraded/error fresh → error. Scheduler, переписывающий status, не нужен.

| Core env variable | Default / границы |
|---|---|
| `XARIONIX_MODULES_AUDIENCE` | xarionix-core-modules; отличается от human audience |
| `XARIONIX_MODULES_CHECK_IN_SECONDS` | 15; 1–120 s |
| `XARIONIX_MODULES_STALE_SECONDS` | 90; 10–900 s и ≥ двух intervals |
| `XARIONIX_MODULES_LEASE_SECONDS` | 30; 5–120 s |

Настройки передаются через `.env`/Compose и валидируются installer/Core. Слишком ранний check-in — 429. Rate limit хранится в instance row, работает между workers. Unknown/disabled/revoked service не допускается; JWKS cooldown ограничивает refresh amplification.

## Команды и надёжность

Только `ping` и `get_status`: никаких shell/Python/URL/download handlers. Platform Admin с MFA создаёт команду с TTL 10–3600 s (default 300); очередь instance ≤100 незавершённых неистёкших команд. Check-in возвращает ≤10. UUID/operation/expiry/attempt/request_id сохраняются в PostgreSQL.

Instance `FOR UPDATE` сериализует его pollers; commands блокируются в той же короткой транзакции. После COMMIT: delivered, attempts+1, lease_until. До конца lease другой poller ту же команду не получает; после — возможна redelivery, максимум пять. TTL/исчерпание попыток → expired. SQL cleanup не загружает всю историю в Python.

ACK требует commands.ack, свой instance/command. Result — строгий discriminated union: pong, безопасные status fields или фиксированный error code; нет произвольных HTML/logs/secret payloads. Command/result должны соответствовать. Истёкшая/не доставленная команда — 409. Успешный ACK и audit атомарны; идентичный повтор — 200 без второго effect/audit, другой result — 409. Уже завершённая команда остаётся идемпотентной после TTL: expiry запрещает новое выполнение, не отменяет сохранённый результат.

Семантика **at-least-once**, не exactly-once. Lost check-in response → redelivery после lease. Lost ACK response → тот же результат повторно. Агент держит ограниченный cache 256 results и pending ACK до expiry. После restart cache теряется, но ping/get_status сами не имеют опасных side effects. Новые неидемпотентные операции требуют persistent inbox/idempotency и отдельного security review.

## Locks и транзакции

JWT/JWKS проверяется **до** DB-транзакции → service FOR SHARE → instance FOR UPDATE (metadata — SHARE) → scope/command row. Revoke: service FOR UPDATE. Admin сохраняет administration lock; scope change берёт существующий company lock до instance. Heartbeat не берёт administration/settings/company lock. Независимые instances параллельны; pool явно ограничен 5 + 10 overflow connections на процесс.

В транзакции нет network callback/ожидания команды. Short polling сразу возвращает ответ, function-scoped dependency коммитит до HTTP success. Deadlock/timeout — безопасный 409 + rollback. Command UUID и request_id связывают операции с исходным административным запросом.

## Агент и запуск

`python -m scripts.module_agent` запускает отдельный процесс без listener. Production требует HTTPS, CA/hostname verification; redirects и environment HTTP proxies выключены. Discovery issuer/token_endpoint сверяются с configured issuer. JWT обновляется заранее; после Core 401 допускается одна повторная аутентификация. 403/404 останавливают процесс, enable требует явного restart. Временная ошибка → exponential backoff с jitter, default максимум 8 последовательных ошибок (настройка 1–20), затем exit 2. SIGTERM/SIGINT прерывают ожидание; текущий HTTP request имеет timeout 10 s.

Env prefix `XARIONIX_AGENT_`: `CORE_URL`, `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `INSTANCE_ID`, опционально `MAX_FAILURES`. Client secret минимум 24 символа, не выводится. Demo Compose не содержит ports, mounts, DB credentials/socket:

```bash
docker compose --env-file /secure/path/module.env -p xarionix-demo-agent -f tests/fixtures/autonomous_module/compose.yaml up -d
```

Env file готовится отдельно с mode 600; image по умолчанию `xarionix-core:sprint-4a`, можно указать `XARIONIX_AGENT_IMAGE`. Никогда не копировать Core DB/IdP admin secrets в agent config или `.xpkg`. Docker administrator может читать environment: это не secret vault.

Только disposable tests включают `XARIONIX_AGENT_ISOLATED_HTTP=true` с ограниченными localhost/core/keycloak hosts и фиксированный `TEST_OIDC_TRANSPORT`. Production example их не включает. Integration agent — другой Compose project и контрольная сеть только с Core/Keycloak, без PostgreSQL. Реальный test disconnect/reconnect сети проверяет восстановление.
