# Module API Gateway V1

Gateway доставляет **разрешённую company operation** подписанного Standard Module в
конкретный живой OCI runtime. Это не reverse proxy по произвольному URL. Core не
импортирует Python пакета, браузер не обращается к контейнеру, human JWT остаётся в Core.

```http
POST /api/v1/companies/{company_uuid}/modules/{module_id}/operations/{operation_id}
Authorization: Bearer <human access token>
Content-Type: application/json

{"name":"Пример"}
```

Успех: `{"request_id":"uuid","body":{...}}`. Operation ID, POST, permission и
размеры определяет подписанный resource. UUID компании проверяется по membership;
actor берётся из Core identity. Platform Admin не заменяет company permission.

Новые безопасные коды: `gateway_module_unavailable`, `gateway_package_unavailable`,
`gateway_operation_not_found`, `gateway_runtime_binding_changed`,
`gateway_agent_disconnected` (503), `gateway_capacity_exceeded` (429),
`gateway_request_limit` (413), `gateway_response_limit` (502),
`gateway_timeout_outcome_unknown` (504), `gateway_session_lost` (503).
Обычные RBAC 403/404 остаются прежними. Детали ошибок не содержат body, SQL или stderr.
После admission ответ/ошибка содержит server-generated operation request UUID;
его же получает модуль и audit. HTTP `X-Request-ID` — отдельная связанная метка.

Core V1 запускается **одним worker** (штатный Docker CMD). Relay хранит ограниченные
ephemeral futures в памяти, не в deployment queue или PostgreSQL. Multi-worker/HA
relay не реализован: другой процесс не имеет session и отказывает, а не отправляет
данные чужому runtime. Нельзя масштабировать workers и ожидать общего relay state.

Конфигурация `XARIONIX_GATEWAY_*`: `AUDIENCE=xarionix-core-gateway`,
`REQUEST_BYTES=65536`, `RESPONSE_BYTES=1048576`, `DEADLINE_SECONDS=10`,
`PENDING=64`, `PER_HOST=8`, `PER_INSTALLATION=2`, `PER_USER=4`.
`INGRESS=64` ограничивает concurrent gateway HTTP handlers до SQL/очереди,
`BODY_SECONDS=10` — чтение входного тела (408 при истечении). Перегрузка ingress
возвращает 429; ожидание свободного slot не создаёт неограниченную очередь.
Значения валидируются при старте; контракт может уменьшить лимиты. JSON depth=16,
collection budget=10000, operation ID ≤63 ASCII. File/SSE/WebSocket passthrough нет.
`JSON_DEPTH` (1–16) и `OPERATION_ID_LENGTH` (1–63) также можно уменьшить через
server configuration; пакет/клиент не может поднять hard caps.

См. [контракт](module-api-contract.md), [transport](module-gateway-transport.md),
[авторизацию](module-gateway-authorization.md), [recovery](module-gateway-recovery.md),
[разработку примера](module-gateway-development.md), [валидацию](sprint-6a-validation.md).
