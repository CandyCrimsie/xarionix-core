# Outbound-only business relay

Выбран один Core↔Agent транспорт: bounded HTTPS long polling. WebSocket потребовал
бы другого session stack, HTTP/2 duplex — другого ASGI/клиентского контракта.
Deployment jobs, leases, fences и durable ACK остаются исключительно control plane.
Никакого TCP/SOCKS/HTTP forwarder, caller URL или cross-module routing нет.

Agent — отдельный `python -m scripts.gateway_agent` / Docker target `gateway-agent`.
Параметры `XARIONIX_GATEWAY_CORE_URL`, `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`,
`HOST_ID`, `ENGINE_SOCKET`, `ENGINE_ID`, `STORAGE_ROOT` берутся из защищённого
окружения. Это отдельный OIDC client credentials principal:
`aud=xarionix-core-gateway` (только эта audience), `xarionix_principal=gateway`,
непустые согласованные azp/client_id. Human, machine и deployment credentials не подходят.
TLS использует системный trust store; redirects и trust_env выключены. Нет credentials
в query string. HTTP разрешён только явно включённым disposable localhost test mode.

Platform Admin с recent MFA явно регистрирует точные issuer/subject/client_id:
`POST /api/v1/platform/deployment-hosts/{id}/gateway-identity`.
Существующий deployment principal использовать нельзя. Изменить identity binding
нельзя; `PATCH` принимает только status active/disabled/revoked, revision увеличивается,
revoked terminal. Новый client требует нового reviewed host binding.

Agent endpoints (`/api/v1/module-gateway/hosts/{id}/`):

| Endpoint | Назначение |
|---|---|
| POST sessions | protocol=`module-gateway-poll-v1`, server nonce UUID, expiry ≤JWT/300s |
| POST poll | session UUID, строго возрастающий sequence, capacity 0–4, wait ≤2s |
| POST claim | session + request UUID; разрешён один раз, свежая authorization |
| POST result | correlation, exact installation/generations, JSON **или** safe error |

Одна session/host, один concurrent poll, максимум 128 sessions. Новый session nonce
инвалидирует старые pending requests с unknown outcome. JWT проверяется на каждом
endpoint; identity status/revision и host status читаются из БД. Refresh credentials
сериализован, session обновляется до expiry. Core restart требует новой session.
Frames закрыты Pydantic; лишние URL/commands/paths, неверная версия, correlation,
generation, duplicate/late result отвергаются. Raw ingress ограничен до JSON parsing,
duplicate keys, NaN и слишком глубокие JSON отвергаются.
Core, Agent и IdP требуют синхронизированных UTC clocks: истёкший deadline/JWT не
игнорируется из-за разницы времени; ошибка приводит к отказу.

4 Agent workers, лимиты per host/installation/user/Core, bounded queues, deadlines.
Capacity=0 сохраняет heartbeat без забирания работы. Payload только в RAM; journal
читается read-only и содержит лишь deployment metadata/receipt. Потерянный result
не запускает операцию ещё раз. Отключённый Agent не становится universal tunnel.
