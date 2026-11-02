# Sprint 4A — реализация, проверки и эксплуатационные границы

Дата: 02.11.2026. Baseline `16410f565a1dcd686ffce6a7175d25edaa3c5129`, исходное дерево чистое. Изменён только `xarionix-core`. Commit/push, release publish, production deployment и изменение GitLab Runner не выполнялись.

## Реализовано и архитектура

Добавлен отдельный control plane: ModuleService с immutable issuer/subject/client binding и конечными machine capabilities; ModuleInstance с installation key и server heartbeat; ModuleCompanyScope с явным доступом к metadata компании; ModuleCommand с durable delivery/lease/result. Module type, service identity и installation UUID не смешиваются: один тип может иметь несколько service records, в v1 одна service identity соответствует одному instance.

Новый machine context не вызывает Identity/User JIT, не создаёт Membership, не использует company human RolePermissions. Operation и scope проверяются на каждом запросе из PostgreSQL. Company permissions Sprint 3 и protected Ownership не изменены. Namespaces ERP/OSS/Billing не активированы и не получили фиктивные permissions.

Реализованы Platform Admin + MFA API регистрации, enable/disable/revoke, instances, company scopes, состояния и очереди ping/get_status; отдельные machine check-in/ACK/metadata. [Схема, ER и API](module-communication.md), [auth sequence и настройка Keycloak](service-authentication.md), [протокол](module-control-channel.md), [threat model](module-threat-model.md).

## Authentication

Используется настоящий Keycloak Client Credentials, не Core-issued token. Существующий OIDCVerifier расширен параметром audience, без отключения прежних signature/issuer/audience/exp/iat/nbf/typ/alg/kid проверок или изменения MFA. Default machine audience `xarionix-core-modules`, отдельная от human `xarionix-core`. Signed purpose `xarionix_principal=machine` обязателен. Registry сравнивает проверенные iss/sub/azp; необязательный client_id обязан совпасть с azp. На реальном Keycloak 26.8.1 sub является service-account UUID, а azp — client ID, они различаются.

Admin регистрирует binding явно, Core не хранит client secret и не получает Keycloak master-admin credentials. Только disposable fixture использует Admin API для создания тестовых clients/realms. External Keycloak не изменяется runtime Core. Human audience/purpose separation блокирует machine JWT до human JIT; SQL guards/resolver запрещают смешать зарегистрированный machine subject с legacy Identity. Старый unclassified human-audience JIT сохранён как совместимый путь без автоматического human admission.

## Управление, доставка и concurrency

Агент инициирует исходящие запросы к IdP/Core; входящий listener отсутствует. Он обновляет токен заранее, повторяет authentication после одного 401, использует bounded exponential backoff/jitter, останавливается при запрете и обрабатывает SIGTERM/SIGINT. Core не запрашивает module URL и не создаёт SSRF/reverse tunnel.

Heartbeat обновляет last_seen серверным временем; stale/connected/error/disabled/revoked выводятся из текущих данных, не client timestamp. Rate limit хранится в instance row. Queue ≤100, batch ≤10, TTL 10–3600 s, lease 5–120 s, не более пяти deliveries. ACK result строго типизирован. Повтор того же ACK идемпотентен, конфликтующий result запрещён; mutation и audit коммитятся атомарно до HTTP success.

Это at-least-once, не exactly-once. Агент имеет ограниченный process-memory cache; ping/get_status сами идемпотентны. Восстановление после process restart для будущих опасных операций не обещается.

Machine lock order: service SHARE → instance UPDATE/SHARE → scope/command. Revoke: service UPDATE. Независимые instances не берут глобальные settings/admin locks. JWT/JWKS verification до DB transaction; внутри нет ожидания сети/команд. Pool ограничен 5 + 10 overflow connections на процесс. Timeout/deadlock откатывается с безопасным 409.

## PostgreSQL и безопасное обновление

Новая revision **`0005_module_control`** поверх неизменённой `0004_rbac`. Добавлены четыре таблицы с UUID/FK/RESTRICT, уникальными bindings и service-instance 1:1, compound scope PK, bounded strings, JSONB capability allowlists, status/protocol/attempt/expiry/completion CHECK и polling indexes. Machine/human binding guards препятствуют скрытой перепривязке; issuer/subject/client/module_key immutable, service revoke terminal. Никаких create_all/drop_all или каскадного удаления.

Для existing Sprint 3 installation:

1. Backup Core/Keycloak и restore rehearsal, сохранить credentials вне Git.
2. Maintenance: остановить старые writes/Core. Zero-downtime совместимость не заявляется.
3. Новый image и штатный `migrate` / `alembic upgrade head`; не менять passwords/volumes.
4. Проверить head=`0005_module_control`, прежние UUID, owner/admin guards, RBAC/invitations/audit и readiness; запустить Core.
5. Service clients, bindings, scopes создать отдельно проверенным операторским/Admin+MFA способом. Установщик не выдаёт автоматическое доверие.
6. При неудаче — анализ rollback и проверенное backup restore под maintenance. Destructive downgrade не реализован.

Dev upgrade фактически выполнен: 0004 → 0005, два `make dev-up` и `make dev-test`. PostgreSQL system identifier до/после `7703322558304469031`; Identity/Company 0/0 до и после. Этот dev-кластер был пустым — доказательство сохранности заполненных данных даёт отдельная integration fixture с legacy Identity, Company/Memberships, Employee, Invitation и audit до upgrade. Старые Sprint 1–3 regression tests сохранены.

### Привилегии: проверено, но не применено к рабочим volumes

Read-only `python -m scripts.db_privileges` на dev вернул:

```json
{"superuser":false,"schema_create":true,"owns_tables":true,"audit_delete":true,"catalog_update":true,"instance_update":true}
```

`audit_delete/catalog_update=true` — наличие SQL grant, **не** успешный обход существующих append-only/catalog triggers. Но владелец таблиц способен менять DDL и отключать их; это подтверждённая избыточная граница доверия.

В новой disposable DB реально выполнено:

1. Upgrade до 0004 от прежнего app owner, seed существующей Company/owner Membership; COMMIT deferred invariants до ownership DDL.
2. Созданы отдельные NOLOGIN schema-owner, LOGIN migrator и runtime с новыми только тестовыми secrets. Ownership явных Core tables/functions/public schema/DB перенесён; migrator получает owner membership и default SET ROLE только в этой DB, runtime — нет.
3. Сняты PUBLIC schema CREATE и database TEMP/CREATE; existing functions получили pinned search_path. Migrator выполнил настоящий Alembic upgrade 0004 → 0005 с сохранением seeded UUID.
4. Runtime получает CONNECT/USAGE/SELECT; business DML, audit INSERT без DELETE/UPDATE/TRUNCATE, read-only catalog/Alembic; reviewed function EXECUTE. Новые SECURITY DEFINER functions не понадобились: штатный nested seed/sync работает invoker и защищёнными triggers.
5. Под runtime реально отказали ALTER TABLE, DISABLE TRIGGER, UPDATE catalog, DELETE/TRUNCATE audit, CREATE TEMP и SET ROLE owner. При этом прошли JIT, company creation с protected system role seed, custom role, Employee, machine heartbeat/audit и readiness.

Это **рабочая disposable maintenance rehearsal**, не автоматический production rollout. Для установки нужны inventory владельцев/объектов, проверенный backup, отдельное secret provisioning, смена migrate/runtime deployment config и проверка grants после каждой миграции. Нельзя заменить `.env` и считать пароли/ownership обновлёнными. Тестовый ownership/grant код находится в `tests/integration/test_module_db_privileges.py`; повторять его вслепую на production нельзя. Отдельный operator/migrator остаётся доверенным. См. [PostgreSQL function security](https://www.postgresql.org/docs/18/perm-functions.html) и [CREATE FUNCTION privileges/search_path](https://www.postgresql.org/docs/18/sql-createfunction.html).

## Testing и результаты

Финальный общий integration прогон: **71 passed, 335 deselected, 315.64 s** (прежние 47 + новые 24 случая). Перед ним также прошли новый subset 22 tests / 155.48 s и полный промежуточный 69 tests / 325.96 s; результаты не складываются как дополнительное покрытие. Проверяются реальные PostgreSQL/Keycloak, signed machine token, wrong audience/issuer/expired/corrupt token, unknown service/instance, human-machine separation, company scope/revoke, capabilities, live JWT revoke, lease redelivery, ACK replay/conflict, concurrent pollers, stale/error, audit rollback, waiting revoke, bounded queue/TTL, запрет human rebinding/namespace grants и отдельный agent container.

Agent container запущен отдельным Compose project в контрольной сети только с Core/Keycloak; без published ports, mounts, DB credentials, master-admin env/socket. Реально выполнены ping/get_status → PostgreSQL completion/audit, disconnect/reconnect Docker network → retry/recovery, revoke → agent exit 3. Проверено отсутствие token/secret в его logs. Lost ACK response проверен повтором committed ACK на настоящем Core и unit fault injection у агента.

На текущем этапе фактически прошли:

| Проверка | Результат |
|---|---|
| `make check` | 335 unit/API passed, coverage 78.15%, gate 70% сохранён |
| `make integration-test` | 71 passed / 315.64 s, без пропусков выбранных integration tests |
| Ruff/Format/MyPy | Passed; 86 formatted files / 68 source files |
| Bandit, обе strict pip-audit | Passed, известных vulnerabilities нет |
| Gitleaks | Git history + non-ignored worktree passed |
| `make docker-build IMAGE=xarionix-core:sprint-4a` | Production multi-stage + OCI/non-root/read-only smoke passed |
| `make docker-scan IMAGE=xarionix-core:sprint-4a` | Trivy HIGH/CRITICAL passed |
| Compose dev/external/managed + Nginx `-t` | Passed |
| Dev-up/dev-test и повторный запуск | Passed; тот же кластер/volumes, head 0005 |

Итого проверены **406 уникальных tests**: 335 unit/API и 71 integration. `git diff --check` прошёл. Новый GitLab pipeline не запускался: push не выполнялся. `.gitlab-ci.yml`, Runner/DinD/TLS и security/coverage gates не ослаблены; новые tests обнаруживаются существующей командой pytest. Старые migrations 0001–0004 и dependency locks не изменены.

### HTTP microbenchmark

В integration автоматически измеряются 12 разных instances, concurrency 1/4/12, p50/p95/p99 и throughput. Каждый instance опрашивается один раз за timed round; только его disposable rate-limit timestamp сбрасывается **до** измерения. В timings входят HTTP client/connect, JWT, DB и COMMIT; перед измерением warming. Никаких production requests. Сырые безопасные данные: ignored `reports/module-heartbeat-benchmark.json`, код — `scripts/module_benchmark.py`. Это очень маленький локальный Docker benchmark; p99 при 12 samples фактически max, production SLA из него не следует.

Последний прогон, macOS/Docker Desktop arm64 / PostgreSQL 18.6:

| Concurrency | Operations | Throughput, ops/s | p50, ms | p95, ms | p99, ms |
|---|---:|---:|---:|---:|---:|
| 1 | 12 | 162.87 | 6.203 | 6.499 | 6.499 |
| 4 | 12 | 203.45 | 13.987 | 36.962 | 36.962 |
| 12 | 12 | 211.13 | 50.044 | 54.641 | 54.641 |

## Изменённые файлы

Новые: `app/domains/modules/{model,authorization,service}.py`, package init; `app/api/v1/{modules,module_schemas}.py`; `app/core/module_body_limit.py`; `migrations/versions/0005_module_control.py`; `scripts/{module_agent,module_benchmark,db_privileges}.py`; `tests/test_modules.py`, `tests/integration/{test_module_control,test_module_db_privileges}.py`; `tests/fixtures/autonomous_module/compose.yaml`; документы module-communication/service-authentication/module-control-channel/module-threat-model и этот отчёт.

Обновлены: `app/core/{authentication,config,database}.py`, `app/integrations/keycloak/oidc.py`, `app/domains/identity/service.py`, `app/domains/registry.py`, `app/main.py`; `scripts/setup.py`, `compose.yaml`, `compose.dev.yaml`, `.env.example`; существующие `tests/test_sprint2.py` (дополнительное чтение binding в JIT mock) и `tests/integration/test_managed_stack.py` (head/isolated machine fixture); README и architecture/identity/security-model/module-permission-contract docs. Старые migrations, dependencies, pipeline/Runner и соседние repos не изменены.

## Ограничения и Sprint 4B

- Нет `.xpkg` install/signatures, Module Manager, remote execution, бизнес-ERP/Billing, gateway/tunnel/RPC, M2M human impersonation или OAuth token exchange.
- Production service client provisioning и SQL-role rollout требуют явного оператора/maintenance. Проверенная rehearsal не означает, что текущий dev/runtime больше не владеет DDL.
- Реальный agent E2E выполнен по явно изолированному HTTP, не с внешними production доменами/TLS-сертификатами. Production HTTPS/hostname/CA обязательны в коде; публичный TLS deployment и настоящий human MFA step-up этого этапа не выполнялись.
- Capabilities фиксированы v1, один binding на instance. Изменение binding требует новой явной регистрации; нет self-service registrar или автоматической активации namespace.
- Cache агента не persistent, exactly-once не обещается; для новых опасных операций нужен другой inbox/idempotency contract. Retention audit/command history, perimeter DoS quotas, HA и capacity planning остаются эксплуатационными задачами.
- Следующий Sprint 4B: `.xpkg` specification, manifest schema, namespace ownership/trust policy, signatures/key lifecycle и compatibility checks. Никакая будущая возможность не считается уже реализованной.
