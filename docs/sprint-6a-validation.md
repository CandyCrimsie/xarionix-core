# Sprint 6A — итоговая проверка и отчёт

Проверки выполнены 5 ноября 2026 года. Core baseline:
`c6ab57707a0b2b486715017316e67d52b80b6d4e`; Web baseline:
`3f1169c5832cfdbe9b15d2555f09531fe0e3d9d1`. Рабочие деревья перед началом
были чистыми. Изменяется только Core; Web и ERP по завершении остались чистыми.
Commit, push, публикация и deployment не выполнялись. Runner №5, системный Docker
и существующие dev volumes/контейнеры не менялись.

## Реализовано

- Human API: `POST /api/v1/companies/{company_id}/modules/{module_id}/operations/{operation_id}`.
  Core разрешает только operation из подписанного контракта после проверки active
  human/user/membership/company/effective company RBAC, namespace/permission generation,
  текущего package/publisher/key/grant, exact dependencies, approved profile, ACK,
  image/generations, fresh health и текущего authenticated host channel.
- [XPKG API contract](module-api-contract.md): дополнительный signed inventory resource
  `payload/resources/module-api-v1.json`. Historical V1 manifest/signature domain,
  canonical vectors и package limits сохранены. Immutable registry привязан к package UUID
  и canonical API digest; установка и deployment approval показывают contract/digest.
- [Data plane](module-gateway-transport.md): отдельный outbound HTTPS long-poll Gateway Agent,
  dedicated audience/principal/approved host identity, sessions/sequence/claim/result,
  bounded concurrency/queues/JSON/bytes/deadline, cancellation и no blind write retry.
  Deployment jobs не используются для business delivery. Перед claim и выдачей результата
  authorization проверяется заново; PostgreSQL transaction не держится во время remote work.
- [Private profile](module-runtime-private-network.md): `module-api-private-v1` сохраняет
  network=none, UID10001, readonly rootfs, cap-drop ALL, seccomp/nnp, реальные cgroups,
  отсутствие binds/socket/ports. Фиксированный stdin/stdout exec bridge вызывает только
  loopback:8080 approved operation. Body не включается в Cmd/env/files/logs; human JWT
  не передаётся модулю. Дополнительный IPC не даёт module egress.
- Additive `0012_module_gateway`: `module_api_contracts`, `module_gateway_identities`,
  immutable/terminal guards и wrapper над прежним `core_module_authorized_4d`.
  Body/token storage и новые catalog privileges не добавлены. Installer получает лишь
  SELECT новой metadata и EXECUTE read-only availability chain. DBA script обновлён.
- Реальный [Hello Business](../examples/modules/hello-business/hello.py): health, read/write,
  проверенный context, company datasets, process nonce/version/correlation, signed OCI/XPKG.
- CI: новые `module-gateway:unit`, `module-gateway:security`,
  `module-gateway:runtime-e2e`; прежние gates сохранены. Новый E2E следует за прежним
  native runtime gate. Trivy дополнительно проверяет Gateway Agent и business example.
  Добавлены Make targets, server limits в env/Compose/installer и документация.

## Найденные и исправленные дефекты

1. Новый identity route перехватывался существующим `deployment-hosts/{id}/{action}`:
   изменён порядок регистрации router; реальный E2E повторён.
2. Private API binding терялся после safety/read-only `inspect`: metadata теперь
   сохраняется по фактически выбранному current profile, включая signed digest/protocol.
   После inspect бизнес-вызов продолжает работать в том же module process.
3. В split DB-role rehearsal installer не имел EXECUTE на новый read-only wrapper
   `core_module_authorized_4d`. Выдано только это разрешение; catalog/DDL separation сохранено.
4. Non-string `xarionix_principal` мог вызывать TypeError/500 в human token gate.
   Теперь такие claims отклоняются с 401 до разрешения запроса.
5. Router примера не принимал цифры в operation ID, хотя signed grammar их разрешает.
   Грамматика приведена к contract; upgrade на `status-read-v2` и rollback реально проверены.
6. ASCII escaping в IPC раздувал допустимый UTF-8 payload и вызывал ложный byte-limit
   отказ. Request/response bridge сохраняют UTF-8; проверены настоящие 40 KiB
   кириллические JSON в обоих направлениях.

Явный административный Docker kill не заменён автоматическим start. Для проверки
аварии используется выход module process с code=1 и штатная on-failure restart policy.

## Фактически выполненные проверки

| Проверка | Результат |
|---|---|
| `make check` | Успех |
| Unit suite | **760 passed**, coverage **72.44%**, baseline 70% сохранён |
| Real PG/Keycloak integration suite | **115 passed**, 2 native scenarios вынесены в отдельные gates |
| Финальный native gateway E2E | **1 passed / 354.27s** |
| Ruff / Ruff Format | Успех, 159 файлов |
| MyPy | Успех, 122 source files |
| Bandit | Успех |
| pip-audit production/dev lockfiles | Известных уязвимостей не найдено |
| Gitleaks history + non-ignored working tree | Успех, redacted reports |
| Compose dev/external/managed | config/interpolation/mounts/privileges/dependencies прошли |
| Nginx external/managed | Реальный `nginx -t` в disposable containers прошёл |
| Production build + image smoke | Успех: non-root, readonly, OCI labels, live=200, unready=503, no-token=401 |
| Trivy Core / Deployment Agent / Gateway Agent / Hello Runtime / Hello Business | HIGH/CRITICAL gate прошёл |
| OpenAPI export | Сформирован `reports/gateway-openapi.json` |
| Существующие dev containers | Четыре исходных сервиса остались healthy |

Native E2E использует отдельный **native Linux rootless daemon** с реальными cgroup v2
CPU/RAM/swap/PID controls. Core/PG/Keycloak работают в другом disposable daemon/project.
Приватный SSH forwarding UDS не подменяет runtime kernel или resource enforcement.
После серии native engine не содержит тестовых контейнеров. Cleanup удаляет лишь
точные owned containers/images данного запуска; ранее существовавшие cache images
сохраняются. Временный SSH forwarding и его private socket directory закрыты.

Финальный E2E проверил: signed import → MFA install approval → отдельный trusted installer →
approved private deployment → healthy ACK → explicit company role grants → реальные
read/write двух компаний; отсутствие admin/owner bypass; cross-company и suspended
membership/company denial; role revoke до и во время remote work; header spoofing;
отбрасывание Set-Cookie/Location/CORS; UTF-8 и oversized/slow output; Agent reconnect;
Core SIGKILL во время write с **одной** фактической записью без automatic retry;
два разных network namespaces; фактические запреты доступа к PG, Keycloak Admin,
metadata, external network, engine socket и host files; module process crash/restart;
upgrade/rollback с другим API contract и новым permission epoch; disable/re-enable,
gateway identity disable/re-enable, publisher revoke и physical quarantine stop.

## Измерения, не SLA

Последний успешный запуск через SSH-forwarded native engine:

- Write end-to-end latency: **4.33 / 5.08 s**.
- Два одновременных read: **9.15 s** суммарного wall time.
- Наблюдаемый timeout: **10.07 s** при policy 10s.
- Revocation во время исполнения: **0.092 s**;
  company mutation не ждала remote transaction.
- Core RSS: **114244 kB → 114536 kB** в небольшом
  контрольном read сценарии. Это не длительный load/soak benchmark и не гарантия отсутствия
  любой утечки.
- Подробные безопасные метрики: `reports/gateway-benchmark.json`.

Exec/inspection на каждую операцию заметно стоят времени на удалённом test daemon.
Чистый production gateway overhead отдельно не изолирован; throughput/SLA не заявляются.

## Ограничения и непроведённые проверки

- GitLab pipeline **не запускался**: пользователь отправляет изменения сам.
- Прежний отдельный `tests/integration/test_runtime_e2e.py` целиком локально не запускался:
  его harness требует Linux test client. Обязательный CI gate сохранён. Новый 6A E2E
  действительно выполнился на native Linux engine через private UDS и дополнительно
  проверил legacy offline peer; это не заявление о запуске старого самостоятельного suite.
- Relay V1 — **один Core worker**, bounded RAM state, без HA/shared queue. После restart
  pending delivery теряется с unknown outcome. Already-started write не обещает rollback
  после concurrent revoke и не имеет exactly-once guarantee.
- Shared module отвечает за корректность фильтрации собственного dataset по context;
  Core не защищает данные модуля от самого злонамеренного кода этого модуля.
- Hello Business dataset volatile; isolated module DB/secrets/migrations/SDK относятся к
  будущему 6B и здесь не реализованы. Autonomous synchronous business RPC также отложен.
- Web оставлен на закреплённом 4D Core ref/snapshot. Private profile selector и обзор
  новых API plans в нём отсутствуют; 6A workflow выполняется через Core API/CLI с просмотром
  полного plan JSON. Переключение Console на новый Core ref потребует отдельного
  обновления его audited contract/UI.
- Production domain/TLS deployment и реальные пользовательские данные не затрагивались.
  Terminal host/identity rebinding остаётся за пределами прежней 4D архитектуры;
  обычное отключение использует disabled, secret rotation сохраняет issuer/subject/client_id.

## Команды повторной проверки

```bash
make check
XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/python -m pytest tests/integration -m 'not runtime' -vv
make gateway-test
XARIONIX_RUNTIME_ENGINE_SOCKET=/absolute/private/native-rootless.sock make gateway-integration-test
make docker-build IMAGE=xarionix-core:sprint6a-validation
make docker-scan IMAGE=xarionix-core:sprint6a-validation
make runtime-images-check
.venv/bin/python -m scripts.compose_check --nginx
```

[Полный build/sign/install/call workflow](module-gateway-development.md).
[Авторизация и concurrency boundary](module-gateway-authorization.md).
[Архитектурный аудит до реализации](module-gateway-architecture-audit.md).

## Изменённые файлы (66)

- [.env.example](../.env.example)
- [.gitlab-ci.yml](../.gitlab-ci.yml)
- [Dockerfile](../Dockerfile)
- [Makefile](../Makefile)
- [README.md](../README.md)
- [app/api/v1/module_gateway.py](../app/api/v1/module_gateway.py)
- [app/core/authentication.py](../app/core/authentication.py)
- [app/core/config.py](../app/core/config.py)
- [app/core/database.py](../app/core/database.py)
- [app/core/module_body_limit.py](../app/core/module_body_limit.py)
- [app/domains/deployments/artifacts.py](../app/domains/deployments/artifacts.py)
- [app/domains/deployments/contracts.py](../app/domains/deployments/contracts.py)
- [app/domains/deployments/service.py](../app/domains/deployments/service.py)
- [app/domains/installations/service.py](../app/domains/installations/service.py)
- [app/domains/module_gateway/__init__.py](../app/domains/module_gateway/__init__.py)
- [app/domains/module_gateway/authorization.py](../app/domains/module_gateway/authorization.py)
- [app/domains/module_gateway/contracts.py](../app/domains/module_gateway/contracts.py)
- [app/domains/module_gateway/model.py](../app/domains/module_gateway/model.py)
- [app/domains/module_gateway/transport.py](../app/domains/module_gateway/transport.py)
- [app/domains/packages/archive.py](../app/domains/packages/archive.py)
- [app/domains/packages/service.py](../app/domains/packages/service.py)
- [app/domains/registry.py](../app/domains/registry.py)
- [app/main.py](../app/main.py)
- [compose.dev.yaml](../compose.dev.yaml)
- [compose.yaml](../compose.yaml)
- [deploy/postgres/module-executor.sql](../deploy/postgres/module-executor.sql)
- [docs/architecture.md](../docs/architecture.md)
- [docs/ci-cd.md](../docs/ci-cd.md)
- [docs/module-api-contract.md](../docs/module-api-contract.md)
- [docs/module-api-gateway.md](../docs/module-api-gateway.md)
- [docs/module-communication.md](../docs/module-communication.md)
- [docs/module-gateway-architecture-audit.md](../docs/module-gateway-architecture-audit.md)
- [docs/module-gateway-authorization.md](../docs/module-gateway-authorization.md)
- [docs/module-gateway-development.md](../docs/module-gateway-development.md)
- [docs/module-gateway-recovery.md](../docs/module-gateway-recovery.md)
- [docs/module-gateway-security.md](../docs/module-gateway-security.md)
- [docs/module-gateway-transport.md](../docs/module-gateway-transport.md)
- [docs/module-installation-executor.md](../docs/module-installation-executor.md)
- [docs/module-permission-contract.md](../docs/module-permission-contract.md)
- [docs/module-runtime-networking.md](../docs/module-runtime-networking.md)
- [docs/module-runtime-private-network.md](../docs/module-runtime-private-network.md)
- [docs/module-runtime.md](../docs/module-runtime.md)
- [docs/security-model.md](../docs/security-model.md)
- [docs/sprint-6a-validation.md](../docs/sprint-6a-validation.md)
- [docs/xpkg-specification.md](../docs/xpkg-specification.md)
- [examples/modules/hello-business/Dockerfile](../examples/modules/hello-business/Dockerfile)
- [examples/modules/hello-business/hello.py](../examples/modules/hello-business/hello.py)
- [examples/modules/hello-business/manifest.json](../examples/modules/hello-business/manifest.json)
- [examples/modules/hello-business/module-api-v1.json](../examples/modules/hello-business/module-api-v1.json)
- [migrations/versions/0012_module_gateway.py](../migrations/versions/0012_module_gateway.py)
- [scripts/ci.py](../scripts/ci.py)
- [scripts/deployment_agent/__main__.py](../scripts/deployment_agent/__main__.py)
- [scripts/deployment_agent/engine.py](../scripts/deployment_agent/engine.py)
- [scripts/deployment_agent/ipc.py](../scripts/deployment_agent/ipc.py)
- [scripts/docker_job.py](../scripts/docker_job.py)
- [scripts/gateway_agent.py](../scripts/gateway_agent.py)
- [scripts/runtime_images.py](../scripts/runtime_images.py)
- [scripts/setup.py](../scripts/setup.py)
- [tests/integration/test_managed_stack.py](../tests/integration/test_managed_stack.py)
- [tests/integration/test_module_db_privileges.py](../tests/integration/test_module_db_privileges.py)
- [tests/integration/test_module_gateway_e2e.py](../tests/integration/test_module_gateway_e2e.py)
- [tests/integration/test_runtime_e2e.py](../tests/integration/test_runtime_e2e.py)
- [tests/runtime_helpers.py](../tests/runtime_helpers.py)
- [tests/test_module_gateway.py](../tests/test_module_gateway.py)
- [tests/test_module_gateway_agent.py](../tests/test_module_gateway_agent.py)
- [tests/test_module_gateway_faults.py](../tests/test_module_gateway_faults.py)
