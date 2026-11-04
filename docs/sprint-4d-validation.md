# Sprint 4D — реализация и журнал проверки

Исходный baseline: `dc29ca064df38cfd1b8393ed6158553f4a884360`.
Additive migration: `0011_deployment_runtime`; старые revisions не редактировались.
Рабочие dev volumes, DB credentials и соседние репозитории не менялись.

## 1. Фактическая архитектура

Core хранит планы, задания, desired/observed state и signed CAS. Он не получает Docker
socket и не импортирует engine adapter. Отдельный trusted catalog executor 4C по-прежнему
меняет metadata через прежнюю DB capability. Отдельный Deployment Agent с собственной
machine identity опрашивает Core, проверяет signed package и управляет только своим
закреплённым rootless engine. Business Module Agent 4A и human identity не получают
deployment API. Схемы доверия и 11 sequence/state/flow diagrams — в runtime-документации.

Добавлены DeploymentHost, DeploymentPlan, RuntimeDeployment, DeploymentJob и ModuleRetirement.
Планы immutable, живут 600 секунд, требуют отдельного fresh MFA approval и exact digest/
package/installation generation/host revision. Одновременные активные jobs одной installation
не допускаются; lease/fence, expiry и текущие права проверяются повторно перед исполнением.
Expired unacknowledged execution приводит к отдельному fenced quarantine, не к assumed success.

## 2. OCI contract и агент

Выбран ограниченный OCI profile **внутри XPKG V1**, не несовместимый V2. Ed25519 подписывает
inventory с `runtime-v1.json`, OCI index/manifest/config и всеми blobs. Manifest digest,
config digest, platform, размеры и diff_ids связаны и проверяются Core и агентом.
Пакет содержит сами offline image bytes, не mutable tag/URL. ZIP/tar не извлекается в Core;
проверяются закрытый inventory, path traversal/symlinks/special entries, логические размеры
tar и bounded gzip expansion. Docker-save converter корректно принимает raw/gzip layers.

Deployment JWT имеет собственный audience, проверенные issuer/sub/client binding и claim
`xarionix_principal=deployment`. Polling только outbound HTTPS, без inbound agent port,
redirects и отключения TLS. В isolated tests HTTP разрешён отдельным явным allowlist.
Durable SQLite WAL/FULL synchronous + exclusive flock сохраняют sequence, поколения и ACK
receipt. Delivery at-least-once, ACK idempotent; credentials не попадают в журнал.
Host capacity 32 installations/active jobs, одна доставка и один выполняемый job на агенте.
Каждая installation имеет отдельные private cache/data; partial staging перепроверяется,
cache очищается, data/history сохраняются. V1 stateless: data directory не монтируется.

## 3. Изоляция, lifecycle и availability

Runtime: UID/GID 10001, read-only rootfs, cap-drop ALL, no-new-privileges, builtin seccomp,
private cgroup namespace, IPC/network none; без ports/devices/host PID/binds/socket/secrets.
`offline-small-v1`: 256 MiB RAM, swap=0, 0.5 CPU, 64 PID; `offline-medium-v1`: 512 MiB,
swap=0, 1 CPU, 128 PID. Private /tmp tmpfs 64 MiB/noexec/nosuid/nodev; логи 1 MiB × 2,
restart on-failure максимум 3. Проверяются не только Docker inspect, но и реальные kernel
controls. Несовпадение после start останавливает неподтверждённый процесс.

- Provision импортирует exact image offline и создаёт stopped container.
- Start ждёт fixed loopback liveness/readiness и isolation checks.
- Stop сохраняет установку/пакет/данные; restart не создаёт отсутствующий runtime.
- Upgrade/rollback применяют exact approved digest отдельно от 4C metadata lifecycle,
  повторно проверяют trust и health; ошибка остаётся fail-closed, не маскируется auto-success.
- Reconcile восстанавливает согласованное состояние после agent restart; inspect read-only.
- Quarantine/retire останавливают собственные процессы без возврата revoked trust.
- Deprovision допускается после stopped state и не удаляет catalog/history/user data.

Core availability/RBAC требуют current trust, exact installed package, succeeded ACK того
же поколения/image с container ID, active/fresh host и fresh ready/live. Один heartbeat
не может подделать завершение job. Legacy metadata-only и autonomous 4A остаются совместимы.

## 4. База и безопасное обновление

Только additive `0011_deployment_runtime`: новые таблицы/guards и runtime-aware availability;
исторические revisions не менялись. Restricted DB bootstrap расширен минимальными SELECT/
function grants, не deployment DML для installer. Прогон owner/migrator/runtime/installer/
catalog capability ролей выполнен на одной disposable DB, включая повторное применение SQL,
negative privileges и сохранение существующих записей. Dev/production DB не мигрировались.

Перед рабочим upgrade: согласованный backup Core DB/CAS, maintenance window, существующий
migrator `alembic upgrade head`, затем документированный restricted-role bootstrap, новый
Core и отдельная ручная регистрация agent identity/host. Не запускать старый Core против
обновлённой схемы и не сбрасывать volumes/пароли. Runtime не исполняет SQL migrations из XPKG.

## 5. Фактически выполненные проверки

| Проверка | Результат |
|---|---|
| Final `make check` | **686 passed**, 116 integration deselected, coverage **72.27%**, gate 70% сохранён |
| Full PostgreSQL/Keycloak integration без native runtime | **115 passed**, 686 deselected, 673.93 s |
| Restricted-role bootstrap + deployment protocol, отдельный targeted прогон | 5 passed, затем расширенный deployment protocol 5 passed |
| Native Linux amd64 real-agent E2E | **1 passed, 365.53 s** на двух разных native rootless engines |
| Fresh-checkout E2E под новым Runner UID 1001 с его systemd hardening | **1 passed, 348.95 s**, отсутствующий reports directory создаётся корректно |
| Runtime artifact validator/converter | реальные 17 MiB XPKG и offline OCI проверены |
| Compose dev / managed / external | interpolation/mounts/security/dependencies passed; отдельно настоящий nginx validation passed |
| Ruff / format / MyPy / shell | passed; MyPy 112 source files |
| Bandit / pip-audit | passed; оба locked dependency sets без известных уязвимостей |
| Gitleaks | full Git history и текущий неигнорируемый working tree passed |
| Production Core build/smoke/Trivy | passed, exact final local image, HIGH/CRITICAL gate |
| Separate Agent + Hello build/smoke/Trivy | оба passed, отдельные reports |
| Negative engine rehearsal | настоящий rootless DinD без delegation отклонён: exit 2, `isolation_unavailable`, runtime не создавался |

Единственный unit warning ожидаем: malicious ZIP fixture намеренно создаёт duplicate entry.
Opt-in native E2E не подменяет обычные integration tests и не скрывается успешным skip в CI.
Использована команда `python -m pytest`, как в Make/CI. Дополнительная попытка вызвать
локальный console-script `.venv/bin/pytest` не собрала тесты из-за import path (`app`);
повтор тем же venv через `python -m pytest` прошёл. Проблема запуска не скрывалась skip/
ослаблением assertions и не требовала изменения application imports.

Положительный E2E проверил два независимых runtime installations, реальные signed bytes/CAS,
отдельный agent process, provision/start/stop/restart, kernel controls, enable/RBAC,
agent crash/restart без дубликатов, readiness failure/recovery, process crash + ограниченный
restart policy, успешные upgrade/rollback, **неуспешные upgrade и rollback** на signed unready
version, восстановление, terminal publisher revoke с физическим quarantine обоих процессов,
retire уже quarantined установки и deprovision **без восстановления trust**. Data sentinel,
installation, jobs и audit history сохранились.

Unit/API/PG tests также покрывают неверные principals/audiences/client binding, stale
host/version/generation/fence, duplicate ACK/lease, current revoked trust, queue bounds,
невозможность fake healthy ACK, rollback транзакции, установочные approvals и недоступность
artifact stream. Concurrency tests используют настоящие DB locks. Полный stress/нагрузочный
benchmark не заявляется.

Измерения успешного native прогона, секунды, **не SLA**:
artifact verification 0.510; provision 3.096; start 11.538; stop 3.718; restart 13.993;
reconcile после agent restart 4.990. `reports/runtime-benchmark.json` и JUnit сохранены локально.
Отдельная повторная репетиция под Runner account: verification 0.476; provision 3.469;
start 12.910; stop 4.141; restart 13.578; reconcile 3.741. Отчёты сохранены как
`reports/runtime-e2e-runner.xml`, `reports/runtime-benchmark-runner.json`; это реальный
systemd-host rehearsal с текущими исходниками, **не GitLab pipeline/job**.

Native Linux test host настроен отдельным rootless user-service с явного согласия владельца.
Системный Docker/Runner и существующие контейнеры не изменены. Для Core test stack используется
второй временный rootless daemon. Rootless/seccomp/cgroup v2 и CPU/RAM/PID controls проверены
не только `docker info`, но и фактическим exec внутри Hello: UID 10001, CapEff=0,
NoNewPrivs=1, Seccomp=2, memory.max=268435456, memory.swap.max=0, pids.max=64,
cpu.max='50000 100000'.

## 6. Реальные дефекты, найденные выполнением

Реальные E2E прогоны нашли и привели к regression fixes:

- Docker-save может содержать уже gzip layers; двойное сжатие ломало diff_id.
- Docker containerd store возвращает manifest ID, classic store — config ID.
- Успешный Docker exec без stdout возвращает пустой stream; это не ошибка health.
- Guard trigger должен ветвиться по таблице до обращения к специфичным NEW-полям.
- Ошибка post-start isolation verification должна остановить неподтверждённый процесс.
- Hello PID 1 должен сам обрабатывать SIGTERM/SIGINT: иначе stop ожидал forced kill.
- `docker kill` — manual stop для restart manager, а не process-crash injection; тест использует
  SIGUSR1 handler с exit 1 и проверяет настоящий bounded on-failure restart.
- Чистый native checkout не имел `reports`: lifecycle проходил, но запись benchmark давала
  FileNotFoundError до создания JUnit. Добавлен mkdir непосредственно перед записью отчёта.

## 7. CI, отдельный Runner и сохранность окружения

Старый Docker/TLS/DinD wrapper и его wait/inspect completion fix сохранены.
Новые jobs: separate runtime image scans и обязательный native `integration:runtime-e2e`.
Native CI требует двух Engine IDs и реальной delegation; pending/failed не считается успехом.
Same-stage dependency сериализует старый managed-stack и новый native job на общей VM,
сохраняя mandatory gates и не меняя concurrency старого Runner.
С отдельного последующего разрешения пользователя на VM добавлены новый locked project
Runner №5 (`runtime-rootless`, no untagged, concurrent=1), отдельная учётная запись без sudo/
rootful Docker, два rootless user-services и отдельный hardened Runner service.
Регистрация подтверждена GitLab как online, после успешной native репетиции пауза снята.
Старая пустая регистрация №4 удалена с отдельного подтверждения, jobs в ней не выполнялись.
Подробности и риски shell executor — [ci-cd.md](ci-cd.md#отдельный-native-runtime-runner).

Настройка нашла PATH/sysctl и systemd notify предпосылки второго daemon; при ручной
регистрации исправлены недоступный cwd после sudo-u, точное имя CI_SERVER_TOKEN и boolean
CLI syntax. Пароли/token не добавлялись в Git, argv, artifacts или обычные логи.
Существующие rootful Docker/Runner не перезапускались и их config не менялся. Временный
outer engine первого native rehearsal остановлен; удалён только его новый data-root после
проверки Engine ID, отсутствия containers/volumes/mounts. Рабочие volumes не удалялись.
После копирования успешных JUnit/benchmark отчётов очищены только новые временные test
checkouts/downloads; новая регистрация/service и их engine caches сохранены. Readiness
проверялась реальным выполнением, не только UI-индикатором online. Отдельный rootless
service/linger пользователя candy, ранее явно разрешённый для первого rehearsal, сохранён;
его Docker CLI context теперь `rootless`, системный rootful daemon не изменён.
Локальный одноразовый OCI/XPKG test bundle перенесён в пользовательскую Корзину; рабочие
ключи/пакеты не затрагивались. SSH master закрыт по окончании настройки.

**GitLab pipeline нового кода ещё не запускался и зелёным не объявляется.** Нужен новый
commit SHA после отдельного разрешения на commit/push; Retry старого pipeline недостаточен.
Docker images не публиковались, production deployment и Sprint 5 не выполнялись.

## 8. Новые файлы

- `app/api/v1/deployments.py`.
- `app/domains/deployments/{__init__,artifacts,contracts,model,service}.py`.
- `migrations/versions/0011_deployment_runtime.py`.
- `scripts/deployment_agent/{__init__,__main__,engine,preflight,protocol,state}.py`.
- `scripts/runtime_artifact.py`, `scripts/runtime_images.py`.
- `examples/modules/hello-runtime/{Dockerfile,hello.py,manifest.json}`.
- `tests/runtime_helpers.py`, `tests/test_deployment_agent.py`, `tests/test_deployments.py`,
  `tests/test_runtime_artifacts.py`, `tests/integration/test_deployment_control.py`,
  `tests/integration/test_runtime_e2e.py`.
- `docs/deployment-agent.md`, `docs/module-runtime.md`, `docs/module-runtime-architecture-audit.md`,
  `docs/module-runtime-artifacts.md`, `docs/module-runtime-development.md`,
  `docs/module-runtime-lifecycle.md`, `docs/module-runtime-networking.md`,
  `docs/module-runtime-recovery.md`, `docs/module-runtime-security.md`, этот отчёт.

## 9. Изменённые существующие файлы

- `.env.example`, `.gitlab-ci.yml`, `Dockerfile`, `Makefile`, `README.md`, `pyproject.toml`,
  `compose.dev.yaml`, `compose.yaml`, `deploy/postgres/module-executor.sql`.
- `app/api/v1/installations.py`, `app/core/{authentication,config,database,module_body_limit}.py`,
  `app/domains/installations/{policy,service}.py`, `app/domains/registry.py`, `app/main.py`.
- `scripts/ci.py`, `scripts/docker_job.py`, `scripts/setup.py`.
- `tests/test_ci_tooling.py`, `tests/integration/test_managed_stack.py`,
  `tests/integration/test_module_db_privileges.py`.
- `docs/{architecture,ci-cd,frontend-module-trust,module-communication,module-installation-executor,
  module-installation-lifecycle,module-manager,runtime-database-roles,security-model,
  xpkg-specification}.md`.

## 10. Ограничения и остаточные риски

Известные ограничения первого профиля: только offline network; Python health contract;
нет пользовательских persistent mounts, public ports, arbitrary commands, HA scheduler,
live migration, Postgres module DDL или package V2/large blob transport. Runtime не заменяет
VM isolation. Native runtime CI требует отдельного tagged runner с реальной delegation.
Другие host UID требуют согласованного agent launch; pinned daemon ID не переносится
автоматически. Нет multi-host failover/scheduler/live migration, runtime secrets broker,
business data migrations, cross-module DB, frontend JS execution или лицензирования.
XPKG V1 limits 128/32/256 MiB сохранены; большие ERP images не поместятся без будущего
blob transport/V2. Download resume пока нет. Active work bounded, history сохраняется.
Недоступный host нельзя физически остановить из Core; compromised host может ложно сообщить
health — это не remote attestation. Rootless user является владельцем своего engine.
Тестовая VM общая/маленькая; для hostile workloads нужна отдельная изоляция/ресурсы.

## 11. Предлагаемый следующий спринт, без реализации

Sprint 5: отдельный Xarionix Web на Angular 21/Spartan NG, Keycloak PKCE login, компании/
сотрудники/RBAC, Module Manager, XPKG upload, просмотр/approval install и deployment plans,
реальные runtime states/monitoring и module navigation. Начать с auth/API contracts и
read-only navigation; dynamic frontend module execution не выводить из факта trusted runtime.
