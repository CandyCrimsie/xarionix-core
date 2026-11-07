# Sprint 6B — реализация и фактические проверки

Рабочие исходники, проверки 6–7 ноября 2026. HEAD при начале: Core
`6b2bbf813d717f994b3695f2ae26baeecdfa6a45`, Web
`3f1169c5832cfdbe9b15d2555f09531fe0e3d9d1`. Оба дерева изначально чистые. ERP checkout также был чистым; opt-in backend adapter
добавлен после contract audit как необходимое условие реальной общей session карты.
Commit, push, production deployment и изменения Runner не выполнялись.

## Web audit и объединение

ERP принимает собственные JWT/numeric company ID; Core — проверенный Keycloak
issuer/audience и UUID. Контракты не смешаны. Console pages перенесены в общий
`src/app/platform`, production bootstrap — один `src/platform-main.ts` и один
Angular shell. Администрирование `/admin` проверяет свежие серверные capabilities.
Защита API остаётся в Core. PKCE/MFA, company pages, upload/approval, hosts,
runtime и audit сохранены. Добавлены Gateway identity metadata, список Install Plans,
backup/restore controls и скомпилированная страница Hello Business.

| Критерий | Фактическое состояние |
| --- | --- |
| Один публичный Web entry point | Реализован build и проверенный HTTPS Nginx config; deployment не выполнялся |
| Одна визуальная оболочка | Реализована, без iframe и второго production SPA |
| Keycloak session Core/administration/modules | Проверена настоящим браузерным PKCE + OTP |
| Полностью мигрированные ERP API | **Не все workflow**: карта/адреса имеют проверенный OIDC bridge; исторические страницы сохранены отдельно |

Карта/ERP source и tests сохранены, существующие записи не менялись. В ERP
`08e5f63b82e38b41aa97e17355079d6ef2312977` реализован opt-in OIDC layer с собственной
ERP audience, fresh Core human/membership checks и explicit operator bindings.
Тот же реальный PKCE JWT принят обоими backend; старый HS verifier не участвует.
До binding сервер отказывает; numeric company spoof отклоняется. Web не вызывает
legacy login/refresh. Полная миграция всех исторических ERP workflow не заявлена.

## SDK и данные

SDK — отдельный stdlib-only wheel. Handler registration, UUID context, deadline,
ограниченные JSON schemas, API/SDK metadata, loopback health/service, graceful
shutdown и non-secret configuration реализованы. Core независимо проверяет signed
metadata, но не импортирует module Python. Ed25519 signer остаётся существующим.

Новый opt-in `module-api-stateful-v1` добавляет owned named volume к прежним
rootless/non-root/read-only/no-egress/resource checks. `/data/storage` приватен;
SQLite использует один writer, DELETE journal и transactional migrations.
Fresh-backup/approval gate предшествует несовместимой migration. Restore пишет
новую epoch и сохраняет прежнюю; uninstall/deprovision не удаляют данные.

Миграция `0013_module_storage` additive: SDK contracts, allocation metadata,
backup metadata, guards, storage-aware availability predicate и расширение
CHECK operation для backup/restore. Старые revisions не изменены. Executor получает
только дополнительные SELECT, Core credentials не передаются модулю.

## Обнаруженные ошибки

- `expected migration head` в readiness должен обновляться при additive revision;
  иначе рабочий Core после миграций отвечает 503.
- Docker inspect опускает `ReadOnly=false`: точная проверка mount теперь
  нормализует только этот false default, остальные параметры остаются закрытыми.
- Docker игнорирует tar header `.`: private storage создаётся фиксированным дочерним
  каталогом, без root helper и без ослабления read-only rootfs.
- Cached SQLite COMMIT мог обходить migration authorizer: statement cache отключён,
  есть тест rollback и запрета явного COMMIT/ATTACH.
- Enable readiness учитывал только private profile: stateful вариант проверяет
  SDK/epoch/schema/installation generation и подтверждённый job.
- Security stop не должен повторять старый restore или allocation revision:
  его storage binding формируется заново из текущего allocation.
- Git transfer Web терял пустые directories packed refs; исправлен transport и
  добавлена regression на настоящем detached Git repository.

## Проверки

| Проверка | Результат |
| --- | --- |
| ERP backend compatibility | 610 passed; real OIDC/company binding/map API regressions, PyJWT 2.15.1, без изменения существующих IDs |
| Core unit suite + SDK coverage | 895 passed, coverage 71,12%; gate 70% сохранён |
| Web ERP + platform unit | 781 passed |
| Platform compatibility tests | 117 passed |
| Browser Core/ERP/PG/Keycloak | 6 passed, реальный PKCE S256 + OTP, mobile navigation/Escape/focus, company CRUD/RBAC, signed xpkg/approval, non-admin deny, logout, реальный ERP marker write/read с прежним owner ID |
| MapLibre WebGL regression | Light/dark × DPR 1/2, errors=[]; mock map transport |
| Typecheck/build | Web, compatibility Console, legacy ERP и Core MyPy проходят |
| Core Docker build/smoke | Non-root, OCI labels, read-only startup; live 200, ready без зависимостей 503, missing token 401 |
| SDK wheel | Собран; импорт и V1 contract в отдельном чистом venv и Python -I проходят |
| Compose | Dev, external и managed config проходят с disposable inputs |
| Nginx | Настоящий nginx -t проходит с временными сертификатами |
| Security | Ruff/Bandit; pip-audit обоих locks — 0 known vulnerabilities; Gitleaks history + working tree; Trivy всех 5 Agent/module images HIGH/CRITICAL gate пройден |
| Native rootless stateful + Sprint 4D + Sprint 6A | **3 passed**, настоящий Linux/cgroup v2, 1129,48 с; отчёт `reports/native-final/native-final.xml` |
| GitLab CI новых commits | **Не запускался**: commits/push запрещены заданием |

Полный Core/PG/Keycloak integration run: **115 passed**, 3 отдельных native tests
deselected, 758,65 с. Последний safety binding дополнительно покрыт regression.
Последний полный integration run выполнен после restore ACK regressions. Локальные безопасные reports находятся в игнорируемом `reports/`. Private keys,
realm secrets, JWT и содержимое backup не включаются в artifacts.
Полный [список изменённых файлов](sprint-6b-changes.md).

## Оставшиеся границы

- Для существующих ERP данных оператор должен явно проверить и создать bindings,
  настроить ERP audience/client и включить opt-in bridge. Рабочие данные автоматически
  не связывались. Старые ERP страницы вне карты/адресов сохраняются в migration target.
- Web CI требует `CONSOLE_CORE_REF` и `CONSOLE_ERP_REF` — полные проверенные SHA после ручного
  commit/push и Repositories Read allowlist ERP (не изменялась). OpenAPI content gate не ослаблен, mutable main не используется.
- SQLite V1 — один writer, без HA и arbitrary network/database access. Лимит размера
  прикладной, не filesystem quota для произвольного злонамеренного бинарного модуля.
- Backups локальны Agent host, максимум восемь; автоматических удаления/retention,
  Secret Manager, внешней PostgreSQL capability и необратимого data deletion нет.
- Gateway сохраняет V1 single-worker relay и per-call inspection/exec. На удалённом
  SSH-forwarded engine наблюдались 10s timeouts; uncertain writes не повторялись.
  Обязательный CI job использует native socket непосредственно на Linux.
- Budget warnings Angular initial 500 kB сохраняются; error budget не повышен.

CI/CD green после новых commits не заявляется: публикация запрещена. Полная миграция
исторического ERP и production rollout остаются отдельными действиями; код SDK/storage
проверен также настоящими native контейнерами и данными, а не только unit tests.
