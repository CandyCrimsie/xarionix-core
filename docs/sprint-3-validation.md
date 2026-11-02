# Sprint 3 — реализация и проверка

Дата проверки: 02.11.2026. Исходная ревизия Git — `e0da385`. Работа выполнена только в `xarionix-core`; commit, push, release publish, production deployment и изменение GitLab Runner не выполнялись.

## Architecture

Статическое соответствие action → owner/admin/member заменено центральным async engine `app/domains/rbac/authorization.py`. Источник полномочий — PostgreSQL, а не Keycloak realm roles, email или пользовательские headers. Engine проверяет active human/User, company-scoped Membership и Company, объединяет активные назначения ролей одним join, фильтрует активный company-каталог и проверяет точный permission key. Отдельный `require_grantable` используется для roles, assignments и invitations.

Добавлены таблицы:

- `permission_namespaces`, `permissions` — стабильные keys, namespace owner/lifecycle и metadata защищённых разрешений;
- `roles`, `role_permissions`, `membership_roles` — company-scoped роли и несколько назначений участнику;
- `role_templates` — версионированные независимые источники копирования;
- `permission_delegations` — явная ограниченная policy делегирования;
- `invitation_roles` — company-scoped связи сохранённых приглашений с custom roles;
- `system_role_definitions` — доверенный versioned seed системных definitions, не runtime mutable API.

Каталог V1 содержит 17 Core permissions, три защищённые системные роли и два шаблона: «Управляющий компанией» и «Инженер». Пользовательская роль имеет UUID, уникальный внутри компании immutable code, active flag и optimistic version. PATCH metadata и PUT permissions требуют `expected_version`; устаревшая версия возвращает 409. Template копируется в собственный набор, а не остаётся живой ссылкой.

`Membership.role` сохранён как защищённый owner/admin/member business marker. PostgreSQL синхронизирует его system assignment; обычное назначение custom role не выдаёт Ownership. Старые Membership API и явная передача владения сохранены. Системные definitions и assignments нельзя менять через custom API или обычный прямой DML. Platform Admin не получает обход company RBAC.

Новые API включают каталог permissions/templates; CRUD company roles; GET/PUT RolePermissions; GET/POST/DELETE MembershipRoles; GET/PUT delegation; GET собственных effective permissions. Pagination, UUID, input bounds, reserved codes и mutable-field allowlists проверяются. Подробный контракт и примеры: [rbac.md](rbac.md).

## Migration

Добавлены только новые Alembic revisions:

1. `0003_locking` — замена singleton statement gate на scoped transaction locks и targeted owner/admin guards.
2. `0004_rbac` — явное создание таблиц/FK/check/index, seed каталога/templates/system roles, backfill существующих Membership и PostgreSQL-защита definitions/assignments.

`0001_identity` и `0002_platform` не изменены. Backfill не меняет Identity/User/Company/Membership UUID и исходные owner/admin/member markers. Новые компании и старый Membership PATCH используют тот же trigger-based путь, а не отдельные расходящиеся Python реализации. Pending Sprint 2 invitations сохраняются; новые приглашения дополнительно сохраняют полный permission snapshot.

Реальный integration fixture создаёт данные на `0002_platform` — Users/Identities, Company, owner/admin/member Membership, Employee, pending Invitation и audit — затем выполняет upgrade head. Проверены прежние UUID, записи и соответствующие system assignments. Отдельно сохранена проверка старой Identity из `0001_identity`.

Локальный существующий dev-кластер успешно обновлён `make dev-up`: `0002_platform` → `0004_rbac`. До обновления и после двух запусков PostgreSQL `system_identifier` одинаков: `7703322558304469031`. Число Identity и Company осталось 0/0: этот dev-кластер был пустым; проверка сохранности **заполненных** данных выполнена на отдельном disposable integration stack, не подменяется проверкой пустой базы.

Ни рабочие volumes, ни PostgreSQL credentials не пересоздавались. Destructive downgrade не реализован. Для production нужен backup/restore rehearsal и maintenance: остановить старые writes/Core, выполнить миграции, проверить head и данные, затем запустить новый Core. Zero-downtime rollout не заявлен. План: [transaction-locking.md](transaction-locking.md#upgrade-sprint-2--sprint-3).

## Concurrency

Старый HTTP/JIT/trigger gate брал `platform_settings FOR UPDATE` для независимых mutations. Даже обновление Employee компании B ожидало незавершённую запись компании A.

Теперь обычные Employee/Role mutations используют transaction-scoped company advisory lock. Quota использует отдельные отсортированные User UUID; глобальные admin операции — отдельный administration lock. Создание компании/приглашение читают policy `FOR SHARE`; её изменение берёт `FOR UPDATE`. JIT отсутствующей Identity использует keyed issuer+subject lock и unique constraint. Общий порядок: policy → administration → sorted quota → sorted company → дочерние строки; ненужные области не захватываются.

`core_check_owners` проверяет только затронутые компании, `core_check_admins` — соответствующие глобальные grants/Users. BEFORE ROW scoped guards сохраняют защиту прямого SQL. Deferred проверки допускают промежуточные изменения внутри транзакции, но запрещают невалидный COMMIT. Принудительная ошибка audit/commit откатывает и domain mutation, и audit.

После ожидания lock повторно читаются User, Membership, RoleAssignments и delegation; старый ORM identity-map snapshot не даёт grant. Это проверено реальными ожидающими HTTP-запросами: параллельно отозванные role/delegation → отказ без назначения и audit. Нет внешнего permission cache.

Lock timeout 5 s / statement timeout 10 s; deadlock, serialization, lock/query timeout возвращают безопасный 409 `transaction_conflict`, constraint conflicts — 409 `data_conflict`. COMMIT выполняется до HTTP success. Произвольный multi-row direct SQL всё ещё может создать deadlock; victim откатывается. Нет бесконечных retry или автоматического replay POST.

### Измеренный benchmark

`make locking-benchmark` действительно сравнил `0002_platform` и `0003_locking` в disposable PostgreSQL 18.6. Workload — SQL gate, UPDATE Employee, INSERT audit, COMMIT, без искусственной задержки critical section. Измерены одна/разные компании и concurrency 1/5/10/20/50, latency p50/p95/p99 и PostgreSQL Lock wait samples.

| Разные компании | До | После |
|---|---:|---:|
| Concurrency 10, throughput | 867.83 ops/s | 1778.73 ops/s |
| Concurrency 10, p95 latency | 14.572 ms | 5.149 ms |
| Concurrency 10, sampled lock waits | 67 | 0 |
| Concurrency 50, throughput | 682.02 ops/s | 1431.33 ops/s |
| Concurrency 50, p95 latency | 80.101 ms | 27.463 ms |
| Concurrency 50, sampled lock waits | 837 | 0 |

Одна компания ожидаемо остаётся сериализованной. Это DB microbenchmark на macOS/Docker Desktop arm64, не HTTP/JWT/RBAC load test и не production SLA. Все десять сравнений и ограничения приведены в [transaction-locking.md](transaction-locking.md#воспроизводимый-benchmark). Generated raw JSON находится в игнорируемом `reports/`, не содержит secrets.

## Security

Grantability не-владельца — пересечение его текущих effective permissions и явной delegation policy. Owner имеет отдельную конечную authority по `owner_grantable`, не wildcard. Protected `core.company.manage`, `core.ownership.transfer`, `core.permissions.delegate` нельзя выдать custom role или delegation. Platform Admin вообще не является company permission.

Административные capabilities create/manage/assign/revoke раздельны. Наличие `roles.manage` не разрешает выдавать произвольные права. Не-владелец не может расширить собственную назначенную роль даже разрешениями из другой роли, управлять Owner, подменить system assignment, изменять чужой tenant или выдать неделегируемый набор через template/invitation. Совместимость Sprint 2 ограничена явным случаем: системный Admin может пригласить стандартного Member, но это не разрешает custom grants.

Приглашения хранят Role links и полный permission snapshot. Accept под company lock перепроверяет issuer, его текущие capabilities/delegation, active roles и snapshot. Изменение набора роли требует нового приглашения; revoked authority не оставляет скрытый grant. Removed Membership теряет custom assignments. Composite company FK, PK/unique/check и PostgreSQL triggers дополняют сервисную авторизацию.

События `role.created/updated/deleted/permissions_changed/assigned/revoked`, `permission.delegation_changed` пишутся в ту же транзакцию; metadata не содержит токены/секреты/private claims. Append-only audit guard сохранён.

Namespaces ERP/OSS/Billing зарезервированы без доступных permissions. Строгий manifest validator и проверка доверенного namespace owner подготовлены, но применение каталога пока только reviewed Alembic deployment: нет публичного registrar, Module Manager, `.xpkg` или прямого SQL-доступа модулей. Контракт: [module-permission-contract.md](module-permission-contract.md).

Runtime DB user пока также владеет объектами для Alembic. Это существующая доверенная граница, не защита от DDL-capable DB owner. Credentials/ownership нельзя безопасно заменить одной `.env`/revision. Конкретный план separate owner/migrator/runtime grants, reviewed SECURITY DEFINER seed/sync и maintenance rollout описан в [security-model.md](security-model.md#разделение-migrationruntime-db-roles--оценка-и-rollout); автоматическая ротация не выполнялась.

## Authentication

Проблема fixture: hardcoded `auth_time` записывался при создании realm, а свежий `iat` не делает старую аутентификацию свежей. Теперь test-only mapper обновляется перед выдачей соответствующего настоящего JWT через Admin API. Обновление mapper и выдача токена сериализованы только в fixture; production realm и JWT verification не подменяются. Уменьшенный test maximum age — 300 s, не огромный обходной TTL.

Оба module-scoped integration stack начинают проверку signed authentication context: signature, issuer, audience, expiration, subject, exact ACR, integer recent auth_time; subjects всех шести тестовых principals различаются. Сохранено исправление конфликта ACR scopes. Отдельный настоящий JWT с новым `iat`, но старым `auth_time` получает отказ.

Clock в MFA unit tests управляемый. Проверены точные границы возраста/future skew, отсутствующие/неподходящие ACR, missing/invalid auth_time, boolean/string, NaN/Infinity, iat-only и пустой allowlist fail-closed — без sleep. Production enforcement не ослаблен.

Один промежуточный полный прогон получил несовместимые результаты MFA (403 административной setup и неожиданный успех stale-auth теста), хотя отдельные прогоны проходили. Точная причина этого промежуточного сбоя не установлена; clock skew после паузы среды — гипотеза, не подтверждённый диагноз. Добавлены подписанный preflight для каждого стенда и безопасный domain error code в setup assertion. Затем focused 4 tests и **два последовательных полных 47-test прогона** прошли без ослабления ожиданий. Для воспроизводимости часы host/Docker/Keycloak должны быть синхронизированы.

**Service-account flow с synthetic test ACR/auth_time не считается реальным human MFA.** Настоящий browser OTP/WebAuthn step-up E2E автоматически не выполнялся; ручная staging-процедура и негативные сценарии описаны в [platform-administration.md](platform-administration.md). Это явное ограничение, а не утверждение прохождения пользовательского MFA.

## Validation

Фактически выполнены:

| Команда / проверка | Результат |
|---|---|
| `make check` | Ruff, format, MyPy, shell/metadata, unit/API, Bandit, обе lockfile pip-audit и Compose checks |
| Unit/API `pytest -vv -m 'not integration'` | 286 passed; coverage app+scripts 80.80%, gate 70% сохранён |
| Ruff / Ruff Format | Passed; 72 Python files formatted |
| MyPy | Passed; 57 source files |
| `make integration-test`, два последовательных запуска | В каждом 47 passed, 286 deselected; 151.40 / 151.23 s; прежние 17 + новые 30 параметризованных случаев |
| Focused signed-context / old-auth-time / stale role+delegation races | 4 passed, 57.47 s |
| `make locking-benchmark` | Passed; baseline/new real PostgreSQL, десять workload combinations |
| `make dev-up`, `make dev-test`, повторно обе команды | Passed; Core/Keycloak/обе DB healthy, head 0004, cluster сохранён |
| `make docker-build IMAGE=xarionix-core:sprint-3` | Production multi-stage build + non-root/read-only image smoke passed |
| `make docker-scan IMAGE=xarionix-core:sprint-3` | Trivy HIGH/CRITICAL scan passed |
| `.venv/bin/python -m scripts.ci secrets` | Gitleaks history + non-ignored worktree passed |
| `.venv/bin/python -m scripts.compose_check --nginx` | Dev/external/managed Compose + generated Nginx validation passed |
| `git diff --check` | Passed |

Production image smoke проверяет `/health/live` 200, без зависимостей `/health/ready` 503 и `/api/v1/me` 401. Dev smoke проверяет live/ready 200, denial без JWT, Discovery и JWKS. Интеграции используют изолированные disposable Compose projects и реальные PostgreSQL/Keycloak; не рабочие dev/prod volumes.

Во время этапов дополнительно выполнялись более ранние unit/integration прогоны (до окончательного набора тестов). Они не складываются с итоговыми числами как отдельное покрытие. Старые tests не удалены/отключены. `.gitlab-ci.yml`, Compose/DinD/TLS и thresholds не ослаблены. **Новый GitLab pipeline не запускался:** без push локальные результаты не являются подтверждением удалённого CI.

## Изменённые файлы

Новые:

- `app/core/locking.py`;
- `app/domains/rbac/__init__.py`, `authorization.py`, `catalog_v1.py`, `model.py`, `registration.py`, `service.py`;
- `app/api/v1/rbac.py`, `rbac_schemas.py`;
- `migrations/versions/0003_locking.py`, `0004_rbac.py`;
- `scripts/locking_benchmark.py`;
- `tests/test_assurance.py`, `tests/test_rbac.py`, `tests/integration/test_sprint3.py`;
- `docs/rbac.md`, `permission-delegation.md`, `module-permission-contract.md`, `transaction-locking.md`, этот отчёт.

Изменены:

- `Makefile`, `README.md`;
- `app/api/v1/dependencies.py`, `schemas.py`, `tenants.py`;
- `app/core/access.py`, `database.py`, `app/main.py`;
- `app/domains/companies/service.py`, `employees/service.py`, `identity/service.py`, `platform/service.py`, `registry.py`;
- `app/domains/invitations/model.py`, `service.py`, `memberships/model.py`, `service.py`;
- `scripts/platform_admin.py`;
- `tests/test_sprint2.py`, `tests/integration/test_managed_stack.py`;
- `docs/architecture.md`, `ci-cd.md`, `platform-administration.md`, `security-model.md`, `tenant-isolation.md`, `users-and-companies.md`.

## Limitations и следующий этап

- Для production нужен maintenance upgrade и проверенный backup, не автоматический zero-downtime rollout/downgrade.
- Separate migration/runtime DB roles, внешний tamper-resistant audit sink и реальный human MFA E2E остаются отдельным hardening.
- Нет role hierarchy/ABAC, wildcards, внешнего authorization cache и произвольных per-role/per-member delegation allowlists: scopes фиксированы `custom_roles` / `non_owners`.
- 200 ролей/company, 50 assignments/Membership, 100 keys/request, 20 custom roles/invitation. Role с сохранёнными invitation references нельзя удалить: deactivation не разрушает историю.
- Консервативный grantability check распространяется и на текущий набор редактируемой/снимаемой роли. Перед будущим отключением module permissions понадобится отдельная reviewed retirement/revocation policy: нельзя обещать свободное редактирование ролей с недоступным catalog key.
- Scoped advisory locks не заменяют порядок произвольных direct SQL transactions. Deadlock victim получает rollback, не ложный успех.
- Benchmark локальный и DB-only; production capacity и end-to-end performance требуют отдельного измерения.
- Sprint 4: подписанный package/namespace lifecycle, trusted versioned registration/removal и retirement policy, модульный API/service authorization без DB credentials; не выдавать модулям Core ownership/platform права. Это следующий этап, не начатая реализация `.xpkg`.
