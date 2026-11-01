# Sprint 2 — реализация и проверка

Дата: 02.11.2026. База: чистое дерево `5d43e64`. Изменения выполнены только в `xarionix-core`, без commit/push, release publish, production deployment или изменения GitLab Runner.

## Phase A: что обнаружено

- Реализованы Identity/JWT/installer/CI, но нет доменных Users/Companies/Membership. `/me.id` — именно Identity UUID; менять его семантику нельзя.
- Readiness жёстко ожидал `0001_identity`; обновлён вместе с миграцией.
- JWT не доказывает human principal; service-account grant реальных integration fixtures подтверждает необходимость отдельной admission policy.
- Изначально CORS разрешал только GET; добавлены существующие mutation methods для явно настроенных origins, wildcard не добавлен.
- Request validation могла отражать тело, включая secret приглашения; input/ctx больше не включаются в ошибки.
- На чистом dev-запуске Compose пытался pull локального image `migrate` до общей сборки. `make dev-up` теперь сначала `build core`, затем `up --no-build`; миграции используют тот же image.

## Сущности и миграция

`0002_platform` поверх сохранённой `0001_identity` добавляет `users`, `companies`, `memberships`, `company_requests`, `employees`, `invitations`, `platform_settings`, `platform_admins`, `audit_events`. Identity получает `user_id` FK и explicit `principal_type`. Старые Identity UUID/issuer/subject не меняются, существующие записи backfill в отдельный User без прав.

UUID PK, timestamptz, RESTRICT FK, unique company slug, unique `(company,user)` Membership/Employee и token hash; bounded strings, status/role/slug/settings checks, company-scoped indexes. Нет `create_all`, drop_all, cascade удаления бизнес-объектов или внедрения соседних моделей. Destructive downgrade явно запрещён.

Действующая компания не теряет последнего usable owner; платформа — последнего active admin с active User. Это защищено и сервисными проверками, и deferred PostgreSQL triggers. Audit append-only через trigger. Mutation gate использует PostgreSQL row lock, JIT — также keyed transaction advisory lock. Request transaction function scope завершает COMMIT до HTTP success.

Для production требуется backup и maintenance rollout: старый Core не совместим с новым обязательным Identity.user_id при INSERT. Zero-downtime upgrade не заявлен. Не сбрасывайте volumes/credentials; используйте штатный Alembic migrate service.

## Реализованные процессы

- `/me`: прежние id/issuer/subject + User UUID, principal type, профиль/status/timestamps. PATCH допускает только display_name. По умолчанию principal unclassified; service/unclassified не получают human company APIs. Suspended User не получает domain access даже с валидным JWT.
- Companies: normalized/reserved slug, lifecycle active/suspended/archived, own company pagination, owner metadata updates. Closed/approval/open хранятся в PostgreSQL; default approval, owner quota=3, invitations enabled. Quota применяется к владению, не обычному Membership.
- Requests: create/list own/cancel, platform list/approve/reject. Одобрение создаёт Company/owner и audit атомарно; replay и concurrent approval не создают дубликаты.
- Membership: owner/admin/member, active/suspended/removed, список, роль/status, исключение, выход, явная передача владения. Co-owner назначается только owner с quota check; owner invitation запрещена.
- Employees: независимая company-запись без обязательного User; явное связывание требует активного Membership той же компании. UUID другого tenant не принимается через чужой URL.
- Invitations: 256 random bits, только SHA-256 в DB, выдача secret один раз, TTL/revoke/recipient UUID/verified email. Accept POST body с company_id, повторная проверка полномочий издателя, atomic Membership + accepted. Никаких secret в URL/list/audit.
- Platform: отдельные grants, защищённые settings/user suspension/admin assignment/principal classification/requests/metadata/audit APIs. Company owner не является Platform Admin, а Platform Admin не получает company data bypass.
- Offline CLI: explicit classify/bootstrap/recovery по проверенному существующему Identity UUID. Первый JWT не создаёт admin. Bootstrap идемпотентен для того же admin, не назначает второго после первого; recovery требует отдельного подтверждения и причины. В audit offline actor_kind=operator, actor User/Identity=NULL, target UUID в resource_id — без ложного приписывания действия целевому пользователю.
- MFA enforcement: exact configured ACR + свежий numeric auth_time из проверенного access token. Пустой allowlist fail-closed; realm roles/iat/произвольный claim не являются MFA. Настройка реального IdP flow — обязательная отдельная operator action, не fake mapper.

Полный REST-контракт, ER Mermaid, policy flow и role matrix: [users-and-companies.md](users-and-companies.md). CLI/MFA/recovery: [platform-administration.md](platform-administration.md). Locking/scoping: [tenant-isolation.md](tenant-isolation.md).

## Фактически выполненные проверки

Окружение: macOS, Docker Desktop / Linux arm64, Docker Engine 29.9.2, host Python 3.12.14, production image Python 3.13.18, PostgreSQL 18.6, Keycloak 26.8.1. Интеграция использует реальные Docker/PostgreSQL/Keycloak/JWT, не SQLite и не mock backend.

| Проверка | Результат |
|---|---|
| `make check` | Успешно: repository/YAML/env validation, Ruff/format, MyPy, shell syntax, unit/coverage, Bandit, оба pip-audit, три Compose режима |
| Unit/API/regression | **229 passed**, 16 integration deselected; прежние тесты сохранены |
| Coverage `app` + `scripts` | **82.39%**, порог 70% не ослаблен; JUnit/Cobertura в reports |
| Ruff Format / MyPy | **57 файлов** отформатированы/проверены, **45 source files** без type errors |
| `make integration-test` | **16 passed**, без skip: сохранение прежних проверок + Sprint 2 workflows, tenant isolation, concurrency и rollback |
| Legacy upgrade | Реальная `0001_identity` с существующей Identity → `0002_platform`, UUID/user link/default settings сохранены; первоначальных admin grants нет |
| Concurrent JIT | 20 параллельных first-login запросов, один Identity/User, нет orphan Users, другой issuer даёт отдельную Identity |
| Concurrency | Из двух approval/accept/create сверх quota/owner demotion/admin revocation/ownership transfer только допустимый набор commits; инварианты сохраняются |
| Deferred rollback | Искусственная ошибка audit constraint на COMMIT возвращает 409, Company/Membership/audit не сохраняются частично |
| DB backstops | Direct DML не снимает последнего owner/admin и не блокирует последнего admin User; UPDATE/DELETE audit запрещены |
| `make dev-up` / повторный запуск | PostgreSQL, Keycloak, Core healthy, migrate exit 0; повтор не меняет идентификатор dev PostgreSQL-кластера и не удаляет volumes |
| `make dev-test` | live/ready 200, `/me` без JWT 401, discovery/JWKS доступны |
| `make docker-build IMAGE=xarionix-core:sprint-2` | Multi-stage build и реальный non-root/read-only smoke успешны; UID 10001, live 200, unready 503 при недоступных зависимостях, missing token 401 |
| `make docker-scan IMAGE=xarionix-core:sprint-2` | Trivy HIGH/CRITICAL без findings; security gate не ослаблен |
| `python -m scripts.ci secrets` | Git history + nonignored working tree Gitleaks без утечек, redacted reports |
| Compose / Nginx | dev/external/managed config validation; production `nginx -t` на test-only TLS/config |
| `git diff --check` | Без whitespace errors |

В integration fixtures отдельные disposable service-account identities явно допускаются оператором и используются с test-only authentication context. Это проверяет серверное enforcement на реальном JWT, **не доказывает прохождение настоящего MFA человеком**. Production realm не получает test claims/grants. Secrets, raw env и JWT не сохраняются в обычные reports.

Все test stacks имеют случайные project names и собственные volumes/networks, teardown ограничен ими. Рабочие volumes не удалялись. На момент начала проверки dev stack отсутствовал; он создан штатным `make dev-up`, а сохранение legacy Identity проверено отдельно в isolated upgrade fixture. Соседние репозитории не изменялись.

## Изменённые файлы

- `app/api/v1/routes.py`, `dependencies.py`, `schemas.py`, `tenants.py` — совместимый `/me`, typed API, pagination и безопасная transaction boundary.
- `app/core/access.py`, `authentication.py`, `config.py`, `database.py`, `app/main.py` — общий auth/action/MFA/scoping, request correlation, validation redaction, readiness и CORS methods.
- `app/domains/identity/model.py`, `service.py` — User link и race-free JIT; `app/domains/registry.py` — явные imports Alembic metadata.
- `app/domains/users/model.py`, `companies/{model,service}.py`, `memberships/{model,service}.py`, `employees/{model,service}.py`, `invitations/{model,service}.py`, `platform/{model,service}.py`, `audit/model.py` — реальные домены и операции.
- `migrations/versions/0002_platform.py`, `migrations/env.py` — новая схема/backfill/checks/triggers без изменения первой revision.
- `scripts/platform_admin.py` — operator CLI; `scripts/setup.py`, `.env.example`, `compose.yaml`, `compose.dev.yaml` — validated fail-closed MFA configuration.
- `Makefile` — build-before-up общей Core/migrate image; отсутствие dev reset сохранено.
- `tests/test_api.py`, `tests/test_sprint2.py`, `tests/integration/test_managed_stack.py` — совместимость, 49 новых unit/regression cases и 12 новых integration workflows поверх прежних четырёх.
- `README.md`, `docs/architecture.md`, `identity.md`, `security-model.md`, `users-and-companies.md`, `platform-administration.md`, `tenant-isolation.md`, этот отчёт — актуальная реализация, API, migration/operations и ограничения.

## Ограничения и Sprint 3

1. GitLab pipeline с этим незакоммиченным кодом **не запускался**. `.gitlab-ci.yml`, rootless executor bridge и Runner settings сохранены; новые тесты автоматически попадают в существующие unit/integration jobs. Нужен разрешённый commit/push перед настоящим CI. Release image не публиковался.
2. Production domains/TLS/реальный MFA flow не настраивались; default admin API закрыт до корректной настройки IdP. Offline bootstrap сам по себе не включает MFA и не делает HTTP API доступным.
3. Mutation gate — единая DB serialization point Sprint 2; это ограничение write throughput, не масштабируемая per-company lock architecture. Перед ростом нужны более тонкий lock ordering и targeted owner checks с сохранением concurrency-тестов.
4. Runtime DB user пока владеет схемой для Alembic. Append-only trigger защищает обычный DML, но не привилегированного DB owner/DDL. Следующий hardening: отдельные migration/runtime roles, защищённый audit sink, operational rate limits и pending request/invitation quotas.
5. Роли минимальные, не полноценный RBAC. Sprint 3: permission catalog/action policies/role assignments, отдельная machine authorization, explicit identity linking policy. Никакого автоматического переноса realm roles или email linking.
6. Human → service reclassification требует отдельного operator review, чтобы не блокировать действующих owners/admins. SMTP, UI, payroll, org hierarchy, Billing, module runtime, Redis и production deployment намеренно не добавлены.
