# Архитектура Core — Sprint 4D

4D: [Core / Agent / Runtime](module-runtime.md), [security boundaries](module-runtime-security.md).
`app/domains/deployments` — control-plane models/contracts, `scripts/deployment_agent` —
отдельный engine adapter/process. Core не импортирует adapter. `0011_deployment_runtime`
additive; прежние revisions/данные/4A protocol сохранены. Ниже — по-прежнему действующая
4C catalog/installer граница; runtime execution вынесен за неё.

Sprint 4C добавляет global module control plane, не runtime orchestrator. HTTP готовит immutable
plans/approval; отдельный operator с отдельной SQL identity повторно проверяет bytes/trust и
атомарно меняет installation/catalog/history/audit. Нет module import/exec, per-company installation
или auto-grants. [Фактическая архитектура](module-manager.md), [executor](module-installation-executor.md).

## Границы

Модульный монолит. `app/api/v1` — строгие DTO, тонкие маршруты и transaction dependency; `app/domains` — identity, users, companies/requests, memberships, employees, invitations, platform и audit. `app/core/access.py` — централизованные проверки principal, MFA, company action и audit writer. `app/core` также содержит конфигурацию, DB и безопасное логирование; `app/integrations/keycloak` — единый OIDC/JWKS resource-server integration. `scripts/setup.py` — stdlib-only deployment tool; `scripts/platform_admin.py` — явные offline operator actions, не HTTP bootstrap.

`app/domains/rbac` добавляет каталог, роли, authorization engine, grantability и доверенный namespace contract. `app/core/locking.py` разделяет блокировки ресурсов. `app/domains/modules` содержит отдельные service bindings, instance/scopes, machine authorization и короткий polling commands/ACK. Это control plane, не business gateway или package installer. Organizations hierarchy отложена. ERP/Billing/Web не импортируются и не нужны для запуска.

## Identity Provider и БД

Keycloak отвечает за вход, пароли, MFA, federation и social login. Core проверяет access token локально по публичным ключам; не принимает пароль, не выдаёт и не обновляет пользовательские токены. Для проверки JWT Core не нужен OIDC client secret.

Managed и external используют **один** `OIDCVerifier`. Managed добавляет отдельные Keycloak и PostgreSQL, первоначальный realm import, публичный hostname и private HTTP transport для discovery/JWKS. External не запускает их и не делает Admin API-запросов.

Проверка JWT всегда использует публичный `iss`. Внутренний `http://keycloak:8080/realms/xarionix` не становится альтернативным issuer. Discovery обязан вернуть точный issuer; JWKS URL ограничен тем же issuer path. Произвольные адреса из JWT/метаданных не используются.

## Внутренняя идентичность

`identities`: стабильный UUID, issuer, subject, user_id, principal_type, created_at. Unique `(issuer, subject)`, FK к глобальному User. При JIT только transaction-scoped keyed advisory lock предотвращает гонку, orphan User и дубли; singleton policy больше не блокируется. Существующая Identity возвращается без нового INSERT. Email не служит ключом связывания. При миграции каждая прежняя Identity получает собственный User без изменения Identity UUID.

JIT создаёт профиль **без полномочий**: principal_type=unclassified. Human admission выполняется явно по Identity UUID проверенным оператором или Platform Admin. Service/unclassified не получают пользовательские company-операции. Realm roles/email/username не определяют тип principal и не дают права Core. User и Employee независимы; Employee может не иметь User. Подробнее — [users-and-companies.md](users-and-companies.md).

## Миграции

Старые Alembic revisions 0001–0005 сохранены. Новая `0006_package_registry` добавляет inert package/trust tables и terminal ModuleInstance revoke guard, не меняя company RBAC. `0007_instance_history` закрывает DML delete/reinsert и TRUNCATE bypass для instance history. `create_all()` не используется. Compose migrate выполняет upgrade head до Core; readiness требует `0007_instance_history`. Destructive downgrade запрещён: нужен maintenance backup/restore. [Upgrade/storage](package-registry.md), [отдельные DB credentials и maintenance](runtime-database-roles.md).

## Транзакции и авторизация

Request context открывает AsyncSession transaction. `Depends(..., scope="function")` завершает COMMIT и deferred checks **до** отправки HTTP success. Ошибки FK/unique/check и известные transient transaction failures дают безопасный 409 без SQL/payload. Company authorization читает актуальные User/Membership/permissions после соответствующего lock. Глобальный exclusive policy lock остался только у изменения политики. Shared policy, отдельный admin lock, owner quota и company locks описаны в [transaction-locking.md](transaction-locking.md).

Owner guard проверяет только затронутые компании; Platform Admin имеет независимый global guard. DB critical-section benchmark и реальные concurrency tests проверяют отсутствие singleton-сериализации независимых company writes. Tenant isolation не заменяется глобальной административной ролью. Custom roles и конечные grant policies — [rbac.md](rbac.md), [permission-delegation.md](permission-delegation.md).

По совместимости defaults приложения/миграций используют `core_app` (не superuser, но владелец schema). Отдельные runtime/migration credentials поддержаны явно; ownership transfer не выполняется автоматически. Отдельный bootstrap superuser нужен только entrypoint PostgreSQL и обслуживанию DB. Keycloak имеет собственные DB, volume и роли; credentials не передаются Core.

`app/domains/packages` отделён от ModuleService/Instance: подписанная дистрибуция, issuer trust и будущая installation — разные сущности. Upload освобождает начальную admin transaction до streaming/hash, затем повторяет live authorization/trust перед metadata+audit commit. Private content-addressed volume хранит инертные blobs без overwrite; explicit reconcile закрывает orphan gap между FS и PostgreSQL. [Детали](package-registry.md).

PostgreSQL healthcheck проверяет TCP loopback, не Unix socket: временный init server официального образа не должен преждевременно разрешать запуск миграций до завершения role provisioning. Это согласовано с [entrypoint Docker PostgreSQL](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).

## Развёртывание

Production: только Nginx публикует 80/443. Core:8000, PostgreSQL:5432, Keycloak:8080/9000 не публикуются. Две закрытые DB-сети и edge-сеть для reverse proxy / исходящего HTTPS. Nginx перезаписывает proxy headers; приложение не доверяет forwarded headers. TLS завершается на Nginx; managed Keycloak принимает только непубличный HTTP за ним.

Образы фиксированы tag + digest, Python-библиотеки — lock-файлами. Core работает UID 10001, root filesystem read-only, capabilities удалены. Nginx также non-root/read-only. PostgreSQL и Keycloak сохраняют необходимые им writable paths; Keycloak выполняет стандартную initial augmentation при `start`, поэтому его root filesystem намеренно не read-only. Docker socket отсутствует.

Отдельный `compose.dev.yaml` использует loopback HTTP и отдельные volumes. Автоматического fallback из production в development нет. API/DB/migrations не подменяются SQLite или mock-реализациями при сбоях.

## Ограничения

Нет высокодоступного deployment, Redis, distributed JWKS cache, общего SDK, UI и service-to-service business permissions. Company RBAC использует PostgreSQL без внешнего authorization cache. Нет role inheritance, wildcard или generic policy языка. Namespace foundation не является module installer. Кэш OIDC-ключей локален процессу; смена trusted issuer требует проверенной конфигурации. Поддерживается один issuer, не произвольные IdP компаний.

Новая [module communication architecture](module-communication.md) отделяет control от будущего business plane. Machine requests не открывают human transaction/JIT, не получают Membership и не используют human permission catalog. Core принимает только исходящие check-in/ACK, не подключается к module URL. Locks: service SHARE → instance UPDATE → command; глобального singleton gate на heartbeat нет.
