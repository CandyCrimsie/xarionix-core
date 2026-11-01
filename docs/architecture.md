# Архитектура Core — Sprint 2

## Границы

Модульный монолит. `app/api/v1` — строгие DTO, тонкие маршруты и transaction dependency; `app/domains` — identity, users, companies/requests, memberships, employees, invitations, platform и audit. `app/core/access.py` — централизованные проверки principal, MFA, company action и audit writer. `app/core` также содержит конфигурацию, DB и безопасное логирование; `app/integrations/keycloak` — единый OIDC/JWKS resource-server integration. `scripts/setup.py` — stdlib-only deployment tool; `scripts/platform_admin.py` — явные offline operator actions, не HTTP bootstrap.

Пустые домены не добавлены. Полный RBAC, organizations hierarchy и modules отложены. ERP/Billing/Web не импортируются и не нужны для запуска.

## Identity Provider и БД

Keycloak отвечает за вход, пароли, MFA, federation и social login. Core проверяет access token локально по публичным ключам; не принимает пароль, не выдаёт и не обновляет пользовательские токены. Для проверки JWT Core не нужен OIDC client secret.

Managed и external используют **один** `OIDCVerifier`. Managed добавляет отдельные Keycloak и PostgreSQL, первоначальный realm import, публичный hostname и private HTTP transport для discovery/JWKS. External не запускает их и не делает Admin API-запросов.

Проверка JWT всегда использует публичный `iss`. Внутренний `http://keycloak:8080/realms/xarionix` не становится альтернативным issuer. Discovery обязан вернуть точный issuer; JWKS URL ограничен тем же issuer path. Произвольные адреса из JWT/метаданных не используются.

## Внутренняя идентичность

`identities`: стабильный UUID, issuer, subject, user_id, principal_type, created_at. Unique `(issuer, subject)`, FK к глобальному User. При JIT mutation gate и transaction-scoped keyed advisory lock предотвращают гонку, orphan User и дубли. Существующая Identity возвращается без нового INSERT. Email не служит ключом связывания. При миграции каждая прежняя Identity получает собственный User без изменения Identity UUID.

JIT создаёт профиль **без полномочий**: principal_type=unclassified. Human admission выполняется явно по Identity UUID проверенным оператором или Platform Admin. Service/unclassified не получают пользовательские company-операции. Realm roles/email/username не определяют тип principal и не дают права Core. User и Employee независимы; Employee может не иметь User. Подробнее — [users-and-companies.md](users-and-companies.md).

## Миграции

Alembic `0001_identity` сохранена; `0002_platform` добавляет таблицы, FK/check/unique/indexes, безопасный backfill пользователей, default settings и DB guard triggers. `create_all()` не используется. Compose `migrate` выполняет `alembic upgrade head` до Core; deployment advisory lock сохранён. Readiness требует `0002_platform`. Деструктивный downgrade намеренно запрещён: нужен reviewed backup/restore, не удаление бизнес-таблиц.

## Транзакции и авторизация

Request context открывает AsyncSession transaction. `Depends(..., scope="function")` завершает COMMIT и deferred checks **до** отправки HTTP success. Ошибки FK/unique/check превращаются в безопасный 409 без SQL/payload. До критической мутации блокируется singleton `platform_settings FOR UPDATE`; после этого читаются актуальные User/Membership/policies. Это простая единая точка сериализации Sprint 2, не distributed lock и не требование Redis. Все лимиты, одобрения, принятия приглашений и изменения owner/admin проходят через неё. Ограничения на последние owner/admin дополнительно проверяются PostgreSQL deferred constraint triggers; аудит записывается в той же транзакции.

Глобальный gate ограничивает write throughput; owner guard пока проверяет активные компании. Перед масштабированием требуется перейти к согласованному lock ordering per-user/per-company и targeted DB checks, сохранив нынешние concurrency-тесты. Tenant isolation не заменяется глобальной административной ролью. Подробности — [tenant-isolation.md](tenant-isolation.md).

Приложение и миграции используют `core_app` (не superuser). Отдельный bootstrap superuser нужен только entrypoint PostgreSQL и обслуживанию DB. Keycloak имеет собственные DB, volume и роли; credentials не передаются Core.

PostgreSQL healthcheck проверяет TCP loopback, не Unix socket: временный init server официального образа не должен преждевременно разрешать запуск миграций до завершения role provisioning. Это согласовано с [entrypoint Docker PostgreSQL](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).

## Развёртывание

Production: только Nginx публикует 80/443. Core:8000, PostgreSQL:5432, Keycloak:8080/9000 не публикуются. Две закрытые DB-сети и edge-сеть для reverse proxy / исходящего HTTPS. Nginx перезаписывает proxy headers; приложение не доверяет forwarded headers. TLS завершается на Nginx; managed Keycloak принимает только непубличный HTTP за ним.

Образы фиксированы tag + digest, Python-библиотеки — lock-файлами. Core работает UID 10001, root filesystem read-only, capabilities удалены. Nginx также non-root/read-only. PostgreSQL и Keycloak сохраняют необходимые им writable paths; Keycloak выполняет стандартную initial augmentation при `start`, поэтому его root filesystem намеренно не read-only. Docker socket отсутствует.

Отдельный `compose.dev.yaml` использует loopback HTTP и отдельные volumes. Автоматического fallback из production в development нет. API/DB/migrations не подменяются SQLite или mock-реализациями при сбоях.

## Ограничения

Нет высокодоступного deployment, Redis, distributed JWKS cache, общего SDK, UI, service-to-service business permissions и полноценного RBAC. Минимальные company роли централизованно сопоставлены действиям, не размножены по JWT/HTTP handlers. Redis не запускается ради заполнения стека. Кэш ключей локален процессу; смена доверенного issuer требует проверенной конфигурации. Рабочая схема рассчитана на один явно настроенный issuer, а не на произвольные IdP компаний.
