# Архитектура Sprint 1

## Границы

Модульный монолит. `app/api/v1` — HTTP-контракты; `app/domains/identity` — единственный реализованный домен; `app/core` — конфигурация, DB и безопасное логирование; `app/integrations/keycloak` — OIDC/JWKS resource-server integration. `scripts/setup.py` — отдельный stdlib-only deployment tool, вызываемый Bash-установщиком; не часть бизнес-API.

Не добавлены пустые домены ради дерева каталогов. Будущие users, companies, memberships, organizations, roles, permissions и modules получат собственные модели/сервисы/API, но будут работать в одном Core. ERP/Billing/Web не импортируются и не нужны для запуска.

## Identity Provider и БД

Keycloak отвечает за вход, пароли, MFA, federation и social login. Core проверяет access token локально по публичным ключам; не принимает пароль, не выдаёт и не обновляет пользовательские токены. Для проверки JWT Core не нужен OIDC client secret.

Managed и external используют **один** `OIDCVerifier`. Managed добавляет отдельные Keycloak и PostgreSQL, первоначальный realm import, публичный hostname и private HTTP transport для discovery/JWKS. External не запускает их и не делает Admin API-запросов.

Проверка JWT всегда использует публичный `iss`. Внутренний `http://keycloak:8080/realms/xarionix` не становится альтернативным issuer. Discovery обязан вернуть точный issuer; JWKS URL ограничен тем же issuer path. Произвольные адреса из JWT/метаданных не используются.

## Внутренняя идентичность

`identities`: UUID, issuer, subject, created_at. Unique `(issuer, subject)`. Email не хранится и не служит ключом связывания. Первый корректный `/me` выполняет PostgreSQL `INSERT ... ON CONFLICT DO NOTHING`, читает стабильный UUID и коммитит. Одновременные первые обращения не создают дубликаты.

Это JIT provisioning **идентичности**, не регистрация администратора или полноценного пользователя. Нет company membership, ролей или разрешений по умолчанию. Realm roles из JWT не преобразуются в права Core. В будущем machine identities и human users следует разделить на уровне авторизации.

## Миграции

Alembic revision `0001_identity` создаёт только таблицу идентичностей. `create_all()` не используется. Одноразовый Compose service `migrate` выполняет `alembic upgrade head` до Core; PostgreSQL advisory lock сериализует миграции. Readiness дополнительно проверяет ожидаемую revision. При добавлении новых миграций обновляйте readiness-contract одновременно.

Приложение и миграции используют `core_app` (не superuser). Отдельный bootstrap superuser нужен только entrypoint PostgreSQL и обслуживанию DB. Keycloak имеет собственные DB, volume и роли; credentials не передаются Core.

PostgreSQL healthcheck проверяет TCP loopback, не Unix socket: временный init server официального образа не должен преждевременно разрешать запуск миграций до завершения role provisioning. Это согласовано с [entrypoint Docker PostgreSQL](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).

## Развёртывание

Production: только Nginx публикует 80/443. Core:8000, PostgreSQL:5432, Keycloak:8080/9000 не публикуются. Две закрытые DB-сети и edge-сеть для reverse proxy / исходящего HTTPS. Nginx перезаписывает proxy headers; приложение не доверяет forwarded headers. TLS завершается на Nginx; managed Keycloak принимает только непубличный HTTP за ним.

Образы фиксированы tag + digest, Python-библиотеки — lock-файлами. Core работает UID 10001, root filesystem read-only, capabilities удалены. Nginx также non-root/read-only. PostgreSQL и Keycloak сохраняют необходимые им writable paths; Keycloak выполняет стандартную initial augmentation при `start`, поэтому его root filesystem намеренно не read-only. Docker socket отсутствует.

Отдельный `compose.dev.yaml` использует loopback HTTP и отдельные volumes. Автоматического fallback из production в development нет. API/DB/migrations не подменяются SQLite или mock-реализациями при сбоях.

## Ограничения

Нет высокодоступного deployment, Redis, distributed JWKS cache, общего SDK, UI, service-to-service authorization и RBAC. Redis не нужен текущей реализации; не запускается ради заполнения стека. Кэш ключей локален процессу; изменение доверенного issuer требует перезапуска с проверенной конфигурацией. Рабочая схема рассчитана на один явно настроенный issuer, а не на произвольные tenants.
