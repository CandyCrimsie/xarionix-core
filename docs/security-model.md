# Модель безопасности

## Доверие и отказ

JWT принимается только из `Authorization: Bearer`. Единственный issuer задаёт администратор. Разрешённые алгоритмы по умолчанию — RS256; поддерживаемый явный allowlist: RS256/384/512 и ES256. `none`, HMAC, ключи из JWT (`jku`, `jwk`, `x5u`) и неизвестные critical headers отклоняются.

Обязательны signature, `iss`, `aud`, `exp`, `iat`, `sub`, payload `typ=Bearer`. `nbf` проверяется, если присутствует: Keycloak не обязан включать его в каждый access token. Числовые даты должны быть конечными числами, не строками/boolean. ID tokens не принимаются как access tokens. Допуск часов — 15 секунд; настройте NTP.

JWKS: HTTPS с проверкой сертификата; для managed допускается только конкретный private backchannel. Никаких `verify=False`, redirect-following, proxy из переменных окружения или произвольных JWKS URL. Ограничены размер документа, количество ключей, длина JWT/kid/sub; приватные JWK и RSA вне 2048–8192 bit отклоняются. ES256 требует curve P-256. Discovery issuer проверяется до использования ключей.

Кэш ключей — 300 секунд, refresh сериализован asyncio lock. Неизвестный `kid` может вызвать refresh не чаще раза в 10 секунд, что ограничивает request amplification. Поэтому ротация с новым kid сразу после refresh может временно вернуть 401 до следующей попытки. Известный cached key допускается только до TTL; просроченный кэш **не** используется при недоступности Keycloak. Недоступный/некорректный JWKS при отсутствии пригодного кэша означает 401, а не обход проверки. После TTL readiness станет 503. Для немедленной revocation требуется отдельная будущая политика introspection/коротких токенов; локальная подпись не обеспечивает мгновенный logout.

TLS context использует доверенное системное CA-хранилище. Для собственной PKI можно добавить CA в производный образ и смонтировать trust bundle через `SSL_CERT_FILE` в **явном проверенном Compose override**; нельзя отключать TLS verification. Аналогичный trust нужен машине установщика для конечной HTTPS-проверки.

## Пользователи и полномочия

Sprint 3 использует [permission-based engine](rbac.md) и [grantability](permission-delegation.md), не статический action→roles mapping. Неизвестные, wildcard, inactive permissions/roles/namespaces не дают доступ. Owner и Platform Admin — защищённые отдельные authority boundaries. Изменения роли, назначения, delegation и invitation проходят company transaction lock и повторную проверку текущих прав; audit записывается атомарно. Protected системные definitions и compatibility assignments защищены PostgreSQL triggers.

Identity UUID связан только с `(issuer, subject)` и явным User FK. Нет email auto-linking, автосоздания администратора, локального password hash или собственного OAuth server. `/me` создаёт unclassified principal и профиль, но не права. Company API требует явного human-допуска, active User, company Membership, разрешённого действия и состояния компании. Статус service не даёт human-возможностей. Role из client header/JWT realm не учитывается. Подробности — [tenant-isolation.md](tenant-isolation.md).

Platform Admin хранится отдельно от Membership. Его чувствительный HTTP API требует настроенного exact ACR и свежего auth_time; пустая/отсутствующая/неподтверждённая политика запрещает доступ. Настройки хранятся в PostgreSQL; bootstrap/recovery — только offline operator CLI с существующим Identity UUID и аудитом. Platform Admin не получает скрытого доступа к company employees/invitations/members. Последний active owner/admin защищён от конкурентных снятий.

Приглашения содержат 256 случайных бит; DB хранит только SHA-256, secret возвращается один раз. Accept — JSON body POST с JWT и company_id; не URL/query. TTL максимум 7 дней, одноразовое использование, revoke, recipient UUID/verified email, текущие полномочия издателя перепроверяются. Owner-invitations запрещены; ownership передаётся отдельно. Неподтверждённый email не подходит даже при точном совпадении. Валидация не отражает request input в ответе.

Audit append-only на обычном DML через PostgreSQL trigger, без token/secret/body/headers; чтение только Platform Admin с MFA, metadata allowlist. Текущий app DB user также владеет схемой для Alembic и технически может менять DDL: trigger не является tamper-proof защитой от администратора БД/компрометации owner credentials. Раздельные migration/runtime grants и внешний защищённый audit sink — задачи последующего hardening, не заявленные гарантии Sprint 2.

Публичны только health и осознанно включаемая OpenAPI. `/system/info` защищён и не содержит настроек. CORS — пустой по умолчанию, только точные HTTPS origins в production; это не замена авторизации.

## Логи и ошибки

JSON logger разрешает только timestamp, level, стабильный event и безопасные request fields. JWT, cookie, пароль, SQL parameters, URL/query, заголовки и stack trace не сериализуются. Uvicorn access log отключён. Request ID валидируется либо генерируется заново и возвращается клиенту. Непредвиденная ошибка — нейтральный 500. Детали подключения не возвращаются health API.

Nginx access log отключён. Его error log ограничен критическими инфраструктурными событиями; не передавайте токены в URL. Логи Docker/Keycloak администратор всё равно должен считать служебными и ограничивать доступ/retention. Не публикуйте `docker compose config`, `docker inspect`, env-файлы и вывод secret manager: они могут содержать credentials.

## Секреты и инфраструктура

Installer не использует shell source/eval для `.env`. Значения экранируются literal single quotes; повторяющиеся переменные отвергаются. Secrets — 32 random bytes в hex; env/backup/private key — 600. На non-root установке Nginx UID совпадает с владельцем ключа, на root ключ копируется с владельцем non-root UID. Публичный realm JSON не содержит пользователей, паролей или client secret.

Секреты находятся в закрытом `.env`, а контейнерные environment доступны Docker-администратору. Это не vault. Используйте защищённую машину, encrypted backups, ограниченный Docker-доступ; будущая интеграция secret store не подменяется обещаниями текущего спринта.

DB-порты закрыты; SQL accounts Core и Keycloak независимы и не superusers. Нет Docker socket в Core. Nginx выполняет TLS и перезаписывает X-Forwarded-* вместо доверия к пользовательским значениям. Не публикуйте Keycloak management9000. Административную Console защищайте сетевыми правилами/MFA согласно политике организации.

Bootstrap Keycloak master admin — временный административный доступ к IdP, **не** администратор Core. После установки создайте именованного постоянного администратора с MFA и удалите bootstrap-admin. Повторное указание bootstrap env не пересоздаёт пользователя в существующей master DB.

## Проверки цепочки поставки

`make security`: Bandit + `pip-audit --strict` по runtime lock. `make lint/typecheck/test`: Ruff, Mypy, pytest и shell syntax checks. Точечные Bandit exceptions у deployment subprocess обоснованы fixed executable argv без shell. Container image scanning и проверка SBOM/signatures выполняются вашей CI; digest защищает от незаметной замены тега, но сам по себе не доказывает отсутствие уязвимостей.

Первый спринт не заменяет внешний security review, pentest, резервное копирование и проверку восстановления.

## Разделение migration/runtime DB roles — оценка и rollout

В Sprint 3 автоматическое разделение credentials **не выполняется**. Текущий `core_app` уже владеет business tables/functions и используется both migrate/Core в существующих volumes. Одной Alembic revision/замены `.env` недостаточно: смена ownership может лишить текущий migrate доступа, а смена password в env не меняет существующую SQL role. Без отдельного согласованного maintenance rollout это риск потери управляемости работающей установки.

Конкретный следующий rollout:

1. Backup/restore rehearsal; inventory владельцев всех таблиц, sequences, функций, schema, Alembic и default privileges. Проверить версии triggers и extensions на копии существующей DB.
2. Создать отдельную NOLOGIN schema-owner role, отдельную LOGIN migration role (с контролируемым SET ROLE owner) и оставить runtime LOGIN без membership в owner/migrator. Secrets хранятся отдельно в operator secret store.
3. Под maintenance перенести ownership **явного списка Core objects** к schema-owner; не выполнять необдуманный cluster-wide REASSIGN OWNED. Отозвать CREATE в schema/public и ALTER/DROP у runtime. Runtime получает только CONNECT/USAGE и минимальные SELECT/INSERT/UPDATE/DELETE на business tables; audit — SELECT/INSERT, каталог — SELECT.
4. Для автоматического seed/sync системных ролей потребуется reviewed SECURITY DEFINER вариант с закреплённым `search_path=pg_catalog,...`, владельцем schema-owner и REVOKE PUBLIC EXECUTE либо минимальные DML grants, сохраняющие нынешние guards. Не ставить SECURITY DEFINER на произвольный registrar. Отдельно протестировать PG function/trigger permissions под runtime role.
5. Разделить Compose/installer настройки Core runtime и migrate, выполнить upgrade от migration credentials, runtime smoke/tenant/concurrency/direct-DML negative tests, затем включить трафик. Проверить, что runtime не может DISABLE TRIGGER, ALTER TABLE/FUNCTION, TRUNCATE audit/catalog или менять system definitions.
6. Rollback: остановить writes, восстановить проверенные ownership/grants/secrets либо backup; не удалять volumes и не менять рабочие passwords автоматически.

Это документированный следующий hardening, не заявленная гарантия Sprint 3. До rollout сервер/DB operator и текущие owner credentials остаются доверенными. Company admin/будущий модуль этих credentials не получает.
