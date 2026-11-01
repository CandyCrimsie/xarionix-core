# Установка и эксплуатация

## До запуска

Linux; Python 3.12+; Docker/Compose v2+; OpenSSL; `ss` из iproute2. Установщик не устанавливает системные пакеты и не меняет firewall/DNS. Нужны Docker access и возможность записи каталога; rootless Docker допустим при заранее настроенной публикации 80/443. Проверьте доступное место для образов, двух PostgreSQL volumes и backups. Не используйте совместный volume с ERP.

Подготовьте два DNS-имени в managed (`core.example.org`, `auth.example.org`) либо одно Core + существующий issuer в external. DNS должен разрешаться и с хоста, и с клиентов. Кириллические домены указывайте в ASCII IDNA/punycode-форме, согласованной с issuer. В production используйте обычные HTTPS hostnames без URL path; Core/managed Keycloak слушают через Nginx стандартный 443. External issuer может иметь path/свой HTTPS port.

Подготовьте PEM fullchain + незашифрованный private key для каждого hostname. Ключ: владелец — запускающий установщик пользователь, права 600, не symlink. Installer проверяет соответствие ключа, имя и срок >24 ч; конечная HTTPS-проверка дополнительно проверяет доверенную цепочку. Зашифрованный ключ для unattended Nginx не поддерживается. Ввод пароля ключа в терминале не запрашивается.

Установщик не получает сертификаты автоматически и не вызывает ACME/произвольные внешние сервисы. Выпуск/продление выполняется администратором выбранным CA/ACME-клиентом отдельно и осознанно. Не отключайте TLS verification ради self-signed сертификата в production.

## Managed

```bash
./install.sh
```

Выберите язык, затем встроенный Keycloak. Укажите HTTPS URLs, точный callback будущего public PKCE-клиента и сертификаты. Callback не является endpoint Core; UI пока отсутствует. SQL passwords и временный Keycloak bootstrap password генерируются криптографически и сохраняются в `.env` (600); в stdout они не выводятся.

Перед установкой показывается подтверждение с безопасным ответом по умолчанию «нет»/«no». Повторный запуск предлагает использовать `.env` без смены секретов. На изменение конфигурации нужно отдельное подтверждение, создаётся закрытая backup-копия. Установщик не удаляет volumes и не делает `down`.

Выбираются `compose.yaml` + `compose.keycloak.yaml`. Обязательные сервисы: PostgreSQL Core, migrate, Core, Nginx; дополнительно отдельные PostgreSQL Keycloak и Keycloak. Роли `core_app` / `keycloak_app` не superusers. Инициализация SQL users выполняется только на пустом соответствующем volume. Версии PostgreSQL18 используют volume `/var/lib/postgresql`, не старый путь `/var/lib/postgresql/data`.

Realm import создаёт начальную конфигурацию только при отсутствии realm; существующие настройки/учётные записи не перезаписываются. Публичный issuer — `https://auth.example.org/realms/xarionix`. Внутренний backchannel используется только transport-слоем, не как альтернативное доверие JWT.

После первого запуска через защищённую локальную сессию администратора прочитайте bootstrap secret из `.env` в password manager (не через `cat` в записываемый терминал), войдите в master Console, создайте постоянного именованного администратора, включите MFA и удалите `bootstrap-admin`. Не оставляйте временный доступ постоянно. Секрет в `.env` можно удалить/заменить после завершения bootstrap согласно вашей secret policy; его значение не изменяет существующую master DB при рестарте. Runtime Core этот пароль не получает.

## External

В установщике выберите внешний режим. Введите issuer существующего realm. Для него нужен публичный discovery/JWKS по доверенному HTTPS; administrative credentials не запрашиваются. Точные инструкции настройки client audience и PKCE — [identity.md](identity.md).

Выбирается **только** `compose.yaml`; контейнеров Keycloak/его DB нет. Обязательны только два DB-секрета Core. `XARIONIX_OIDC_BACKCHANNEL` пуст. Не указывайте URL discovery вместо issuer. Core проверяет `iss` и не доверяет автоматически другим realm/серверам.

Переключение managed → external меняет identity namespace: прежние `(issuer, sub)` не сопоставляются по email. Старые volumes Keycloak не удаляются, но orphan containers проекта могут быть остановлены Compose; перед переключением сделайте backups. Автоматической миграции пользователей между IdP нет.

## Неинтерактивный режим

```bash
python3 -m scripts.setup init-config --env-file /secure/path/core.env --language en
# Редактором заполнить реальные URLs и TLS paths; для external изменить mode/issuer/backchannel.
python3 -m scripts.setup validate --env-file /secure/path/core.env --language en
./install.sh --non-interactive --env-file /secure/path/core.env
```

Все необходимые параметры должны быть предоставлены; молчаливых production defaults для отсутствующих secrets/URLs нет. Выбор языка отображается первым экраном; в unattended-режиме чтения stdin нет, язык берётся из файла, либо из `--language ru|en`. Для разрешённой замены отличающегося `.env` добавьте `--replace-config`. Эта опция **не** разрешает удаление volumes/DB.

Файл должен принадлежать текущему пользователю и иметь 600. Формат: `XARIONIX_KEY='literal value'`. Нет `export`, shell-подстановок, дубликатов, многострочных значений или запуска команд из `.env`. Для JSON CORS используйте, например, `XARIONIX_CORS_ORIGINS='["https://console.example.org"]'`. Пути с пробелами поддерживаются, с literal single quote — нет. Не выводите реальный `docker compose config` без `--quiet` в CI-логи.

`init-config` никогда не перезаписывает файл. Это новый шаблон, не инструмент ротации существующей DB. `.env.example` не содержит действительных паролей; `init-config` — удобный способ заполнить их без вывода на экран.

## Переменные `.env`

Все имена начинаются с `XARIONIX_`.

| Суффикс | Назначение |
|---|---|
| `ENVIRONMENT` | `production` при установке; `development` только в явном dev Compose |
| `INSTALL_LANGUAGE` | `ru` / `en`; только язык установщика |
| `KEYCLOAK_MODE` | `managed` / `external` |
| `PUBLIC_URL` | Публичный HTTPS origin Core |
| `KEYCLOAK_PUBLIC_URL` | Отдельный HTTPS origin managed Keycloak |
| `OIDC_ISSUER` | Точный публичный issuer, без конечного slash |
| `OIDC_AUDIENCE` | В deployment этого спринта `xarionix-core` |
| `OIDC_BACKCHANNEL` | Только managed: `http://keycloak:8080/realms/xarionix`; external: пусто |
| `BROWSER_REDIRECT_URI` | Точный callback public browser client, без `*` |
| `BROWSER_ORIGIN` | Точный origin того же клиента, без path |
| `DOCS_ENABLED` | `false` по умолчанию; `true` публикует docs/OpenAPI |
| `CORS_ORIGINS` | JSON список точных origins; по умолчанию `[]` |
| `DB_PASSWORD` | Пароль nonsuperuser `core_app`, random 64 hex chars |
| `DB_BOOTSTRAP_PASSWORD` | Отдельный PostgreSQL bootstrap superuser secret |
| `KC_DB_PASSWORD` | Отдельный nonsuperuser `keycloak_app` secret, только managed |
| `KC_DB_BOOTSTRAP_PASSWORD` | Keycloak PostgreSQL bootstrap secret |
| `KC_ADMIN_PASSWORD` | Временный master bootstrap admin, только первоначальный managed setup |
| `CORE_TLS_CERT` / `CORE_TLS_KEY` | Абсолютные исходные PEM paths Core |
| `KEYCLOAK_TLS_CERT` / `KEYCLOAK_TLS_KEY` | Абсолютные исходные PEM paths managed Keycloak |
| `NGINX_UID` | Non-root UID для контейнера Nginx: текущий uid или 101 при root; ключи копируются с подходящим владельцем |
| `POSTGRES_IMAGE` | Проверенный PostgreSQL tag + digest |
| `KEYCLOAK_IMAGE` | Проверенный Keycloak tag + digest, только managed |
| `NGINX_IMAGE` | Проверенный unprivileged Nginx tag + digest |

Runtime-only параметры для осознанного Compose override: `OIDC_ALGORITHMS` (JSON, default `["RS256"]`), `OIDC_CACHE_SECONDS` (300), `OIDC_REFRESH_COOLDOWN` (10), `OIDC_TIMEOUT_SECONDS` (5), `OIDC_LEEWAY_SECONDS` (15), `DB_HOST/PORT/NAME/USER`. Шаблоны Compose передают только перечисленные runtime settings, **не весь `.env`**, поэтому редактирование этих дополнительных переменных в файле само по себе не меняет runtime. Для изменения нужен явный override environment. Не допускайте `HS256`, wildcard CORS или cross-origin backchannel.

## Nginx и сертификаты

Рендерер конфигурации находится в `scripts/setup.py`; итог — `deploy/generated/nginx.conf`, TLS copies — `deploy/generated/tls`. Generated и secrets игнорируются Git/Docker build context. Config/realm публичны, private keys — 600. Только Nginx публикует 80/443. Неизвестный HTTP Host отвергается, неизвестный TLS SNI не принимает handshake. HTTP redirect использует фиксированный hostname, а не входной Host.

При установке Nginx `-t` выполняется **до запуска/применения**, затем выполняются проверка в работающем контейнере и safe reload. DNS upstream разрешается динамически Docker resolver, поэтому preflight не требует уже запущенного Core. Proxy headers перезаписываются. Ограничены body size и таймауты, TLS1.2/1.3, HSTS без preload/includeSubDomains.

После продления сертификатов:

```bash
python3 -m scripts.setup prepare --env-file .env --language ru
python3 -m scripts.setup reload --env-file .env --language ru
```

`prepare` проверяет cert/key до копирования; `reload` сначала делает `nginx -t`, только затем `nginx -s reload`. При ошибке проверки reload не выполняется. Не редактируйте пути под `/etc/xarionix` вручную в контейнере.

## Резервное копирование

Следующие примеры — **managed**, запускаются из каталога Core. В external удалите `-f compose.keycloak.yaml` и не выполняйте команды DB Keycloak. Резервируйте обе DB согласованным maintenance-процессом; для большого production рассмотрите PostgreSQL continuous archiving/PITR отдельно.

```bash
umask 077
mkdir -p backups
docker compose --env-file .env -f compose.yaml -f compose.keycloak.yaml exec -T postgres \
  pg_dump -U core_bootstrap -d xarionix_core -Fc > backups/core.dump
docker compose --env-file .env -f compose.yaml -f compose.keycloak.yaml exec -T keycloak-postgres \
  pg_dump -U keycloak_bootstrap -d keycloak -Fc > backups/keycloak.dump
```

Проверяйте exit status/целостность dump, не считайте пустой файл успешной копией. Архивируйте также `.env`, TLS и точную revision исходников/образов; храните их **зашифрованно**, вне сервера и с ограниченным доступом. Generated realm JSON не заменяет DB backup Keycloak: он не содержит живых пользователей/изменений Console. Не добавляйте dumps в Git. Регулярно проверяйте восстановление в отдельном Compose project.

## Обновление и восстановление

1. Сделайте и проверьте backups обеих DB и секретов; запишите текущие image digests / revision.
2. Обновите код и согласованные image/lock pins, выполните тесты/security scan.
3. Повторно запустите установщик с существующим `.env`. Он не меняет SQL passwords или realm, применяет Alembic перед Core и проверяет readiness.
4. При сбое не удаляйте volumes и не генерируйте новые secrets. Смотрите `docker compose ... ps`, безопасные Core logs и readiness. CLI install намеренно не копирует raw subprocess output в обычные логи: Docker diagnostics может содержать секреты.

Для аварийного восстановления **осознанно** остановите Core/Keycloak, восстановите правильный `.env` и совместимую версию приложения, и только затем восстановите dumps в выделенные DB с сохранёнными ролями. Например, после подготовки соответствующих DB и подтверждения администратора `pg_restore -U core_bootstrap -d xarionix_core --clean --if-exists` внутри `postgres` с dump через stdin; аналогично для Keycloak DB. Это разрушительная административная операция, установщик её не выполняет. Затем запустите Core/Keycloak и проверьте миграцию, issuer и вход. Не делайте автоматический Alembic downgrade на рабочих данных; возврат несовместимой schema требует проверенной recovery-процедуры.

Изменение SQL passwords требует явной ротации `ALTER ROLE` в нужной DB, защищённого обновления `.env` и пересоздания нужных контейнеров. Entry-point SQL скрипт не запускается повторно на непустом volume. Смена major PostgreSQL — отдельная процедура `pg_upgrade`/dump-restore, не простая смена tag.

## Диагностика без утечек

`/health/live` 200 означает живой процесс, не успешную интеграцию. `/health/ready` 503 требует проверки DB/migrations или OIDC/TLS. `/me` 401 — токен отсутствует/неверен либо нет пригодного JWKS; такой отказ никогда не отключает проверку подписи. `/system/info` не содержит внутренних URL.

Проверьте issuer byte-for-byte, audience mapper, тип access token, часы и сертификат. Не публикуйте токен целиком, env или `docker inspect`. Отсутствие Docker daemon на машине разработки не означает, что production следует запускать в небезопасном режиме.

## Границы текущей поставки

Нет автоматического ACME, HA, внешнего vault, UI или полного user administration. Production TLS/DNS и Google OAuth требуют реальной инфраструктуры администратора. Installer не устанавливает Docker, не запускает daemon и не делает системный upgrade. Изменения существующего realm остаются административной операцией; managed означает развёртывание и initial provisioning, не безусловное управление всеми последующими настройками IdP.
