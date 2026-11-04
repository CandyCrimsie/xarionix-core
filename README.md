# Xarionix Core

Sprint 4D добавляет [изолированный OCI runtime](docs/module-runtime.md), отдельный
[Deployment Agent](docs/deployment-agent.md), signed offline artifacts, approved lifecycle,
health/generation gates и safe retirement. Core не получает Docker socket и не выполняет код.
Профиль V1 — offline, без пользовательских persistent mounts и public ports; полноценный
ERP/Billing deployment этим не объявляется. [Development](docs/module-runtime-development.md),
[security](docs/module-runtime-security.md), [проверки и ограничения](docs/sprint-4d-validation.md).

Ниже сохранён контекст Sprint 4C; ограничение «standard runtime не развёртывается» относится
к 4C. В 4D поддержан только явно описанный bounded OCI profile, не произвольные backend artifacts.

Sprint 4C: глобальные module installations, immutable install plans/MFA approval,
отдельный trusted operator executor, exact dependency pins, permission epochs,
explicit autonomous instance binding и transactional recovery. Пакеты **не исполняются**,
standard runtime не развёртывается; resources-only metadata mode не означает provisioning.
[Module Manager](docs/module-manager.md), [lifecycle](docs/module-installation-lifecycle.md),
[executor/DB bootstrap](docs/module-installation-executor.md), [security](docs/module-installation-security.md),
[dependencies](docs/module-dependencies.md), [RBAC](docs/module-permission-activation.md),
[recovery](docs/module-installation-recovery.md), [проверки и границы 4D](docs/sprint-4c-validation.md).

Sprint 4B: строгий `.xpkg` V1, offline Ed25519 keygen/pack/sign/verify, publisher/key/namespace trust,
потоковый admin/MFA upload, PostgreSQL verified registry и private CAS с reverify/recovery.
Это **не installer**, не runtime loader и не лицензирование. [Спецификация](docs/xpkg-specification.md),
[подписи](docs/xpkg-signatures.md), [trust](docs/publisher-trust.md), [API/storage](docs/package-registry.md),
[путь разработчика](docs/module-development-guide.md), [threat model](docs/xpkg-security.md),
[frontend boundary](docs/frontend-module-trust.md), [DB roles](docs/runtime-database-roles.md),
[проверки Sprint 4B](docs/sprint-4b-validation.md).

Sprint 4A: отдельные machine identities/capabilities/company scopes, исходящий REST check-in, PostgreSQL command leases/идемпотентный ACK, demo autonomous agent и disposable DB privilege rehearsal. [Архитектура/API](docs/module-communication.md), [регистрация и JWT](docs/service-authentication.md), [протокол и запуск агента](docs/module-control-channel.md), [threat model](docs/module-threat-model.md), [проверки и upgrade](docs/sprint-4a-validation.md).

Sprint 3: tenant-scoped custom roles, несколько назначений, permission-based authorization, защищённые системные роли и владение, безопасное делегирование, fine-grained PostgreSQL locks и стабильные MFA fixtures. [RBAC/API](docs/rbac.md), [делегирование](docs/permission-delegation.md), [блокировки, benchmark и upgrade](docs/transaction-locking.md), [контракт модулей](docs/module-permission-contract.md), [проверки Sprint 3](docs/sprint-3-validation.md).

Sprint 2: глобальные профили, явный human/service-допуск, компании и owner/admin/member memberships, заявки, сотрудники, одноразовые приглашения, Platform Admin, транзакционный аудит. [Модель и API](docs/users-and-companies.md), [администрирование и обязательная настройка MFA](docs/platform-administration.md), [изоляция](docs/tenant-isolation.md), [проверки](docs/sprint-2-validation.md).

Sprint 1.1: исправлены Docker mounts; добавлены GitLab CI/CD, реальные изолированные integration tests, coverage и security/image gates. Настройка runners и release policy — [docs/ci-cd.md](docs/ci-cd.md). CI не выполняет автоматический production deployment.

Самостоятельное платформенное ядро Xarionix ERP/OSS/BSS. Sprint 1: безопасный FastAPI resource server, внутренняя UUID-идентичность, PostgreSQL/Alembic, Keycloak, HTTPS reverse proxy и установщик RU/EN.

Core **не зависит** от ERP, Web или Billing. Их код, авторизация и данные сюда не перенесены. Нет локальных паролей, собственной выдачи пользовательских токенов, Billing или Angular UI. Проверенный токен ещё не означает human-допуск или административные полномочия.

## Быстрый запуск разработки

Требуются Python 3.12–3.15, Make и Docker с Compose v2+. Контейнер приложения закреплён на Python 3.13.18. Установка зависимостей выполняется только в локальное виртуальное окружение.

```bash
make install-dev
make dev-config
make dev-up
```

Это **явный HTTP dev-режим**, не production: Core `http://localhost:8000`, Keycloak `http://localhost:8090`, OpenAPI `http://localhost:8000/docs`. Базы не публикуются на хост. Отдельный Compose project и volumes отделяют разработку от production. Секреты генерируются в `.env.dev` (600), не выводятся на экран. Повторный `dev-config` сохраняет их. Установщик никогда не выбирает dev автоматически.

Клиент `xarionix-browser` заранее настроен на будущий `http://localhost:4200/auth/callback`, но **Core не реализует OAuth callback или UI**. Для пользовательского access token нужен OIDC-клиент с Authorization Code + PKCE S256; пример ручной проверки и политика первого входа — в [identity.md](docs/identity.md). Не включайте password grant ради тестирования.

```bash
curl --fail http://localhost:8000/health/live
curl --fail http://localhost:8000/health/ready
# Без токена: 401
curl -i http://localhost:8000/api/v1/me
make dev-down
```

`dev-down` не удаляет volumes. Не применяйте `down -v` к рабочей установке.

`make dev-up` ждёт healthy (до 420 секунд на первый запуск Keycloak). `make dev-status`, `make dev-logs`, `make dev-test` показывают состояние и проверяют endpoints. `make compose-check` использует временные test-only `.env`/TLS/config, а не production secrets. Bind mounts не создают отсутствующие файлы как каталоги; `/tmp` сохраняет требуемые security flags.

## Production

Требования: Linux x86_64/arm64, Python 3.12+, Docker Engine с Compose v2+, OpenSSL, `ss` (iproute2), права на Docker и запись каталога проекта. Практический старт: 2 vCPU, 4 GB RAM, 20 GB свободного диска; резерв и размер DB рассчитываются отдельно. Docker group эквивалентна root-доступу. Отдельные публичные DNS-имена и доверенные TLS-сертификаты нужно подготовить заранее.

```bash
./install.sh
```

Первый экран — Русский / English. Затем проверка системы, выбор managed/external, HTTPS-домены, сертификаты, генерация DB-секретов, проверка, подтверждение, Nginx validation, миграции и health/OIDC-проверки. Все дальнейшие сообщения установщика идут на выбранном языке. `.env` не заменяется без подтверждения и резервной копии. Контейнеры/данные соседних проектов не используются.

### Неинтерактивная установка

```bash
python3 -m scripts.setup init-config --env-file deployment.env --language ru
chmod 600 deployment.env
# В защищённом редакторе заполните реальные домены, callback и пути TLS.
python3 -m scripts.setup validate --env-file deployment.env --language ru
./install.sh --non-interactive --env-file deployment.env
```

Первый экран языка сохраняется; без ввода язык берётся из `XARIONIX_INSTALL_LANGUAGE` файла. Можно явно задать `--language en`. Все обязательные параметры и секреты должны уже присутствовать. При отличии существующего `.env` потребуется `--replace-config`; прежний файл попадёт в `backups/` с правами 600. Одинаковая конфигурация не переписывается. **Не генерируйте новые DB-пароли для существующих volumes**: смена `.env` не меняет SQL-пароли.

Не добавляйте реальный `deployment.env` в Git: рекомендуется хранить его вне репозитория (абсолютный путь поддерживается). Подробности обоих режимов, TLS и эксплуатации — [installation.md](docs/installation.md).

## API

| Endpoint | Доступ | Назначение |
|---|---|---|
| `GET /health/live` | Публичный | Процесс работает |
| `GET /health/ready` | Публичный | DB, миграция и пригодные OIDC-ключи доступны; иначе 503 |
| `GET /api/v1/me` | Bearer JWT | Внутренний UUID, проверенные issuer и subject |
| `PATCH /api/v1/me`, `/api/v1/companies`, `/api/v1/company-requests` | Явно допущенный human | Профиль, создание и заявки по глобальной политике |
| `/api/v1/companies/{id}/members`, `/employees`, `/invitations` | Активное company membership + действие | Company-scoped бизнес-операции |
| `/api/v1/companies/{id}/roles`, `/members/{id}/roles`, `/me/permissions` | Текущие company permissions | Роли, назначения, effective permissions |
| `/api/v1/platform/*` | Явный Platform Admin + настроенный свежий MFA context | Политики, заявки, admin grants, безопасные метаданные и аудит; не обход company access |
| `/api/v1/platform/module-services`, `/module-instances` | Platform Admin + MFA | Явная регистрация, scopes, состояние и безопасные команды |
| `/api/v1/module-agent/*` | Dedicated machine JWT + DB binding/capability | Исходящие heartbeat, свои команды/ACK, разрешённые metadata; без human JIT |
| `GET /api/v1/system/info` | Bearer JWT | Только продукт и версии API/приложения |

В production `/docs` и `/openapi.json` отключены по умолчанию. `XARIONIX_DOCS_ENABLED=true` осознанно делает их публичными. Health не раскрывает адреса инфраструктуры или причины ошибок. Readiness не подменяет authentication.

## Проверки

```bash
make lint
make typecheck
make test
make security
# Отдельно, с работающим Docker и доступом к реестрам:
XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest tests/integration -vv
```

`make test` запускает unit/API/regression отдельно от integration и сохраняет JUnit/Cobertura в `reports/`. Полный локальный набор: `make check`, `make integration-test`, `make docker-build`, `make docker-scan`. GitLab использует 7 обязательных стадий. Как ERP/Web, Core работает на существующем group Docker executor; для Docker-проверок используется tag `debian` и отдельный rootless DinD service с TLS. Privileged разрешён только точному закреплённому service image; job не получает Docker socket VM. Настройка и ограничения — в [CI/CD](docs/ci-cd.md), результаты исправления — в [Docker executor](docs/docker-executor.md). Копировать checkout на сервер Runner вручную не требуется: это делает GitLab.

`requirements.lock` фиксирует runtime, `requirements-dev.lock` — инструменты и тесты. `make security` проверяет оба lock-файла через `pip-audit --strict`; `make docker-scan` проверяет Core image через Trivy. Runtime закреплён на Alpine, установочные инструменты из него удалены. Обновление версий и digests — только осознанное, с повторными проверками.

Документация: [архитектура](docs/architecture.md), [идентичность и Google IdP](docs/identity.md), [безопасность](docs/security-model.md), [установка, переменные и эксплуатация](docs/installation.md), [CI/CD](docs/ci-cd.md), [проверки Sprint 1.1](docs/sprint-1.1-validation.md). [Отчёт Sprint 1](docs/sprint-1-validation.md) сохранён как исторический.

## Следующие этапы

Sprint 4B: `.xpkg` specification, manifest/trust policy, signatures и compatibility checks. Полноценные Module Manager, user delegation/token exchange, business gateway, Org hierarchy, payroll, SMTP и frontend отложены. Модули не получают Core DB credentials. Readiness требует `0005_module_control`; до production upgrade прочтите [maintenance guide](docs/sprint-4a-validation.md). `make locking-benchmark` сохраняет DB comparison 0002 → 0003; module HTTP measurement встроен в новые integration tests. Read-only privilege audit: `python -m scripts.db_privileges` внутри настроенного Core-контейнера; ownership/credentials он не меняет.
