# Xarionix Core

Самостоятельное платформенное ядро Xarionix ERP/OSS/BSS. Sprint 1: безопасный FastAPI resource server, внутренняя UUID-идентичность, PostgreSQL/Alembic, Keycloak, HTTPS reverse proxy и установщик RU/EN.

Core **не зависит** от ERP, Web или Billing. Их код, авторизация и данные сюда не перенесены. Нет локальных паролей, собственной выдачи пользовательских токенов, компаний, RBAC, Billing или Angular UI. Проверенный токен ещё не означает административные полномочия.

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

`requirements.lock` фиксирует runtime, `requirements-dev.lock` — инструменты и тесты. `pip-audit --strict` требует сети и проверяет Python-зависимости; контейнерные образы дополнительно сканируйте средствами вашей CI/registry. Registry digests закреплены после проверки 31.10.2026. Обновление — только осознанное, с повторными проверками.

Документация: [архитектура](docs/architecture.md), [идентичность и Google IdP](docs/identity.md), [безопасность](docs/security-model.md), [установка, переменные и эксплуатация](docs/installation.md), [проверки спринта](docs/sprint-1-validation.md).

## Следующие этапы

Внутренние пользователи и профили; компании и memberships; сотрудники и оргструктура; company-scoped RBAC; затем контракты модулей/SDK и отдельная миграция ERP/Web. Пока это границы будущих доменов, не фиктивные API или пустые реализации.
