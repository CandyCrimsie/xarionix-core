# Sprint 1: реализация и проверки

Дата проверки: 31.10.2026. Среда: macOS, Python 3.12.14 в локальном `.venv`, Docker Compose CLI 5.6.1. Docker daemon отсутствует/не запущен. Соседние проекты не изменялись; commit/push не выполнялись. Каталог Core изначально был пустым и не являлся Git repository.

## Реализовано

- FastAPI factory/lifespan, четыре минимальных endpoint, настраиваемая OpenAPI.
- SQLAlchemy 2 async + psycopg, PostgreSQL, Alembic `0001_identity`; UUID identity по `(issuer, subject)`, без паролей, email linking и автоматических привилегий.
- Общая OIDC verification для managed/external: discovery, проверка public issuer, signature/algorithm/audience/expiry/nbf, JWKS rotation/cache/refresh lock/cooldown, fail closed.
- Два production Compose-файла и отдельный явный dev Compose. Core non-root/read-only, независимые SQL roles/volumes, закрытые DB-порты, TLS reverse proxy.
- Managed initial realm import с resource/PKCE clients и audience mapper; повторный импорт существующего realm не используется как механизм обновления.
- Bash installer с первым экраном RU/EN и stdlib deployment helper: config validation, secrets generation, file permissions, backups/confirmation, mode-specific Compose, TLS checks, `nginx -t`, reload, health/OIDC verification.
- Русская документация с эксплуатацией, Google IdP и ограничениями.

## Файлы

Приложение:

- `app/main.py`, `app/api/v1/routes.py`;
- `app/core/config.py`, `database.py`, `logging.py`;
- `app/domains/identity/model.py`, `service.py`;
- `app/integrations/keycloak/oidc.py` и package initializers реальных модулей.

Схема и deployment:

- `alembic.ini`, `migrations/env.py`, `migrations/script.py.mako`, `migrations/versions/0001_identity.py`;
- `Dockerfile`, `compose.yaml`, `compose.keycloak.yaml`, `compose.dev.yaml`;
- `install.sh`, `scripts/setup.py`, `scripts/__init__.py`;
- `deploy/postgres/10-app-user.sh`, `deploy/nginx/README.md`, `deploy/keycloak/README.md`;
- `.env.example`, `.gitignore`, `.dockerignore`, `pyproject.toml`, `requirements.lock`, `requirements-dev.lock`, `Makefile`.

Проверки:

- `tests/conftest.py`, `test_config.py`, `test_oidc.py`, `test_api.py`;
- `tests/test_installer.py`, `test_deployment.py`, `test_lifecycle.py`, `test_process_smoke.py`;
- `tests/integration/test_managed_stack.py`.

Документация: `README.md`, `docs/architecture.md`, `identity.md`, `security-model.md`, `installation.md`, этот отчёт.

## Фактически выполнено

| Проверка | Результат |
|---|---|
| `make lint` | Ruff lint/format, Bash и POSIX shell syntax — успешно |
| `make typecheck` | Mypy strict: 20 source files, ошибок нет |
| `make test` / `pytest -vv` | **115 passed, 3 skipped** |
| `make security` | Bandit — без находок; pip-audit runtime lock — известных уязвимостей не найдено |
| `pip check` | Нарушений зависимостей нет |
| `docker compose config` | Managed и external валидируются реальным CLI; в external нет Keycloak services и backchannel |
| `alembic upgrade head --sql` | Offline PostgreSQL DDL генерируется без credentials |
| Container registry manifests | Доступность закреплённых tag/digest подтверждена; образы не собирались/не запускались |
| Real Uvicorn process smoke | Без DB/IdP: live=200, ready=503, `/me`=401, секретов/токена в выводе нет; процесс завершён |

Unit/API tests используют управляемые RSA keys и MockTransport, а не настоящий внешний Keycloak. Реальный process smoke не подменяет успешную интеграцию с БД: он проверяет безопасный отказ при отсутствии зависимостей. Installer tests проверяют оба языка, unattended без stdin, повторный запуск, backup policy, literal dotenv, сертификат/hostname/key permissions, отсутствие утечек и порядок Nginx preflight; Docker mutations в них подменены.

## Что не запускалось и почему

Три opt-in Docker integration tests **не выполнялись**: реальный PostgreSQL/Alembic persistence, managed token → `/me`, повторный startup Keycloak и external resource server/concurrent identities объединены в этих сценариях. Причина: Docker daemon недоступен. Не запускались production image build, настоящий `nginx -t`, полный Linux installer deployment, HTTPS с реальным DNS/certificate chain, Google federation и restore rehearsal.

Для реального прогона на машине с Docker:

```bash
XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest tests/integration -vv
```

Тесты создают случайный отдельный Compose project, свои volumes и loopback ports; очищают только этот test project. Тестовый service-account client/secret существует только в disposable realm, не в production template. Они не используют ERP/Web DB или установленный `.env`.

Отдельно нужно выполнить Linux production install с подготовленными DNS/TLS и проверить оба режима. Поэтому утверждение «весь production-спринт проверен end-to-end» пока было бы неверным.

## Зафиксированные ограничения

Нет UI, полного user/company/RBAC, ACME, HA, vault, Redis или миграции старых проектов. Изменения существующего realm выполняются осознанно через Keycloak administration; startup import его не перезаписывает. После установки требуется заменить временного bootstrap-admin постоянным администратором с MFA. Старые DB credentials не ротируются автоматически. HTTPS trust не отключается ради обхода ошибок среды.
