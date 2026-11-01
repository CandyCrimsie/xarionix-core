# Sprint 1.1 — реализация и проверка

Исторический отчёт первого прогона. Актуальный Docker-executor contract и дополнительные проверки после job `validate:compose` — в [ci-cd.md](ci-cd.md) и [docker-executor.md](docker-executor.md). Числа ниже относятся к первому прогону.

Дата: 01.11.2026. Изменения выполнены только в `xarionix-core`, без commit/push, публикации образов или production deployment.

## Исправленные причины ошибок

1. **Некорректный tmpfs.** В YAML flow sequence запятые разделяли строку `/tmp:rw,...` на несколько mount paths, включая `noexec`. Во всех Compose-файлах теперь одна quoted строка на tmpfs. Core/migrate: `rw,noexec,nosuid,nodev,size=64m`; Nginx: аналогично, 32m. Keycloak: `rw,nosuid,nodev,size=128m`; возможность исполнения native JVM libraries сохранена и объяснена комментарием.
2. **Неявное создание bind directories.** Все bind mounts переведены на long syntax с `read_only: true`, `create_host_path: false`. Отсутствующий realm/config больше не превращается в каталог. Named volumes также имеют явные source/target; PostgreSQL 18 использует `/var/lib/postgresql`, имена существующих volumes не изменены.
3. **Две сборки одного image tag.** Общий build для Core и migrate мог приводить к конкурентному экспорту одного tag. Теперь build определён только у Core, migrate использует тот же образ. Установщик явно скачивает инфраструктурные images, не пытаясь pull локального приложения migrate.
4. **Уязвимости за пределами requirements.lock.** Реальный Trivy scan исходного Debian runtime обнаружил HIGH findings в системных пакетах и vendored библиотеках установочных инструментов. Runtime переведён на закреплённый Alpine 3.24 с Python 3.13.18; pip и bundled ensurepip удалены из финального образа. Пороги scanner не ослаблены, unfixed vulnerabilities не скрываются. После смены базы повторены сборка, запуск и integration-тесты.
5. **Загрязнение build context.** Вложенные host `__pycache__` могли попадать в образ. Добавлены рекурсивные Dockerignore patterns для bytecode и secret files; image smoke проверяет отсутствие pip и host bytecode в `/srv/core`.
6. **Срок ожидания scanner DB.** Один из повторных Trivy-прогонов остановился на первой загрузке vulnerability DB без JSON результата. CLI подтверждает штатный общий timeout 5m, включающий download более 131 MiB. Установлен явный 12m timeout внутри 15m Docker deadline; старый JSON удаляется перед scan, отсутствие нового результата остаётся ошибкой, а не «0 vulnerabilities».

Приложение, auth/RBAC-политика, OIDC issuer/backchannel и схема identity не переписаны. Новых миграций данных не требуется. Настройки read-only, non-root, cap-drop и no-new-privileges сохранены.

## Что добавлено

- GitLab pipeline из семи стадий: validate → lint → test → integration → security → build → publish.
- Отдельные unit и настоящие Docker integration jobs; отсутствие daemon/runner не выдаётся за успешную интеграцию.
- Временные Compose/TLS/env fixtures для dev, production external и production managed. Production `.env` и сертификаты не читаются и не меняются.
- Проверка mounts, networks, healthchecks, migration dependencies, DB isolation и опасных Docker privileges.
- JUnit и Cobertura artifacts, процент coverage в MR и минимальный порог **70%** после измерения baseline.
- Bandit, pip-audit для обоих lock-файлов, pinned Trivy для candidate и точного финального image, Gitleaks по истории и неигнорируемым исходникам. Единственное Gitleaks-исключение ограничено точным не-секретным JDBC endpoint и фиксированными файлами.
- Multi-stage/BuildKit build, кешируемый слой dependencies, OCI metadata, non-root/read-only smoke, checksum image artifact.
- Release publish только с protected version tag, совпадающим с Python package version. Credentials — стандартные GitLab job variables, password передаётся через stdin. Публикуются version и `sha-<commit>` tags, deployment отсутствует.
- Make targets для validate/check/compose/dev status/logs/endpoints/integration/build/scan. `dev-down` не удаляет volumes; destructive dev reset не добавлен.

## Фактически выполненные проверки

Окружение: macOS, Docker Desktop с Linux arm64 containers, Docker Engine 29.9.2, Compose 5.6.1; host Python 3.12.14, image Python 3.13.18. Результаты относятся к локальному окружению, не к GitLab серверу.

| Проверка | Результат |
|---|---|
| `make check` | Успешно: repository validation, Ruff/format, Mypy, shell syntax, unit/coverage, Bandit, оба pip-audit, три Compose config |
| Unit/API/regression tests | **148 passed**, 4 integration deselected; без отключения прежних тестов |
| Coverage `app` + `scripts` | **78.62%**; `reports/unit.xml`, `reports/coverage.xml`; integration coverage в этот процент не включён |
| Mypy | 23 source files без ошибок |
| Ruff Format | 33 файла проверены |
| `docker compose config -q` | Успешно для dev, production external и production managed на временной конфигурации |
| `python -m scripts.compose_check --nginx` | Оба production режима прошли настоящий `nginx -t` в одноразовых контейнерах с test-only TLS files |
| `make dev-up` и повторный запуск | Две PostgreSQL, Keycloak, Core healthy; Alembic завершился с exit 0 |
| `make dev-test` | live 200, ready 200, `/api/v1/me` без токена 401; discovery/JWKS доступны |
| Docker integration | **4 passed**, без skip: реальный Keycloak token → Core → PostgreSQL; повторный up/restart с сохранением UUID; discovery/JWKS/tmpfs; external mode и concurrent identity provisioning |
| Mount interpretation | Docker HostConfig и `/proc/mounts` подтвердили единственный `/tmp` с `noexec,nosuid,nodev,size=65536k` у Core |
| Сохранность dev databases | Идентификаторы обоих PostgreSQL-кластеров до/после повторного запуска совпали; существующие volumes не удалялись |
| Production image build/smoke | Успешно, `xarionix-core:sprint-1.1`; UID 10001, read-only, OCI metadata, live 200, при недоступных зависимостях ready 503 и `/me` 401 |
| Экспорт image artifact | `dist/core-image.tar` (42.2 MiB) и metadata descriptor созданы локально; SHA-256 перепроверена, в Registry ничего не отправлено |
| Security | Bandit и pip-audit обоих locks без findings; Gitleaks history + working tree без утечек; Trivy Core image без HIGH/CRITICAL |
| Дополнительно | `pip check` и `git diff --check` успешны |

Installer regression-тесты проверяют RU/EN, managed/external configuration, повторный запуск/backup, TLS hostname/key/permissions, `.env` 600, генерацию secrets и их отсутствие в stdout/stderr. Добавлены отдельные случаи отсутствующего Docker CLI и недоступного daemon; ошибки остаются локализованными. Production installer на реальных доменах не запускался.

Disposable integration projects имеют собственные случайные имена, credentials, networks и volumes. Их teardown удалял только созданные ими ресурсы. Dev environment оставлено работающим; `down -v`, глобальные prune и удаление существующих данных не выполнялись.

## Изменённые файлы

### Docker и local tooling

- `compose.yaml`, `compose.dev.yaml`, `compose.keycloak.yaml` — mounts и единственный build owner.
- `Dockerfile` — pinned Alpine, multi-stage cache, installer-free non-root runtime, OCI labels.
- `.dockerignore`, `.gitignore` — исключение bytecode, secrets и временных reports/config.
- `Makefile` — команды проверок и безопасного dev lifecycle.
- `pyproject.toml`, `requirements-dev.lock` — pinned build backend, pytest-cov/coverage, coverage configuration.
- `scripts/setup.py` — pull только инфраструктурных сервисов; существующий `install.sh` сохранён.

### CI и тесты

- `.gitlab-ci.yml`, `.gitleaks.toml` — pipeline gates, publication rules и точечное false-positive исключение.
- `scripts/validate.py` — metadata/YAML/shell/example env/secret-file validation.
- `scripts/compose_check.py` — disposable config fixtures, normalized Compose/security audit, Nginx check.
- `scripts/ci.py` — preflight/build/smoke/scanners/export/publish/dev checks и ограниченный CI cleanup.
- `tests/test_ci_tooling.py` — 33 regression cases для mounts, CI gates, scanners, credentials, cleanup и installer failures; OCI metadata совместимы с HTTP/HTTPS URL self-hosted GitLab и не принимают credentials.
- `tests/integration/test_managed_stack.py` — реальный isolated stack, data persistence, JWKS и mount assertions.
- `README.md`, `docs/ci-cd.md`, этот отчёт — запуск, runner contract, release/security policy и результаты.

## Что не проверено и что требуется в GitLab

1. **GitLab Pipeline ещё не запускался на GitLab.** Локально проверены YAML и invariants, исполнены соответствующие команды, но серверный CI Lint, фактические job permissions/artifacts/MR coverage требуют настоящего pipeline.
2. **Registry push не выполнялся.** Publisher покрыт regression-тестами, без передачи настоящих credentials и без публикации. Нужны включённый Container Registry, protected release tags и server-side protection release image tags.
3. Нужны обычный Linux Docker executor для Python jobs, выделенный Linux shell runner `xarionix-docker` с локальным daemon/shared filesystem и отдельный protected runner `xarionix-release`. Docker group даёт root-equivalent доступ: MR jobs должны выполняться на изолированном ephemeral runner, не production host. Privileged DinD автоматически не подключён.
4. На runner нужны Python 3.12+, Make, Git, OpenSSL, Docker/Compose 2.24+, сеть к публичным registries/PyPI/vulnerability DB и достаточно ресурсов. Artifacts должны допускать image tar (рекомендуемый лимит 1 GiB).
5. **Linux amd64 и именно Compose v2** локально не прогонялись; выполнен Linux arm64 на Docker Desktop/Compose 5.6.1. На целевом runner обязательно повторить те же обязательные gates. Alpine/musl зависимости прошли arm64 integration, но это не доказательство для любой архитектуры.
6. Production DNS, доверенная TLS chain, настоящий внешний Keycloak и HTTPS end-to-end не проверялись: только тестовые config, Nginx syntax и external integration layer с реальным одноразовым Keycloak. Рабочие сертификаты/production services не использовались.
7. Trivy gate охватывает **Core runtime image**, а не все инфраструктурные/CI images. Пакетные advisories меняются: сегодняшний чистый scan не гарантирует отсутствия будущих CVE. Build backend имеет фиксированную версию; транзитивные build dependencies не оформлены отдельным hash lock.
8. На долгоживущем runner остаются build images/cache; рекомендуется ephemeral VM lifecycle. Не добавлен глобальный cleanup, который мог бы удалить чужие данные. Prerelease tags, multi-arch manifest publication и automatic deployment отложены.

Подробная настройка и команды — [CI/CD](ci-cd.md). Безопасный локальный повтор:

```bash
make check
make dev-up
make dev-test
make integration-test
make docker-build IMAGE=xarionix-core:local
make docker-scan IMAGE=xarionix-core:local
```
