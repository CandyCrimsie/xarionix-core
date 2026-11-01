# Docker executor — исправление `validate:compose`

Дата: 01.11.2026. Продолжение Sprint 1.1; без изменения API, схемы DB, соседних репозиториев, commit/push или deployment.

## Причина

В GitLab job `validate:compose` №94 не получил Runner с требуемым tag `xarionix-docker`. Поэтому trace отсутствовал: Docker/Compose ещё не запускались. При этом обычный Python job Core уже успешно работал на существующем group Docker executor, как ERP/Web. Репозиторий GitLab Runner скачивает самостоятельно; вручную «отгружать» Core на VM не нужно.

Ранее Docker jobs предполагали Shell executor и общий filesystem с daemon. Простая замена tag не решила бы bind mounts, приватные TLS permissions, localhost интеграционных тестов и доступ к Docker. Выбран существующий Docker executor с ограниченным rootless DinD, а не job-доступ к Docker socket VM.

## Применено на Runner

Для существующей Docker-регистрации сохранены `privileged=false`, tag `debian`, остальные настройки и прежний `/cache`. Добавлены `services_privileged=true`, allowlist **только точного tag+digest rootless DinD** в двух эквивалентных registry spellings и `/certs/client` volume для TLS. Wildcards и socket VM в job volumes не добавлены.

Изменение выполнено `scripts/configure_docker_runner.py`: создана private backup исходного config, запись 0600, повторная проверка подтвердила идемпотентность. Runner перечитал config; fatal configuration errors не наблюдалось. Контейнер Runner не перезапускался, настройки ERP/Web не изменены. Токены и содержимое config не выводились в отчёт.

Privileged rootless service всё ещё имеет ненулевой риск выхода на VM. Это не безопасный способ запускать произвольный недоверенный код на production-хосте. Ограничения shared Runner, concurrency, release tags и ресурсов описаны в [ci-cd.md](ci-cd.md).

## Реализация

- `.gitlab-ci.yml` — реальный tag `debian`, закреплённые CLI/rootless images, per-job network и mTLS 2376; старые несуществующие Shell/release selectors удалены. Все семь gates и release-проверки сохранены.
- `deploy/ci/Dockerfile` — отдельный закреплённый CI toolbox с Python/Compose/Git/OpenSSL и locked tools. Production image не менялся.
- `scripts/docker_job.py` — TLS/rootless preflight, безопасная передача checkout/history, общий daemon-side workspace, запуск реальных проверок, возврат allowlisted artifacts и ограниченный cleanup. Внутренний socket и host network относятся **только к rootless service namespace**, не физической VM.
- `scripts/configure_docker_runner.py` — проверяемое, атомарное и идемпотентное изменение конкретной регистрации Runner с private backup.
- `.gitignore` — `.venv` исключает и каталог, и CI symlink. Directory-only pattern раньше оставлял symlink в working-tree scan; защита от произвольных symlinks не отключалась.
- `scripts/ci.py` — диагностическое сообщение теперь соответствует local/rootless Docker contract.
- `scripts/validate.py`, `tests/test_ci_tooling.py`, `tests/test_docker_executor.py` — проверки наличия tooling, CI gates/TLS, allowlist, безопасной передачи исходников/artifacts, cleanup и сохранности Runner config.
- `README.md`, `docs/ci-cd.md`, `docs/sprint-1.1-validation.md`, этот файл — актуальная настройка и результаты; старый отчёт сохранён как исторический.

Ещё один дефект выявлен настоящим integration-прогоном: pytest создавал TLS/realm fixtures в controller `/tmp`, недоступном sibling Compose containers. Теперь `--basetemp=.ci-tmp/pytest` размещает их в общем daemon-side volume. После исправления весь integration-прогон прошёл без skip.

## Реально выполнено

Локальное окружение: macOS Docker Desktop, Linux arm64, rootless Docker 29.9.2 по тому же digest, что в CI; Python host 3.12.14 / toolbox 3.13.18. Отдельный тестовый rootless service использовал TLS и собственные disposable ресурсы, не dev/production volumes.

| Проверка | Результат |
|---|---|
| `make check` | Успешно: metadata/YAML, Ruff/format (36 файлов), Mypy (25 файлов), shell syntax, unit/coverage, Bandit, оба pip-audit, три Compose configurations |
| Unit/API/regressions | **180 passed**, 4 integration deselected; прежние тесты не отключены |
| Coverage `app` + `scripts` | **79.83%**, порог 70% сохранён; JUnit/Cobertura сформированы |
| Rootless bridge `run compose` | Dev/external/managed Compose + оба настоящих `nginx -t` успешно; bind mounts и TLS file permissions работают |
| Rootless bridge `run integration` | **4 passed**, без skip: PostgreSQL, Alembic, Keycloak/JWT/JWKS, Core, restart/data persistence, external mode и concurrent identity |
| Rootless bridge `run secrets` | Gitleaks Git history и working tree успешно; отчёты безопасно возвращены из rootless service |
| Rootless bridge `run build` | Production build, OCI metadata, UID 10001, read-only smoke, live 200, ready 503 при недоступных зависимостях, `/me` 401, Trivy HIGH/CRITICAL успешно |
| Image artifact | Экспорт и возврат `dist/core-image.tar`/`image.json` прошли без пересборки и без Registry push |
| Remote Runner | Изменение применено, backup/0600 и auto-reload проверены; job containers остаются unprivileged |
| GitLab CI Lint | Новый незакоммиченный YAML прошёл настоящую server-side simulation для default branch; Docker jobs выбирают tag `debian`, release publish не включён. Commit и запуск jobs не выполнялись |
| Сохранность dev | После проверок PostgreSQL/Keycloak/Core остались healthy; `make dev-test` прошёл. Удалены только созданные для probe контейнер/volumes и одноразовые test TLS files |

## Что пока не проверено

Новый pipeline **не выполнялся на GitLab**: CI-код находится в незакоммиченном локальном дереве. Нужен разрешённый commit/push всех новых tooling-файлов вместе с `.gitlab-ci.yml`, затем новый pipeline. Retry старого job №94 использует старую конфигурацию и не проверяет исправление.

Полный amd64-прогон именно на Runner и Registry publish ещё не выполнялись. Публикация проверена unit-тестами и ограничена protected release tag, совпадающим с версией; реальных push образов не было. Настройки protected Git/container tags и лимит image artifacts должны быть подтверждены администратором GitLab. Runner с 2 CPU / примерно 4 GiB RAM и ограниченным свободным диском может потребовать расширения для полного последовательного стека и Trivy. Нехватка ресурсов должна давать явный сбой, а не отключение security/integration gates.

## Локальный запуск

Обычные команды `make check`, `make integration-test`, `make docker-build` остаются доступны с локальным Docker. Для воспроизведения именно executor bridge нужен **отдельный** rootless DinD daemon с валидными клиентскими TLS-файлами:

```bash
DOCKER_HOST=tcp://localhost:2376 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH=/absolute/private/test-certs \
  .venv/bin/python -u -m scripts.docker_job run compose
```

Аналогично доступны `integration`, `secrets`, `scan`, `build`. Не запускайте `publish` для проверки без явно запланированного release. Не подключайте bridge к VM socket и не отключайте TLS. Настройка Runner — отдельная административная операция, не часть обычного `make check`.
