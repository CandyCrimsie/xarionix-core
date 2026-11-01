# GitLab CI/CD и проверки Docker — Sprint 1.1

## Pipeline

Основной файл — `.gitlab-ci.yml`. Код не зависит от имени git remote или места клонирования (GitHub/GitLab). URL registry, project и credentials берутся только из стандартных GitLab variables. Автоматического production deployment нет.

| Stage | Реальные проверки |
|---|---|
| validate | Метаданные Python, обязательные файлы, YAML без дубликатов, shell syntax, безопасный `.env.example`, запрет secret files в Git; все три Compose режима и настоящий `nginx -t` на временных сертификатах |
| lint | Ruff, Ruff Format, строгий Mypy, Bash/POSIX shell syntax |
| test | `pytest -vv -m "not integration"`, JWT/API/installer/CI regressions, JUnit и Cobertura coverage |
| integration | Отдельный случайный Compose project, две PostgreSQL, Alembic, Keycloak, Core, настоящий JWT, discovery/JWKS, повторный `up` и restart, сохранность identity, проверка actual tmpfs |
| security | Bandit, pip-audit runtime/dev locks, Gitleaks по доступной Git history и актуальному неигнорируемому working tree, Trivy candidate image |
| build | Production multi-stage build, OCI labels, запуск образа non-root/read-only, **повторный Trivy именно финального образа**, image archive и checksum descriptor |
| publish | Только protected version tags: проверка artifact checksum/revision/labels, повторный image smoke, registry login через stdin, push двух тегов; без deployment |

Стадии последовательно являются обязательными gates; независимые jobs одной стадии выполняются параллельно. Candidate scan в security не заменяет проверку финального build: итоговый образ сканируется ещё раз, экспортируется и передаётся publish **без пересборки**. Не используется `allow_failure` для security/integration. Сбой базы у image smoke ожидаемо даёт ready=503 и `/me`=401: успешную интеграцию с DB/IdP проверяет отдельный полный стек.

### События

- Merge Request: все проверки и build, **без push образов**.
- Push в default branch (обычно main): все проверки и build, **без release-публикации**.
- Protected tag `vX.Y.Z` / `X.Y.Z`: все проверки, build и publish. Версия должна совпадать с `project.version` в `pyproject.toml`.
- Feature branch без MR: базовые validate/lint/unit/security; дорогие integration/image build выполняются при MR или manual pipeline.
- Web/manual pipeline на ветке: полный прогон без release push.
- Неподходящие/неprotected tags: pipeline не создаётся. Prerelease tags пока не публикуются.
- Для push feature branch с открытым MR branch pipeline подавляется; MR pipeline остаётся. Default branch не исключается этим правилом.

Правила соответствуют [GitLab workflow rules](https://docs.gitlab.com/ci/yaml/workflow/). Наличие YAML и локальных тестов **не означает**, что pipeline уже запускался на сервере GitLab.

## Runner: настройка обязательна

### Обычные Python jobs

Linux Docker executor без privileged mode, закреплённый Python image из YAML. Перед установкой locked Python tools ставится Git из подписанного OS package repository. Нужны исходящие соединения к PyPI и OS repositories. Нет Docker socket/DinD и production secrets. В CI используйте согласованную версию GitLab, поддерживающую `coverage_report` и `artifacts:access`.

### Docker jobs

По умолчанию используется **выделенный Linux shell executor** с tag `xarionix-docker`:

- Python 3.12+, venv/pip, Git, Make, OpenSSL;
- Docker Engine с BuildKit, Compose **2.24+**;
- локальный Docker daemon с bind-mount paths, доступными из shell job;
- loopback ports для ephemeral integration containers; доступ к public image registries и Trivy vulnerability DB;
- достаточно места/памяти: ориентир 4 vCPU, 8 GB RAM, 20+ GB свободного диска для test stack, build и scanner;
- право GitLab Runner user обращаться к daemon.

Вступление в Docker group эквивалентно root-доступу к хосту. Поэтому runner должен быть project-scoped/locked, **изолированным и желательно ephemeral VM на job**, без чужих проектов, production volumes/credentials, SSH keys и общих writable caches. MR-код нельзя выполнять на рабочем сервере. После job VM уничтожается инфраструктурой runner, а не `docker system prune`.

Тег `xarionix-release` назначается **отдельному protected runner**, допускающему только protected refs. На protected version tag workflow перенаправляет туда все Docker jobs, включая integration/security/build; publish всегда требует этот tag. Не используйте один и тот же persistent Docker daemon для недоверенных MR и release. Не предоставляйте protected runner недоверенным fork MR; отключите передачу protected variables/runners в такие pipelines.

Обычный GitLab runner **не считается автоматически Docker-capable**. Если runner с нужным tag не зарегистрирован/недоступен, GitLab покажет job pending/stuck с требованием tag; это не успешный тест. Если runner выбран, но Docker CLI/daemon недоступен, preflight завершится явной ошибкой. Нельзя заменить такой job `when: never` или `allow_failure` ради зелёного pipeline.

Базовая поставка **не включает privileged DinD**. Привязка host Docker socket к Docker executor также не является безвредной заменой shell runner и не настроена автоматически. Remote DinD требует отдельного решения для host paths и loopback/network access; текущий integration runner contract — локальный daemon/shared filesystem. [GitLab описывает различия executor/DinD/socket binding и их риски](https://docs.gitlab.com/ci/docker/using_docker_build/).

### GitLab settings

1. Включить Container Registry и проверить, что стандартные `CI_REGISTRY_*` доступны publish job.
2. Зарегистрировать обычные Python runners и отдельные Docker/release runners с указанными tags; запретить untagged jobs для выделенных runners.
3. Защитить default branch и release Git tags; право создавать version tags — только ответственным за release.
4. Настроить server-side protection/immutability для release container tags. Одного условия в YAML недостаточно против MR, меняющего собственный pipeline: job token может иметь registry scope текущего проекта.
5. Не создавать production secrets в обычных CI variables. Публикация использует временные стандартные job credentials, не PAT. Если добавляются секреты позже — только protected/masked/file variables с минимальным scope.
6. Разрешить достаточно большие job artifacts: image tar может превышать стандартный лимит 100 MB; практический лимит 1 GiB. Build artifacts ограничены developer access и удаляются через день.
7. Включить требование успешного pipeline для merge. Не трактовать pending integration как успешный gate.

Точный публичный HTTP URL текущего GitLab из SSH remote определить нельзя, поэтому Pipeline badge **не выдуман**. После проверки project web URL добавьте badge штатным механизмом GitLab. `CI_PROJECT_URL` внутри настоящего pipeline заполнит OCI source автоматически.

## Variables и credentials

| Variable | Использование |
|---|---|
| `CI_REGISTRY` | Registry login endpoint |
| `CI_REGISTRY_IMAGE` | Полное имя публикуемого repository |
| `CI_REGISTRY_USER` / `CI_REGISTRY_PASSWORD` | Временные job credentials; password только stdin |
| `CI_COMMIT_SHA` | OCI revision и `sha-<commit>` tag |
| `CI_COMMIT_TAG` / `CI_COMMIT_REF_PROTECTED` | Двойная проверка release в YAML и Python publisher |
| `CI_COMMIT_REF_SLUG` | Безопасное имя ref для временных image tags |
| `CI_PROJECT_URL` / `CI_COMMIT_TIMESTAMP` | OCI source / created |
| `CI_JOB_ID` / `CI_PIPELINE_ID` | Изоляция ресурсов и cleanup только своего job |
| `GIT_DEPTH=0` | Полная доступная история для secret scan |
| `XARIONIX_RUN_DOCKER_TESTS=1` | Обязательное включение integration fixture в integration job |
| `XARIONIX_DOCKER_RUNNER_TAG` | Runner selector; protected release workflow выбирает protected runner |

Registry password не передаётся аргументом команды и не печатается. Docker auth config создаётся в private temporary directory, удаляется после publish и не попадает в artifacts/cache. Не включайте shell tracing, `CI_DEBUG_TRACE`, вывод `env`, `docker inspect` целиком или production `docker compose config` в логи.

## Integration tests

```bash
make integration-test
```

Либо `XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest -vv -m integration`. Требуется рабочий Docker; это не mock-тест. Полный запуск ждёт readiness/health с timeout (до 420 секунд для первого старта Keycloak), а не произвольный фиксированный sleep. Polling после restart использует deadline.

Compose project `xarionix-test-<pipeline>-<job>-<random>` имеет собственные volumes, networks, loopback ports, случайные credentials и отдельный test-only service-account client. Production realm templates не включают этот client/grant. В ответах pytest credentials fixture скрыты.

Fixture cleanup удаляет **только свой случайный project**. CI after_script дополнительно проверяет job label и prefix test project перед удалением оставшихся containers/networks/volumes после прерывания. Без числового `CI_JOB_ID` этот cleanup отказывается работать. Он не обращается к `xarionix-core`/`xarionix-core-dev` и не выполняет глобальные prune.

`reports/integration-diagnostics.json` при ошибке содержит только Service/State/Health/ExitCode. Raw `.env`, JWT, passwords, Docker Env и realm secrets не сохраняются как artifacts. Для расширенной локальной диагностики используйте собственную изолированную среду и не публикуйте секреты.

## Coverage и отчёты

Unit и integration запускаются отдельно. Unit job сохраняет `reports/unit.xml` и `reports/coverage.xml`; integration — отдельный JUnit. `coverage` regexp и Cobertura report формируются из одного прогона. Это обеспечивает процент в MR widget и построчные annotations при поддерживаемой версии GitLab; [эти механизмы конфигурируются отдельно](https://docs.gitlab.com/ci/testing/code_coverage/).

Coverage измеряется по `app` и `scripts`, включая installer/CI helpers, без искусственного исключения сложных участков. После добавления regression-тестов измерен baseline выше 77%; в Makefile и GitLab установлен минимальный порог 70%. Точный результат — в [отчёте Sprint 1.1](sprint-1.1-validation.md). Следующий шаг — расширять покрытие CLI orchestration и постепенно повышать порог, не исключать эти файлы из расчёта.

## Security checks

`Bandit` и `pip-audit --strict` проверяют Python; аудитируются оба lock-файла, runtime и dev. Pinned Trivy 0.76.1 проверяет HIGH/CRITICAL уязвимости Core Docker image (включая unfixed, без broad ignore). Ошибка загрузки DB/запуска scanner тоже блокирует job. Scanner читает image archive, а не Docker socket или production `.env`. Данные проекта не отправляются в облачный анализатор: скачивается публичная vulnerability DB, анализ локален. Эта проверка не означает, что отдельно просканированы все инфраструктурные и CI images.

Trivy получает `--timeout 12m` при внешнем Docker deadline 15 минут: его штатные 5 минут включают первую загрузку vulnerability DB (более 131 MiB) и могут закончиться до начала анализа при медленной сети. Progress bar отключён; сетевые ошибки не становятся успешным scan, предыдущий JSON удаляется перед новым запуском. Нужен доступ к публичному DB mirror, скрытого перехода к старым результатам нет.

Gitleaks 8.30.1 сканирует Git и snapshot неигнорируемого working tree без сети; findings редактируются `--redact=100`. `.gitleaks.toml` сохраняет default rules. Единственное исключение — **точный** внутренний PostgreSQL JDBC endpoint из двух Compose-файлов на фиксированных paths (и в самом описании исключения): generic-api-key ошибочно воспринимает `port/database` как credential. Это не пароль/username и не отключение правила. Не добавляйте baseline suppression для настоящих secrets; удалите/ротируйте найденный секрет и разберите историю.

Bandit точечно учитывает фиксированные argv без shell, SafeLoader и container-only tmpfs paths. Производственные права не ослаблены: Core/Nginx read-only, capabilities dropped, `noexec/nosuid/nodev` на tmpfs. Keycloak сохраняет исполняемый `/tmp` для возможного извлечения JVM native libraries; `nosuid/nodev` остаются.

## Build и release

```bash
make docker-build IMAGE=xarionix-core:local
make docker-scan IMAGE=xarionix-core:local
```

BuildKit используется Docker Engine; локальный layer cache ускоряет повторные сборки. Shared writable caches между недоверенными MR и release не настроены. Base image и scanner images фиксированы tag+digest; Python runtime/dev tools — lock-файлами. Core и migrate используют один app image: только `core` имеет `build`, поэтому нет двух конкурентных экспортов одного Docker tag.

При реальном сканировании исходного Debian runtime обнаружились HIGH CVE в системных пакетах, для части которых stable ещё не содержит исправлений. Вместо подавления findings Core переведён на закреплённый `python:3.13.18-alpine3.24`, после чего повторены build, startup, integration и scan. Из runtime удалены pip и bundled ensurepip: установщики и их vendored зависимости не нужны работающему API. Musl wheels проверены на arm64; amd64 должен пройти те же gates на GitLab Runner. Сборочный backend Hatchling закреплён по версии, зависимости устанавливаются отдельным кешируемым слоем. Host bytecode и secrets исключены из build context.

Release process: обновить `project.version` согласованным change (включая API version metadata и Compose image defaults), пройти MR, создать разрешённый protected `vX.Y.Z` tag. После всех gates publisher проверит artifact и загрузит:

```text
$CI_REGISTRY_IMAGE:X.Y.Z
$CI_REGISTRY_IMAGE:sha-$CI_COMMIT_SHA
```

При недоступном Registry, отсутствующих variables, неправильном tag/version или checksum mismatch publish падает. MR/main не выполняют release push. Обновление production — отдельная административная операция; pipeline ничего не деплоит.

## Локальные команды

```bash
make install-dev
make check                  # validate + lint + types + unit/coverage + Python security + compose config
make compose-check          # все 3 режима, без daemon и production .env
make dev-up                 # без смены secrets/volumes, ждёт healthy
make dev-status
make dev-test               # live/ready/401/discovery/JWKS
make dev-logs               # только локальная диагностика; не публиковать произвольные logs
make dev-down               # volumes НЕ удаляются
make integration-test       # отдельные одноразовые ресурсы, не dev DB
make docker-build
.venv/bin/python -m scripts.compose_check --nginx
.venv/bin/python -m scripts.ci secrets
```

Отдельной автоматической команды destructive dev reset нет: она не нужна для проверок и не должна случайно удалить данные.

## Диагностика mounts и запусков

Исходная конструкция `tmpfs: [/tmp:rw,noexec,nosuid,size=64m]` — YAML flow sequence из четырёх строк: параметры превратились в mount paths. Исправлено на block list с **одной quoted строкой**. В long volume syntax Compose предоставляет size/mode, но не все требуемые mount flags, поэтому tmpfs остался корректным quoted short syntax. Bind mounts переведены на long syntax с `read_only: true`, `create_host_path: false`: отсутствующий realm/config file не превращается в каталог. [Compose mount syntax](https://docs.docker.com/reference/compose-file/services/).

Нормализованный config и security audit ловят относительные tmpfs paths; integration дополнительно проверяет Docker HostConfig и `/proc/mounts`. В ожидаемом Core mount есть `/tmp` с `noexec,nosuid,nodev,size=64m`; PostgreSQL18 volume остаётся `/var/lib/postgresql`. Если отсутствует generated realm, сначала `make dev-config`; не создавайте directory вместо JSON. Если контейнер нездоров — проверьте service status и конкретный exit code, не удаляйте volume.

## Безопасные обновления

Обновляйте версии и digests по официальным registries, затем dev lock/runtime lock и package metadata согласованно. Запускайте весь `make check`, integration, build и Trivy; сохраняйте проверяемые результаты. Не заменяйте pinned images на `latest`, не используйте `allow_failure` и `--ignore-unfixed` для зелёного pipeline. Смена major PostgreSQL требует отдельной DB upgrade/restore процедуры. Перед обновлением существующей установки сделайте backups; `.env`, volumes и realm не перегенерируются ради тестов.
