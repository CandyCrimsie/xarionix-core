# GitLab CI/CD и проверки Docker — Sprint 1.1

## Secret scan: detached checkout и packed refs

GitLab job может иметь detached HEAD и хранить все refs в `packed-refs`. Пустые
`.git/refs` и `.git/objects` всё равно нужны Git: source/history transfer сохраняет
их как directory entries, включая пустые подкаталоги. Перенос только файлов приводил
к `fatal: not a git repository` внутри rootless controller.

Перед Gitleaks проверяются обычный non-bare checkout, наличие HEAD commit,
полнота history (`GIT_DEPTH=0`) и доступность reachable objects. Неполный/повреждённый
репозиторий останавливает job до сканирования; stale reports удаляются. Затем по-прежнему
проверяются вся Git history и неигнорируемый working tree с `--redact=100` и без сети.
Clone config/reflogs/hooks/credentials не переносятся; scanner rules не отключаются.

## Gateway gates Sprint 6A

`module-gateway:unit` и `module-gateway:security` запускают contract/relay/IPC/JWT
regressions и Bandit; основной `test:unit` по-прежнему включает их и сохраняет coverage≥70%.
Прежний `integration:managed-stack` проверяет реальные PG/KC/upgrade/role privileges.
Новый обязательный `module-gateway:runtime-e2e` следует за прежним native runtime E2E
на том же `runtime-rootless` tag: signed OCI business module, реальные Agents/RBAC и
измеренные namespace/cgroups. Runner configuration/registration/policy не меняются.
Недоверенным MR нельзя открывать существующий trusted shell runner или его secrets.
Отсутствие native socket/delegation — явная ошибка, не allow_failure/успешный skip.

`security:runtime-images` дополнительно собирает gateway-agent и hello-business,
сканирует их Trivy и публикует только безопасные отчёты. Нет новых registry tokens,
автоматического deployment, секретных dotenv artifacts или global cleanup.
Локально: `make gateway-test`, затем явный dedicated native engine +
`make gateway-integration-test`; см. [development](module-gateway-development.md).

## Runtime gates Sprint 4D

Существующий rootless DinD/TLS wrapper сохранён: controller completion проверяется через
`docker wait` **и** inspect, не через exit streaming logs. Core build остаётся default target.
`security:runtime-images` отдельно собирает/smoke-проверяет Agent и Hello, сканирует оба
Trivy HIGH/CRITICAL, сохраняет отдельные JSON; Python gates охватывают новый код.

`integration:runtime-e2e` — обязательный для full pipeline native Linux **shell runner**
с tag `runtime-rootless`. Нужны Python 3.13+venv, Git, Docker/Compose и два отдельных rootless
daemon: DOCKER_HOST для disposable Core stack, `XARIONIX_RUNTIME_ENGINE_SOCKET` для пустого
runtime daemon с native cgroup v2 delegation. Engine IDs обязаны различаться. Один job на
runner (concurrent=1); отдельный unprivileged account только для доверенного проекта.
Не запускайте недоверенные fork MR на таком host и не давайте ему production secrets.
Нет privileged job, rootful socket mount или автоматической установки runner из pipeline.

Без соответствующего runner job останется pending; без socket/delegation — failed с причиной.
Это намеренно не `allow_failure` и не successful skip. Старый DinD job проверяет control
protocol, но физически не может доказать отсутствующие cgroup limits. Runner регистрацию/
теги/политику protected MR на GitLab администратор настраивает отдельно. Локальные тесты не
означают успешный GitLab pipeline; publish по-прежнему только protected release после gates.

### Отдельный native runtime runner

04.11.2026 с отдельного согласия владельца на тестовой VM добавлены **новые**, не заменяющие
существующий Docker Runner, project runner №5 и service `xarionix-runtime-runner.service`.
Регистрация locked к `xarionix-core`, tag только `runtime-rootless`, untagged jobs отключены,
concurrent/limit/request_concurrency = 1. Версия отдельного бинарного Runner — 19.5.0;
официальный binary сверялся с `release.sha256`. Authentication token вводился скрыто,
хранится только в приватном runner config 0600, не в репозитории/argv/CI variables/artifacts.
Не копируйте этот config в issue или отчёты.

Системная учётная запись `xarionix-runtime-ci` (UID 1001) имеет locked password, приватный
home 0700, не входит в sudo/docker и не имеет доступа к rootful socket. Два user-services:

| Назначение | Service | Socket |
|---|---|---|
| Только модули E2E | `docker.service` | `/run/user/1001/docker.sock` |
| Disposable Core/PG/Keycloak test stack | `docker-ci-stack.service` | `/run/user/1001/docker-ci-stack.sock` |

Их Engine IDs различаются; проверены rootless/seccomp/cgroup v2 и CPU/RAM/swap/PID flags.
User linger включён явно. `DOCKER_HOST`, `XARIONIX_RUNTIME_ENGINE_SOCKET`, `XDG_RUNTIME_DIR`
и private `TMPDIR` заданы в новой регистрации/service, не как общие project variables.
Runner service запускается без root, с NoNewPrivileges, RestrictSUIDSGID, PrivateTmp,
ProtectSystem/ProtectHome и записью только в собственный home. Существующий rootful Docker,
старые Runner registrations/config и чужие контейнеры/volumes не менялись.

Для своего второго rootless daemon нужны полный PATH с `/usr/sbin` (иначе не находится
`sysctl`) и `NotifyAccess=all` при `Type=notify`. Это настройки нового user-service,
не глобальные ослабления systemd или Docker. При регистрации через `sudo -u` сначала
переходите в home новой учётной записи: Runner 19.5 может завершиться на чтении недоступного
cwd до обработки аргументов. CLI token environment — `CI_SERVER_TOKEN`; boolean CLI flags
передаются как `--clean-git-config=true`, не двумя аргументами.

Администрирование: `systemctl status|restart xarionix-runtime-runner.service`;
user Docker services проверяются от **этой** учётной записи с соответствующими XDG/DBus.
Не перезапускайте старый Runner для изменения нового. Shell executor запускает доверенный
код checkout с правами своего пользователя, включая доступ к его runner config: это не
граница против злонамеренного maintainer/MR. Не включайте для fork/untrusted проектов,
не добавляйте production secrets и не увеличивайте concurrency без повторного аудита.
VM всё ещё общая со старым Runner: kernel/resource exhaustion остаются общим риском.
`integration:runtime-e2e` имеет same-stage needs на `integration:managed-stack`, без загрузки
его artifacts: два полных стека не запускаются одновременно на этой небольшой VM. Старый
Runner/service не перенастраивается; последующие security/build gates остаются обязательными.
Практический ориентир для dedicated CI host — 8 GiB RAM и 40+ GiB disk; имеющаяся тестовая
VM меньше. Рост build cache требует scoped обслуживания только этих test engines;
global prune и удаление рабочих volumes не допускаются.

Регистрация online не означает, что pipeline нового checkout прошёл. Изменения 4D остаются
незакоммиченными: после отдельного разрешения на commit/push потребуется реальный pipeline
нового SHA, а не Retry старого job.

### Job 208: native runner падает до checkout

В job №208 на Sprint 4D shell executor выполнил prepare script, но завершил
`prepare environment` с exit 1 ещё до получения исходников. Причина подтверждена на VM:
`.bash_logout` нового `xarionix-runtime-ci` побайтно совпадал с Debian `/etc/skel` и при
`SHLVL=1` вызывал `/usr/bin/clear_console -q`. У неинтерактивного login-shell нет console;
с `set -e` ошибка logout перекрывала успешное выполнение prepare. Сам GitLab описывает
этот случай в [shell profile loading](https://docs.gitlab.com/runner/shells/#shell-profile-loading).

Воспроизведение: `/bin/bash --login` от UID 1001, stdin/stdout/stderr без TTY,
`SHLVL=1`, `set -eo pipefail`, marker prepare и `exit 0` давали **exit 1**.
Условие только этого logout-блока дополнено `[ -t 0 ] && [ -t 1 ]`;
interactive console clearing сохранён. После применения тот же prepare даёт **exit 0**,
а намеренный `exit 42` по-прежнему **42**. Ошибки jobs не подавляются.

Идемпотентный stdlib operator tool, check-only по умолчанию:

```bash
sudo python3 scripts/configure_runtime_shell.py --home /home/xarionix-runtime-ci
sudo python3 scripts/configure_runtime_shell.py --home /home/xarionix-runtime-ci --apply
```

При изменении сохраняется private backup 0600 с прежним владельцем; обновление атомарно,
права/владелец исходного файла и остальной текст сохраняются. Symlinks, hardlinks,
неизвестный/неоднозначный блок и concurrent edit приводят к отказу, не перезаписи.
Runner token/config, system-wide `/etc/profile`, старый Docker Runner, systemd hardening,
контейнеры и volumes не затрагиваются. Перезапуск сервиса не нужен: следующий login-shell
читает исправленный профиль. Это **host-only fix**: Retry job текущего SHA может проверить
его без commit/push локального helper/documentation. Предыдущая положительная native E2E
репетиция проверяла runtime/isolation, но не Runner-generated login-shell/logout — поэтому
не выявила этот отдельный дефект bootstrap.

### Job 214: prepare исправлен, bootstrap PostgreSQL недоступен

Retry №214 того же `b0d171bd` уже прошёл prepare/checkout и собрал тесты. Он выявил
следующий дефект: native Runner намеренно имеет `UMask=0077`, а Git checkout сохранил
`deploy/postgres/10-app-user.sh` как **0700**. Его read-only bind принадлежит namespace root,
не PostgreSQL UID 70. Отдельный реальный container probe подтвердил отсутствие чтения
для UID 70; Core source/alembic.ini при UID 10001 читались нормально. `pg_isready` проверяет
доступность сервера, не успешность создания application role после init/restart, поэтому
ошибка проявилась при первой миграции. Удаление существующей DB или ослабление FK не нужны.

Исправление сохраняет строгий umask и секреты:

- Disposable fixture копирует **только публичный** init script в своё staging directory
  с явным 0755 и монтирует его read-only в обе PostgreSQL. Checkout script и dotenv не chmod'ятся.
- Hello Dockerfile явно задаёт owner/mode 0644 для `hello.py`: иначе такой же закрытый
  checkout создаёт образ с root-owned 0600 скриптом, недоступным runtime UID 10001.
- Base runtime нормализует права **только app/scripts/migrations/alembic.ini** для двух
  непривилегированных UID Core/Agent. CAS, agent state, секреты и host paths не затронуты.
- Native job сохраняет также allowlisted `integration-diagnostics.json`, на который
  ссылается ошибка fixture; raw stderr/credentials по-прежнему не публикуются.

Эти исправления уже находятся в исходниках, поэтому для GitLab нужен **новый commit SHA**.
Retry старого job №214 повторяет старую fixture/Dockerfile, даже при исправленном профиле.
Commit/push выполняет пользователь отдельно. Сквозная host-проверка специально использует
checkout с directories 0700/files 0600, executable bootstrap 0700 и исходным UMask=0077,
а не нормализованный Docker-wrapper tar. Нет fallback на root/privileged или отключение
read-only/seccomp/resource enforcement.

Проверка исправлений 04.11.2026 (новый GitLab SHA ещё не отправлялся):

| Проверка | Фактический результат |
|---|---|
| `make check` | 699 unit/API tests; coverage 72.37%, прежний gate 70%; Ruff/format/MyPy/shell/Bandit/оба pip-audit/Compose passed |
| Managed-stack regression на настоящих PostgreSQL/Keycloak | 17 passed, 98.34 s |
| Native rootless E2E с login-shell, CI identifiers, UMask 0077 и закрытым checkout | 1 passed, 367.60 s; JUnit/benchmark скопированы в локальные `reports/job-208-*` |
| Agent/Hello smoke из закрытого checkout на native host | passed, отдельный вызов `check(scan=False)` |
| Production Core build/read-only/non-root smoke и Trivy | passed на локальном Docker Desktop |
| Agent/Hello build/smoke и оба Trivy HIGH/CRITICAL gates | passed на локальном Docker Desktop |
| Gitleaks history/worktree и `git diff --check` | passed |

Не путайте native E2E с GitLab job: повтор №214 подтвердил исправленный prepare, но ещё
использовал старый bootstrap. Host rehearsal выше использовал новые локальные исходники.
Commit/push оставлены пользователю. В commit нужны также новые
`scripts/configure_runtime_shell.py` и `tests/test_runtime_runner_shell.py`.

Дополнительное ограничение, **не причина отказа native E2E job**: прямой запуск
`scripts.runtime_images` с Trivy на этом native rootless daemon не прошёл доступ к private
bind-mounted scan/report paths. Scanner запрашивает host UID 1001, тогда как `uid_map`
этого daemon отображает container UID 0 в host UID 1001. Реальный read-only probe при
container UID 1001 не смог прочитать report directory 0700. Это не успешный security scan
и не результат анализа уязвимостей. Отдельный smoke без scanner проверен явно; полные
security scans выше действительно выполнены в локальном Docker Desktop. Native E2E CI
job scanner не вызывает; `security:runtime-images` по-прежнему использует отдельный
Docker-controller wrapper, без `allow_failure`/понижения severity. Универсальный native
scanner UID mapping не менялся в этом точечном исправлении; private directories не
делались world-writable и security checks не пропускались в pipeline.

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

Используется существующий **Linux Docker executor**, как у ERP/Web, с реально зарегистрированным tag `debian`. Раньше Core требовал отсутствующие `xarionix-docker` / `xarionix-release`: job не назначался Runner, поэтому не имел trace. Ручная загрузка репозитория на VM не нужна. Если у другой установки иной tag, согласованно измените `tags` в `.docker` и регистрацию Runner.

Каждый Docker job получает собственный `docker:29.9.2-dind-rootless`, закреплённый по digest в `.gitlab-ci.yml`. CLI также закреплён. Соединение job → service использует **проверяемый TLS на 2376**, клиентские сертификаты в `/certs/client` и отдельную job network (`FF_NETWORK_PER_BUILD=1`). Plaintext 2375 и физический Docker socket VM не используются. Preflight проверяет TLS-файлы, Compose и `name=rootless` в SecurityOptions daemon. Отсутствие сервисного daemon завершает job ошибкой с объяснением, а не skip.

В соответствующем `[runners.docker]` необходимы:

```toml
privileged = false
services_privileged = true
allowed_privileged_services = [
  "docker:29.9.2-dind-rootless@sha256:ae083cc7de51e7a8e5a597f8fb774ca7914c408a95fc0f1477826a913479518a",
  "docker.io/library/docker:29.9.2-dind-rootless@sha256:ae083cc7de51e7a8e5a597f8fb774ca7914c408a95fc0f1477826a913479518a",
]
volumes = ["/cache", "/certs/client"]
```

Не добавляйте wildcard в allowlist, `privileged=true`, `seccomp=unconfined` или `/var/run/docker.sock` в job volumes. Сам существующий Runner container может использовать socket VM для управления executor: это **не** разрешение передать его job. Обычные Python/ERP/Web jobs не становятся privileged. Риск выхода privileged service на хост полностью не исчезает даже при rootless: Runner не должен находиться на production-сервере или содержать production secrets. Политика соответствует [restricted rootless DinD GitLab Runner](https://docs.gitlab.com/runner/executors/docker/#use-rootless-docker-in-docker-with-restricted-privileged-mode).

Для проверяемого применения есть standalone-скрипт, не выводящий token/config:

```bash
sudo python3 scripts/configure_docker_runner.py --path /srv/gitlab-runner/config/config.toml
# По умолчанию только проверка. Применение — отдельное явное действие:
sudo python3 scripts/configure_docker_runner.py --path /srv/gitlab-runner/config/config.toml --apply
```

Путь зависит от установки Runner. При нескольких регистрациях передайте `--runner-name`. Скрипт отказывается менять небезопасный/неоднозначный config, сохраняет остальные поля, создаёт private backup и атомарно записывает файл 0600. Повторный запуск идемпотентен. GitLab Runner перечитывает config без перезапуска. Не прикладывайте config или backup к issue/artifacts: там authentication token. При откате восстановите только проверенную private копию конкретного config; volumes/DB не удаляются.

### Workspace, права и сеть внутри rootless service

Обычный Compose bind mount смотрит на filesystem **daemon**, не job. Поэтому просто добавить DinD недостаточно: файлы realm/TLS и `localhost` интеграционных тестов оказались бы в другом контейнере. `scripts/docker_job.py` решает это без доступа к VM:

1. Собирает закреплённый toolbox (`deploy/ci/Dockerfile`) с CLI/Compose, Python и locked test tools. Это не публикуемый production image.
2. Передаёт tracked и неигнорируемые исходники в одноразовый named volume rootless daemon. Приватные `.env`, ключи, venv, artifacts и clone credentials исключены; Git history передаётся без `.git/config`/reflogs. Symlinks и выход за checkout запрещены.
3. Запускает непривилегированный controller внутри этого daemon; volume смонтирован по его daemon-side absolute path. Поэтому последующие bind mounts видят те же файлы и UID, включая read-only TLS key 0600 и Nginx UID. Pytest temporary files также находятся внутри volume (`--basetemp=.ci-tmp/pytest`), не в чужом `/tmp`.
4. Controller использует socket **только rootless service** `/run/user/1000/docker.sock` и `--network host` **только внутри DinD namespace**. Это не socket и не host network физической VM; `localhost` остаётся внутри данного job. Внешнее соединение по TCP остаётся с TLS.
5. Возвращает только allowlisted regular artifacts (`reports`/`dist`), запрещает links/path traversal и удаляет собственный controller/volume. Job teardown уничтожает отдельный DinD service. Нет global prune.

### Job 189: тесты прошли, но обёртка вернула failure

В сохранённом trace job №189 на commit `346e55c` все **106 integration tests прошли**
за 852.30 секунды. Затем появилась строка `integration failed in the rootless job
container (exit 0)`. Это не падение тестов, миграций или Keycloak: старая обёртка
объединяла через `or` код процесса `docker start --attach` и `.State.ExitCode` контейнера,
но в сообщении показывала только второй. Из лога следует ненулевой exit Docker CLI
при нулевом exit контейнера; точный код и низкоуровневая причина attach-сбоя в нём
не сохранены. Называть его OOM или сетевым timeout по этому trace нельзя.

Запуск теперь отделён от чтения вывода: проверяемый `docker start`, затем
`docker logs --follow`, затем [`docker wait`](https://docs.docker.com/reference/cli/docker/container/wait/)
и повторный `inspect`. CLI attach может вернуть ошибку потока отдельно от результата
контейнера — это видно в [исходниках закреплённого Docker CLI](https://github.com/docker/cli/blob/v29.9.2/cli/command/container/start.go).
Успех разрешён только при совпадающем нулевом exit из wait/inspect, `Status=exited`,
`Running=false`, `Dead=false`, `OOMKilled=false` и пустом `State.Error`.
Сбой log transport отдельно сообщается в trace, не подменяя подтверждённый результат
контейнера. Работающий/не запущенный контейнер, ненулевой exit, OOM, некорректный ответ,
сбой wait/inspect и timeout по-прежнему блокируют job. Для logs+wait общий deadline;
retry тестов или `allow_failure` не добавлены. Отчёты копируются и при ошибке ожидания.
Raw State.Error, credentials и Docker config в диагностику не выводятся.

`reports/integration-diagnostics.json` создаётся при ошибке самого тестового стека.
В job №189 такой ошибки не было, поэтому warning об отсутствии этого дополнительного
файла не является причиной failure; JUnit был сформирован и загружен успешно.

Regression-тесты проверяют сбой log transport при успешном/неуспешном контейнере,
расхождения wait/inspect, незавершённое состояние, OOM, безопасные сообщения,
сохранение JUnit и cleanup. Дополнительно четыре opt-in Docker tests запускают
настоящие короткоживущие non-root/read-only контейнеры с exit 0/23, в том числе
с искусственным обрывом только log stream; wait/inspect остаются настоящими.
Они включены в обычный integration job без отдельного сервиса и без доступа к dev DB.

Для применения нужен pipeline **нового commit SHA** после отправки изменений;
Retry старого job №189 использует прежнюю обёртку. Настройки Runner, базы и volumes
менять не требуется. Новый GitLab pipeline этим локальным исправлением не запускался.

Локальная проверка 03.11.2026: `make check` прошёл — **554 unit/API tests**,
coverage **73.64%**, Ruff/format/MyPy/shell, Bandit, оба pip-audit и все три
Compose-конфигурации. `XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/python -m pytest
tests/integration/test_docker_controller.py -vv` — **4 passed** на Docker Desktop
29.9.2/Linux arm64, с реальными start/wait/inspect и изолированными контейнерами.
Полные PostgreSQL/Keycloak integration tests повторно в этом исправлении не запускались;
их результат **106 passed** выше относится к предоставленному GitLab trace job №189,
а не к новому прогону. Commit/push и изменения серверного Runner не выполнялись.

Перед сбором integration-тестов controller устанавливает **текущий переданный checkout**:
`python -m pip install --no-deps --editable .`. Toolbox содержит только locked dependencies,
а не метаданные самого `xarionix-core`; без этого `app.version` не может получить версию
через `importlib.metadata` и pytest завершается с `PackageNotFoundError` до запуска стека
(job 153). Runtime-зависимости не обновляются; build backend закреплён в `pyproject.toml`.
Ошибка установки блокирует тесты и сохраняет штатный cleanup. Версия не подменяется
fallback-значением. Локальный `make install-dev` и `.python` jobs уже выполняют такую установку.
После отправки исправления нужен pipeline нового commit SHA: retry job старого commit
продолжит выполнять старый CI-код. Настройки Runner и существующие volumes менять не нужно.

Проверка исправления job 153 (02.11.2026): 448 unit/API tests прошли как на локальном
Python 3.12, так и в чистом Linux arm64 toolbox с Python 3.13.18; локальный coverage — 75.09%.
В toolbox без установленного проекта отдельно воспроизведён `PackageNotFoundError`, затем
тот же `inner("integration")` с новым install-шагом успешно собрал все 87 integration-тестов
(`--collect-only`, без Docker socket). Полный `make integration-test` отдельно прошёл на
Docker Desktop: **87 passed**, 367.04s, настоящие PostgreSQL/Keycloak/CAS и изолированные volumes.
Ruff/format/MyPy/shell, repository validation, Bandit и `git diff --check` также прошли.
Новый pipeline на Linux amd64 GitLab Runner после исправления пока не запускался.

Нужны Linux user namespaces, совместимый Docker executor, BuildKit/Compose, доступ к OS/PyPI/image registries и Trivy DB. Ориентир для полного стека — 4 vCPU, 8 GB RAM, 20+ GB свободного диска. Текущий Runner меньше; при нехватке ресурсов расширяйте VM, а не пропускайте integration. Его `concurrent=1` также предотвращает конкуренцию за persistent client cert volume. Не увеличивайте concurrency без отдельной проверки изоляции certificates/cache между jobs. Rootless DinD может не иметь cgroup delegation: лимиты всего service задаются на executor, на внутренние per-container limits полагаться нельзя.

Release также получает **новый изолированный DinD daemon**, а не общий persistent build daemon. Это не отдельная release VM и не полная граница против выхода на Runner-хост. Для недоверенных fork MR предпочтительны отдельные ephemeral VM и отдельный protected release runner; production credentials не передаются. Не предоставляйте protected variables/runners недоверенному MR.

### GitLab settings

1. Включить Container Registry и проверить, что стандартные `CI_REGISTRY_*` доступны publish job.
2. Включить существующий group Docker runner для Core; разрешить обычные untagged Python jobs и tag `debian` для Docker jobs, применить restricted rootless service config выше. Не регистрировать фиктивные Shell tags.
3. Защитить default branch и release Git tags; право создавать version tags — только ответственным за release.
4. Настроить server-side protection/immutability для release container tags. Одного условия в YAML недостаточно против MR, меняющего собственный pipeline: job token может иметь registry scope текущего проекта.
5. Не создавать production secrets в обычных CI variables. Публикация использует временные стандартные job credentials, не PAT. Если добавляются секреты позже — только protected/masked/file variables с минимальным scope.
6. Разрешить достаточно большие job artifacts: image tar может превышать стандартный лимит 100 MB; практический лимит 1 GiB. Build artifacts ограничены developer access и удаляются через день.
7. Включить требование успешного pipeline для merge. Не трактовать pending integration как успешный gate.

Текущий GitLab доступен по внутреннему NetBird hostname; публичный badge не добавляется. Pipeline использует стандартный `CI_PROJECT_URL`, без хардкодного внутреннего URL в OCI metadata.

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
| `DOCKER_HOST` / `DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH` | Закреплённый TLS endpoint rootless DinD; не переопределять на VM socket или plaintext |
| `FF_NETWORK_PER_BUILD=1` | Отдельная executor network для каждого Docker job |

Registry password не передаётся аргументом команды и не печатается. Docker auth config создаётся в private temporary directory, удаляется после publish и не попадает в artifacts/cache. Не включайте shell tracing, `CI_DEBUG_TRACE`, вывод `env`, `docker inspect` целиком или production `docker compose config` в логи.

## Integration tests

Sprint 3 сохраняет `.gitlab-ci.yml`, семь stages, rootless DinD/TLS и Runner allowlist без изменений. Новые `test_assurance.py`, `test_rbac.py`, `integration/test_sprint3.py` автоматически попадают в прежние jobs. Coverage threshold остаётся 70%; security gates не ослаблены. Результаты локальных проверок и ограничения — [sprint-3-validation.md](sprint-3-validation.md).

```bash
make integration-test
```

Либо `XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest -vv -m integration`. Требуется рабочий Docker; это не mock-тест. Полный запуск ждёт readiness/health с timeout (до 420 секунд для первого старта Keycloak), а не произвольный фиксированный sleep. Polling после restart использует deadline.

Compose project `xarionix-test-<pipeline>-<job>-<random>` имеет собственные volumes, networks, loopback ports, случайные credentials и отдельный test-only service-account client. Production realm templates не включают этот client/grant. В ответах pytest credentials fixture скрыты.

Fixture cleanup удаляет **только свой случайный project** и образ `xarionix-core-test` с тегом этого project. Образ собирается один раз, затем Compose запускает его с `--no-build`. В `finally` controller дополнительно проверяет job label и prefix test project перед удалением оставшихся test containers/networks/volumes; без числового `CI_JOB_ID` этот cleanup отказывается работать. При жёстком прерывании Runner удаляет одноразовый DinD service целиком. Native jobs хранят временные файлы pytest в отдельном каталоге `.ci-tmp/native-<CI_JOB_ID>` и удаляют его в `after_script`.

`reports/integration-diagnostics.json` содержит до 20 записей об ошибках: случайный test project,
фазу команды, статическую категорию, exit code, номер попытки/решение о retry и
Service/State/Health/ExitCode контейнеров. При сбое Keycloak в поле `keycloak_error_kind`
сохраняется только фиксированная категория из его журнала. Даже если build упал до их создания, фаза и причина
не теряются в пустом `[]`. Не публикуются raw stdout/stderr, argv, `.env`, JWT, passwords,
Docker Env и realm secrets. Категория `unclassified` означает, что точную причину необходимо
воспроизвести в собственной изолированной среде; это не доказательство сетевого сбоя.

### Нехватка места у PostgreSQL Keycloak

Если Keycloak завершается с кодом 1 после успешных миграций Core и диагностика показывает
`disk_full`, проверьте свободное место на VM через `df -h` для Docker data root,
containerd и домашнего каталога native runner. В pipeline №67 PostgreSQL Keycloak вернул
`No space left on device`, хотя его healthcheck ещё показывал готовность. Оба тестовых
Docker-движка делили системный раздел VM. После завершения заданий удаляйте только
идентифицированные временные каталоги и образы соответствующих тестов. Для стабильных
запусков учитывайте место для одновременного хранения образов, build cache и БД.

### Ошибка сборки до запуска стека (job 171)

JUnit pipeline показал **70 passed / 17 setup errors**: один `docker compose build core`
завершился с ненулевым exit code, поэтому все 17 тестов, использующих эту module fixture,
получили одну и ту же ошибку. Следующие четыре disposable stacks, включая package registry,
успешно отработали. Ошибки установки project metadata и запуска Keycloak здесь не подтверждаются.
Старый код полностью отбрасывал output build, поэтому низкоуровневая причина этого конкретного
падения не восстановима из сохранённого JUnit/trace. Нельзя объявлять её ни PyPI timeout,
ни OOM без новых данных.

Теперь зафиксированные сообщения о network timeout, временном DNS/reset или HTTP 429/502/503
дают **ровно один повтор только `build core`**, с двухсекундной паузой и сохранённой записью
о первой попытке. Миграции, команды API/БД, `up`, тесты и ошибки TLS/зависимостей/диска/памяти
не получают такого retry. Повторная или неклассифицированная ошибка остаётся hard failure;
общего GitLab retry `script_failure` нет. `ps` для диагностики ограничен 20 секундами, его
недоступность не заменяет исходную ошибку. В builders/toolbox и Python CI jobs у pip явно
установлен socket timeout 60 секунд, включая build backend; runtime container не получает
новых pip-настроек и по-прежнему не содержит pip. TLS и security gates сохранены.

После отправки изменений нужен pipeline нового commit SHA. Runner permissions, volume reset
и production deployment для этих изменений не требуются. Успех нового GitLab pipeline
можно подтвердить только его реальным запуском, не локальной проверкой.

Локальная проверка 03.11.2026: `make validate lint typecheck test` — **474 passed**,
coverage **75.12%**; `make integration-test` — **87 passed**, 391.60s на настоящих
PostgreSQL/Keycloak/CAS. Production build + non-root/read-only/live/401 smoke, Bandit,
оба pip-audit, Gitleaks history/worktree и все три Compose configuration checks прошли.
Fault injection regression отдельно проверяет предел повторов, отказ для постоянных ошибок,
сохранение диагностики при пустом списке контейнеров и отсутствие секретов в выводе.
Rootless Linux amd64 GitLab job с этими изменениями ещё не запускался.

### Нестабильный MFA-контекст тестового realm (Sprint 2)

В job №117 на `1364d43` rootless DinD и Compose успешно запустились, но тест параллельного снятия Platform Admin получил `[200, 403]` вместо `[200, 409]`. Это не ошибка Runner или PostgreSQL locking. Тестовые clients не задавали `defaultClientScopes`, поэтому наследовали realm scope `acr`: его встроенный mapper и тестовый `test-acr` записывали один claim с одинаковым приоритетом. На новых стендах воспроизведён подписанный токен с `acr=1` вместо `test-step-up`; Core корректно отказывал в административном доступе. Порядок обработки mapper'ов не был надёжным контрактом. См. исходники закреплённой версии Keycloak: [создание default scopes](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java) и [сортировка mapper'ов](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/ProtocolMapperUtils.java).

Теперь только disposable integration clients имеют явные пустые default/optional scopes и собственный `oidc-sub-mapper`: обязательный `sub` сохраняется без наследования конкурирующих ACR/auth_time mapper'ов. Production realm, MFA allowlist и серверные проверки не изменены. Новый regression проверяет подпись, issuer, audience, expiry, уникальность subject и тестовый authentication context всех шести участников; unit-тест отдельно сохраняет отказ для обычного `acr=1` со свежим `auth_time`.

Перед гонкой оба администратора должны успешно пройти защищённый API. После неё проверяются ровно `409 last_platform_admin` и один оставшийся active admin. Error diagnostics выводят только label/status/domain code, не JWT. Тестовая fixture восстанавливает исходные admin flags под DB lock даже при assertion failure: раньше сбой до восстановления bootstrap admin вызывал вторичный `403` в следующем, не связанном с MFA тесте rollback. Это cleanup только собственной одноразовой БД; он выполняется после проверок и не превращает ошибку теста в успех.

После отправки исправления нужен pipeline **нового commit SHA**. Retry старого job снова использует старый код; удаление dev/production volumes или изменение Runner для этого исправления не требуется.

Локальная проверка исправления 02.11.2026: `make check` — успешно, **230 unit/API tests**, coverage **82.39%**, Ruff/format/MyPy/shell/Bandit/оба pip-audit и три Compose-конфигурации без ошибок; `make integration-test` — **17 passed** на реальных PostgreSQL/Keycloak. Проверки authentication context, admin race и deferred rollback дополнительно прошли **два отдельных запуска по 3 теста** с новыми realm/volumes. Gitleaks Git history/working tree и `git diff --check` — без замечаний. Host: macOS/Python 3.12.14, сервисы — Docker Desktop/Linux arm64. Новый GitLab pipeline с исправлением пока не запускался; результат Linux amd64 Runner не заявляется.

## Coverage и отчёты

Unit и integration запускаются отдельно. Unit job сохраняет `reports/unit.xml` и `reports/coverage.xml`; integration — отдельный JUnit. `coverage` regexp и Cobertura report формируются из одного прогона. Это обеспечивает процент в MR widget и построчные annotations при поддерживаемой версии GitLab; [эти механизмы конфигурируются отдельно](https://docs.gitlab.com/ci/testing/code_coverage/).

Coverage измеряется по `app` и `scripts`, включая installer/CI helpers, без искусственного исключения сложных участков. В Makefile и GitLab установлен минимальный порог 70%. Исходный baseline — в [отчёте Sprint 1.1](sprint-1.1-validation.md), дополнительные Docker-executor результаты — в [docker-executor.md](docker-executor.md). Следующий шаг — расширять покрытие CLI orchestration и постепенно повышать порог, не исключать эти файлы из расчёта.

## Security checks

`Bandit` и `pip-audit --strict` проверяют Python; аудитируются оба lock-файла, runtime и dev. Pinned Trivy 0.76.1 проверяет HIGH/CRITICAL уязвимости Core Docker image (включая unfixed, без broad ignore). Ошибка загрузки DB/запуска scanner тоже блокирует job. Scanner читает image archive, а не Docker socket или production `.env`. Данные проекта не отправляются в облачный анализатор: скачивается публичная vulnerability DB, анализ локален. Эта проверка не означает, что отдельно просканированы все инфраструктурные и CI images.

Для обоих `pip-audit` в GitLab и `make security` явно задан `--timeout 60`
(socket timeout вместо стандартных 15 секунд) и выключен progress spinner.
Job 163 остановился на `requests.exceptions.ConnectionError: ... pypi.org ... Read timed out`
во время dev audit: Bandit и runtime audit уже прошли, но dev audit не был завершён.
Это ошибка получения данных, а не отчёт об обнаруженной уязвимости. Увеличенный timeout
не отключает TLS/`--strict`, не исключает зависимости и не превращает сетевую ошибку в success.
Нет blanket retry для `script_failure`, `allow_failure` или `--ignore-vuln`.
При повторном timeout проверьте доступ Runner к `pypi.org` и `files.pythonhosted.org` через HTTPS,
DNS/прокси/исходящий firewall; не отключайте проверку сертификатов.
Для временного сетевого сбоя допустим Retry того же job. Для применения новых аргументов
CI нужен pipeline нового commit SHA. Остальные проверки не требуется переписывать.

Локально 03.11.2026 выполнены `make security` (Bandit и оба audit прошли,
`No known vulnerabilities found`) и `make validate lint typecheck test`
(450 unit/API tests, coverage 75.09%, без ошибок lint/typecheck/validation).
Это не результат повторного запуска job на GitLab Runner; удалённый pipeline не запускался.

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

## Sprint 6B: SDK и persistent runtime

`test:sdk-wheel` собирает отдельный first-party wheel и импортирует его с Python
`-I`, исключая подмену editable Core путями. Unit coverage включает SDK и сохраняет
70% gate. Ruff/MyPy/Bandit проверяют `sdk/python/src`; security image job дополнен
stateful Hello и отдельным Trivy report. Прежние jobs и проверки не удалены.

Обязательный `module-storage:runtime-e2e` выполняется после существующих native
runtime/Gateway jobs на **том же** теге `runtime-rootless`. Runner registrations
и host configuration не меняются. Нужны два разных native rootless engine,
пустой выделенный runtime engine, cgroup v2 delegation и установленный
`XARIONIX_RUNTIME_ENGINE_SOCKET`. Docker Desktop/DinD не подменяют этот gate.
При отсутствии runner job остаётся pending, при неправильных limits/socket — failed.

```bash
make sdk-test
XARIONIX_RUNTIME_ENGINE_SOCKET=/absolute/private/runtime.sock make stateful-integration-test
```

E2E создаёт disposable Core/PostgreSQL/Keycloak stack, подписывает реальные OCI
версии SDK-модуля, работает через Gateway от пользователей двух компаний,
проверяет restart/update/migration/backup/restore и retained uninstall. Уборка
ограничена UUID/labels данного запуска; global prune и dev volumes не используются.
Содержимое бизнес-баз и приватные ключи не публикуются как artifacts.

Web CI отдельно требует `CONSOLE_CORE_REF` с проверенным полным SHA Core 6B после
ручного commit/push. Это не новый credential. Старый 6A baseline не содержит
новых storage API. GitLab pipeline этих незакоммиченных изменений не запускался.
