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

Fixture cleanup удаляет **только свой случайный project**. В `finally` controller дополнительно проверяет job label и prefix test project перед удалением оставшихся test containers/networks/volumes; без числового `CI_JOB_ID` этот cleanup отказывается работать. При жёстком прерывании Runner удаляет одноразовый DinD service целиком. Cleanup не обращается к `xarionix-core`/`xarionix-core-dev` и не выполняет глобальные prune.

`reports/integration-diagnostics.json` содержит до 20 записей об ошибках: случайный test project,
фазу команды, статическую категорию, exit code, номер попытки/решение о retry и
Service/State/Health/ExitCode контейнеров. Даже если build упал до их создания, фаза и причина
не теряются в пустом `[]`. Не публикуются raw stdout/stderr, argv, `.env`, JWT, passwords,
Docker Env и realm secrets. Категория `unclassified` означает, что точную причину необходимо
воспроизвести в собственной изолированной среде; это не доказательство сетевого сбоя.

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
