# Настоящий runtime-модуль: development workflow

Работайте только в disposable окружении. Не выполняйте DBA bootstrap на существующей
установке автоматически. Требуются отдельные Core/Keycloak stack и rootless runtime daemon;
Core, Agent и контейнер не разделяют секреты. Пример расположен в `examples/modules/hello-runtime`.

```sh
make install-dev
make runtime-example-build
docker image save --output /protected/work/hello.tar xarionix-hello:local
.venv/bin/python -m scripts.runtime_artifact /protected/work/hello.tar /protected/work/hello-dist
```

Посмотрите `python -m scripts.runtime_artifact --help` перед запуском: CLI принимает
Docker-save input и **новый** output directory, не перезаписывает существующий.
Конвертер нормализует raw и gzip Docker layers, не использует registry pull URL.
Проверьте platform под целевой host. Для другого architecture собирайте явно с `--platform`.

Подпись — существующий `scripts.xpkg`: `keygen`, затем `pack` с source
`/protected/work/hello-dist/payload` (не родительским каталогом), manifest из примера,
private key и publisher/key ID. Используйте `--help` для точных имен CLI options.
Не кладите private key, env или registry credentials внутрь payload. Fingerprint и public key
можно передать администратору; private key остаётся у издателя. `xpkg verify` проверяет V1,
а runtime validation дополнительно проверяет OCI.

Через существующий защищённый platform API зарегистрируйте publisher/key/namespace,
импортируйте package, создайте/подтвердите install plan и примените trusted executor.
Затем [зарегистрируйте host](deployment-agent.md), запустите отдельный агент и
[подтвердите deployment plan](module-runtime-lifecycle.md). Проверьте jobs и runtime state,
только после healthy выполняйте installation enable. Для версии 2 соберите новый image
с `--build-arg HELLO_VERSION=2.0.0`, подпишите новый version package тем же доверенным ключом.
Metadata update и runtime upgrade подтверждаются отдельно. Rollback так же явный.

## Проверки

```sh
make runtime-test
make runtime-images-check
# Native Linux, два РАЗНЫХ rootless daemon. Второй socket только для runtime:
XARIONIX_RUNTIME_ENGINE_SOCKET=/run/user/1000/docker-runtime.sock make runtime-integration-test
```

Обычный DOCKER_HOST/context используется для disposable PostgreSQL/Keycloak/Core и image build.
Runtime engine обязан иметь другой ID и быть пустым перед тестом. Тест создаёт собственные
publisher/key/agent identity, подписывает настоящий образ, запускает настоящий agent process,
проверяет namespace/readonly/cgroups/health, lifecycle, upgrade/rollback и restart recovery.
Cleanup затрагивает только ресурсы теста; нет global prune или удаления existing volumes.

Benchmark выполняется тем же E2E на фактическом host. Задержки локального стенда не SLA.
Общий integration в rootless DinD проверяет control protocol отдельно; он не подменяет
положительный native E2E тест.
