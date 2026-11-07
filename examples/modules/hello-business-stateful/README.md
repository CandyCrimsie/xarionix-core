# Stateful Hello Business

Рабочий SDK-модуль `hello-business` 1.1.0: записи компаний в SQLite, health/version,
транзакции, schema migrations и graceful shutdown. Данные находятся в owned
`/data/storage`, которое предоставляет Agent. Модуль не подключается к Core DB.

## Локальная сборка подписанного пакета

Команды выполняются из корня Core с установленным dev environment. Перед
загрузкой зарегистрируйте publisher, полученный public key и право на namespace
`hello` по обычной процедуре Core. `example-runtime` и ключ ниже подходят только отдельному dev-стенду.
Для production используйте собственную проверенную identity издателя и offline key.

```bash
umask 077
module_work=$(mktemp -d)
(
  cd examples/modules/hello-business-stateful
  ../../../.venv/bin/python -m xarionix_sdk check hello:module --manifest manifest.json
  ../../../.venv/bin/python -m xarionix_sdk metadata hello:module --manifest manifest.json --output .
)
docker build -f examples/modules/hello-business-stateful/Dockerfile -t xarionix-hello-business:1.1.0 .
docker save --output "$module_work/image.tar" xarionix-hello-business:1.1.0
.venv/bin/python -m scripts.runtime_artifact "$module_work/image.tar" "$module_work/distribution"
cp examples/modules/hello-business-stateful/module-api-v1.json "$module_work/distribution/payload/resources/"
cp examples/modules/hello-business-stateful/module-sdk-v1.json "$module_work/distribution/payload/resources/"
.venv/bin/python -m scripts.xpkg keygen --private-key "$module_work/dev.private" --public-key "$module_work/dev.public"
.venv/bin/python -m scripts.xpkg pack \
  --source "$module_work/distribution/payload" \
  --manifest examples/modules/hello-business-stateful/manifest.json \
  --signing-key "$module_work/dev.private" --publisher example-runtime --key-id dev-key \
  --output "$module_work/hello-business-1.1.0.xpkg"
```

Private signing key находится вне build context. Core не запускает этот CLI над
uploaded Python; он только проверяет signature, inventory и декларации. Для другой
версии согласованно обновите manifest, metadata и `HELLO_VERSION` build arg; для
новой схемы также `HELLO_DATA_SCHEMA` и migration declarations.

## Установка и использование

1. Загрузить `.xpkg` в общем Web: Администрирование → Каталог пакетов.
2. Создать Install Plan, проверить capabilities и подтвердить с MFA. Применение
   выполняет отдельный trusted executor существующего Module Manager.
3. Подготовить deployment `module-api-stateful-v1` на зарегистрированном rootless
   host, проверить storage/schema 0 и утвердить точный digest. Дождаться ready.
4. Включить модуль отдельным планом и подтвердить runtime для новой installation
   generation. Назначить company roles с `hello.items.read`, `hello.items.create`.
5. Выбрать компанию в Web → Модули → Деловые записи. Gateway сам создаёт company/
   actor context. Human JWT не передаётся модулю; `company_id` в payload запрещён.

API operations: `items-read`, `items-create` (`{"name":"A1"}`), `status-read`.
Одна установка обслуживает несколько компаний; SQL handlers всегда фильтруют по
`ctx.company_id`. Пример ограничен 100 записями на компанию. Не является Billing/HA DB.

Обновление схемы требует остановки, fresh backup и отдельного migration approval.
После смены пакета дождитесь ACK автоматической quarantine; backup должен отражать
текущую allocation revision. Restore создаёт новую epoch; image rollback без
совместимой схемы запрещён. См. [workflow](../../../docs/module-backup-restore.md).

## Полный реальный тест

```bash
XARIONIX_RUNTIME_ENGINE_SOCKET=/absolute/private/native.sock make stateful-integration-test
```

Нужны отдельные engine для Compose stack и native runtime. Тест проверяет A1/B1,
restart, update 1.1.1, migration 1.2.0/schema 2, backup/restore/schema compatibility,
quarantine и uninstall без удаления данных. Используются только disposable ресурсы.
Прямой `docker run` с произвольным host bind не является поддерживаемым provisioning.
