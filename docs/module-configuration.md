# Конфигурация модуля V1

`xarionix_sdk.configuration.Configuration` принимает закрытый non-secret document
через `XARIONIX_MODULE_CONFIGURATION`. Identity — installation UUID, installation
generation, module ID и package version. Неизвестные поля запрещены.

| Категория | Минимальные поля Hello Business |
| --- | --- |
| Public | `title` — bounded отображаемое название |
| Administrator-approved | `max_items_per_company` — лимит примера |
| Runtime-only | `storage_max_bytes`, `expected_schema_version`, `target_schema_version`, `allow_migration` — только из проверенного deployment plan |
| Secrets | Не поддерживаются этим контрактом |

Нет универсального словаря environment, arbitrary paths, URL, credentials,
permissions, Docker limits или network flags. Модуль не выбирает volume name.
Документ должен формироваться доверенной deployment boundary из проверенного
плана; его содержание не является самостоятельным доказательством авторизации.
Core и Agent остаются authoritative, SDK не может выдать себе привилегии.

В V1 title и лимит 100 записей задаёт серверная политика примера. Schema 0
обозначает первичную инициализацию. `allow_migration` не является переключателем
самого модуля: для существующей БД он требует approved plan и свежего backup.

Core SQL credentials, Keycloak bootstrap/admin secrets, publisher private keys и
human access/refresh tokens не входят в конфигурацию. Полноценный Secret Manager
отложен; sensitive settings не маскируются полем public configuration.
