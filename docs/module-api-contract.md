# Подписанный API contract V1

XPKG остаётся V1. `manifest.json`, canonical signature domain и исторические
Ed25519 test vectors не меняются. Новый файл `payload/resources/module-api-v1.json`
включается в обычный signed artifact inventory (точный SHA256 и размер), а все OCI
blobs по-прежнему подписаны. Нет второго доверенного unsigned sidecar.

```json
{"schema_version":1,"operations":[{"id":"items-read","method":"POST","permission":"hello.items.read","request":{"kind":"json","max_bytes":65536},"response":{"kind":"json","max_bytes":65536}}]}
```

Схема закрыта: неизвестные поля, Boolean version, URL, shell, runtime flags,
wildcards, дубликаты, чужие/core permissions запрещены. Разрешены 1–64 операции;
каждый permission должен быть объявлен в собственном manifest namespace со scope
company. Только JSON object request/response и POST в V1. Максимум contract=64 KiB.

Verifier проверяет resource после подписи и всей inventory, повторно сверяет его
байты с artifact digest. Registry сохраняет immutable canonical semantic contract
и его SHA256 **на package UUID**. Whitespace ресурса допустим: raw bytes всё равно
подписаны inventory; semantic digest считается по canonical модели. Старые пакеты
без ресурса не получают API автоматически и остаются offline.

Установка и deployment approval показывают API contract/digest. Private deployment
delivery содержит его же модель; Agent независимо извлекает и сравнивает подписанный
resource перед OCI import. Claim/result привязаны к package SHA, contract SHA,
image digest, installation и deployment generations. Upgrade/rollback выбирает
контракт exact текущего package, без кеша старых операций и без автоматических grants.

Миграция `0012_module_gateway` добавляет две таблицы: `module_api_contracts`
(package FK, digest, document, immutable UPDATE/DELETE/TRUNCATE guard) и
`module_gateway_identities` (отдельная identity назначенного host, immutable binding,
status/revision, terminal revoke). Bodies/tokens/ответы не сохраняются.
Installation executor получает только SELECT новых таблиц; `core_catalog_guard`
и его fixed SQL capability не изменены. Existing data/backfill не переписываются.
