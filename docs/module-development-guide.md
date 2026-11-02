# Разработка `.xpkg`: полный offline → registry цикл

Все команды выполняются в `xarionix-core`. Нужен установленный virtualenv. Core/Keycloak не нужны
для keygen/pack/sign/verify/diff. Подготовленная дистрибуция — не исходный monorepo, не `.venv` и не Git clone.

## 1. Ключ вне репозитория и payload

```bash
mkdir -m 700 /secure/xarionix-signing
.venv/bin/python -m scripts.xpkg keygen \
  --private-key /secure/xarionix-signing/publisher.key \
  --public-key /secure/xarionix-signing/publisher-public.txt
```

Не помещайте private key в Core/CI/build context. `keygen` не перезаписывает существующий key pair;
stdout содержит только public key/fingerprint. Для реальной публикации создайте собственный ключ,
не используйте тестовый RFC vector. Перенесите копию только по утверждённой offline-процедуре backup.

## 2. Manifest и pack/sign

Пример `examples/xpkg/manifest.json` объявляет `example-publisher`, `example-module`, namespace `example`.
В шаблоне `artifacts=[]`: пакер сам создаёт inventory. Готовый пакет с пустым inventory verifier не принимает.

```bash
.venv/bin/python -m scripts.xpkg pack \
  --source examples/xpkg/distribution \
  --manifest examples/xpkg/manifest.json \
  --signing-key /secure/xarionix-signing/publisher.key \
  --publisher example-publisher --key-id release-key \
  --output /secure/example-module-1.0.0.xpkg
```

`sign` имеет **те же аргументы**, пересчитывает inventory и создаёт новый deterministic/self-verified ZIP.
Он предназначен для подписи/re-sign подготовленной distribution, не патчит произвольный ZIP на месте.
`--output` не может быть внутри source и не перезаписывается. Пути/ссылки/обнаруживаемые secret names
проверяются до упаковки; это не замена отдельному секрет-сканированию подготовленной дистрибуции.
Пакер использует directory-relative O_NOFOLLOW opens, отвергает symlinks/hardlinks и не загружает payload целиком.

## 3. Offline trust store и verify

В защищённом редакторе создайте `trust.json` с public key из первого шага:

```json
{
  "schema_version": 1,
  "keys": [{
    "publisher_id": "example-publisher", "key_id": "release-key",
    "public_key": "<approved-base64-32-byte-public-key>",
    "publisher_status": "active", "status": "active", "namespaces": ["example"]
  }]
}
```

Placeholder намеренно не является ключом и не проходит verifier. Проверьте происхождение и fingerprint
независимым каналом, защитите файл от записи посторонними. Затем:

```bash
.venv/bin/python -m scripts.xpkg verify \
  --package /secure/example-module-1.0.0.xpkg --trust-store /secure/trust.json
```

Успех — escaped JSON и exit 0. Ошибка — bounded JSON code в stderr и exit 1.
`core_compatible=false` — самостоятельный verdict: криптографически корректный пакет может требовать другой Core.
Registry такой пакет не публикует. `deployment_ready=false` всегда: execution отсутствует.

## 4. Регистрация доверия через реальный Core API

Platform Admin должен иметь реальную настроенную MFA policy; пустой allowlist закрывает эти API.
Получите native human access token штатным OIDC Authorization Code + PKCE, не password grant.
Храните HTTP Authorization header в защищённом `/secure/core-admin.headers` (600), не в command argv/истории.
Создайте JSON request files с публичными metadata, не private key:

```json
{"publisher_id":"example-publisher","display_name":"Example publisher"}
```

```bash
curl --fail-with-body --header @/secure/core-admin.headers \
  -H 'Content-Type: application/json' --data-binary @/secure/publisher.json \
  https://core.example.org/api/v1/platform/package-publishers
```

Возвращённый UUID используется в `/package-publishers/{uuid}/keys`: POST
`{"key_id":"release-key","public_key":"<тот же approved public key>"}`.
Затем PUT `/package-publishers/{uuid}/namespaces` с `{"namespaces":["example"]}`.
Это operator approval, **не self-registration издателя и не применение permissions**.
Все три операции записывают audit в той же PostgreSQL transaction.

## 5. Upload, inspection, diff, revoke

```bash
curl --fail-with-body --header @/secure/core-admin.headers \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @/secure/example-module-1.0.0.xpkg \
  https://core.example.org/api/v1/platform/packages
```

По package UUID: GET metadata, GET `/manifest`, POST `/verify`. Listing — `?limit=20&offset=0`.
Для двух версий одной lineage: GET `/packages/{new_uuid}/diff?previous_id={old_uuid}` или offline
`python -m scripts.xpkg diff --previous old-manifest.json --current new-manifest.json`.
Diff только информирует, не даёт новых прав. Dependency candidate report не устанавливает зависимости.

Отзыв: POST `/package-publishers/{publisher_uuid}/keys/{key_uuid}/revoke`.
После него GET package показывает `current_trust=false`, reverify/import не принимает ключ,
история и blob остаются. Ротация — новый key ID/public key; отозванный key ID не оживает.
Перечитайте `publisher-trust.md` до изменения namespace allowlist: revoke grant terminal.

## 6. Что дальше, но не сейчас

Future 4C: явный approved install plan, текущий trust+blob recheck, dependency pinning/diff approval,
изолированный runtime и отдельный migration/rollback contract. Standard не означает Python внутри Core.
Autonomous продолжает работать по Sprint 4A HTTPS control plane, без автоматической выдачи credentials.
Company/user licensing, activation, DRM, hardware binding и ограничения по числу инсталляций не реализуются.
