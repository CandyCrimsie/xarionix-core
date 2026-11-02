# Sprint 4B — реализация и проверка

## 1. Объём и исходное состояние

Репозиторий `xarionix-core`, baseline `0270b03a951a124452cacd264476dd6078517bd4`.
На старте рабочее дерево было чистым. Соседние ERP/Web/Billing не изменялись.
Commit/push, публикация образа/пакета, production deployment и изменение Runner не выполнялись.
Старые Alembic revisions 0001–0005 сохранены. Product version осталась 0.1.0.

Реализован inert package/trust registry, **не installer**. Package, Publisher, logical module metadata
и будущая Installation не объединены. Новых пустых доменов и execution TODO-заглушек нет.

## 2. Фактический `.xpkg` V1

Strict ZIP transport, canonical manifest + отдельный signature envelope + exact payload inventory.
STORED/raw DEFLATE, local/central consistency, no extraction, bounded actual byte counts/CRC/SHA,
запрет ambiguity/duplicates/special entries/ZIP64/descriptors/hidden bytes/unused DEFLATE tail.
Все девять archive dimensions можно уменьшать конфигурацией, но hard caps поднять нельзя.
Нормативные поля/JSON/paths/пределы — [xpkg-specification.md](xpkg-specification.md).

## 3. Криптография и CLI

Ed25519 через уже закреплённую `cryptography==50.0.2`; новой внешней crypto/SemVer библиотеки не добавлено.
Подписывается domain-separated complete canonical manifest вместе с publisher/key/algorithm identity.
Внешний public-key trust, strict base64, SHA-256 inventory, reproducible writer и self-verification.
`scripts.xpkg`: keygen, pack, sign, offline verify, informational diff; безопасные JSON reports/nonzero failures.
Ключ 0600/O_EXCL, no overwrite; payload streams через pinned directory descriptors без symlink/hardlink reads.
Fixed RFC8032 public test seed/vector содержит canonical bytes, manifest/message digests, public key и signature.
Это тестовый материал, не автоматически установленный trust anchor.

## 4. Publisher trust

Global Platform Admin + recent configured MFA, не Company Owner и не machine.
Несколько immutable keys, terminal revoke, exclusive namespace authority отдельно от active catalog.
Существующий reserved/active namespace сохраняет module owner: publisher grant не может его заменить.
Current trust читается заново; длинная проверка не удерживает global admin lock, финальная публикация
повторно проверяет JWT/expiry/MFA/admin/key/publisher/namespace. Publisher/key/grant row locks закрывают
конкурентный DML revoke в короткой final transaction. Ротация требует новый key ID, история не удаляется.

## 5. Registry и сбои

Raw bounded HTTP stream → private staging → worker validation → durable no-overwrite content-addressed blob
→ short metadata + audit transaction. Same SHA retry возвращает UUID исходного пакета; different SHA той же
module/version/publisher — 409. Archive bytes не исполняются и не отдаются через arbitrary download/path API.

Файлово-DB atomic transaction **не заявляется**. Crash/rollback после publication оставляет orphan,
который виден explicit operator reconcile; trusted partial metadata не создаётся. Exclusive maintenance lock
защищает snapshot/cleanup от действующих uploads, referenced blobs не удаляются. Tampering при копировании
проверяется повторным hash, corrupt existing blob не перезаписывается; reverify может quarantine запись.

Два cross-process flock slots, ограниченный staging/free-space gate, thread work вне event loop.
Native cancellation/repeated cancellation ожидает завершения файлового worker до cleanup/unlock;
не требуется `setTimeout`, detached background publisher или глобальная DB-блокировка на время hashing.

## 6. База и сохранность данных

`0006_package_registry`: publishers, signing keys, namespace grants, module packages; UUID/FK/RESTRICT,
unique/check/index, immutable identities/history, terminal revoke, transactional audit.
`0007_instance_history`: запрет DELETE/TRUNCATE как обхода terminal ModuleInstance revoke через reinsert.
Readiness требует head `0007_instance_history`. Это additive migrations без удаления старых данных.

Реальный существующий dev volume до/после имеет PostgreSQL system identifier **7703322558304469031**.
Head обновлён 0005 → 0006 → 0007; identities=0 и companies=0 сохранились. Пароли/volumes не сбрасывались.
Core/Keycloak healthy; `dev-test` подтверждает health, authentication denial, discovery/JWKS.

Restricted-runtime rehearsal обновлён: настоящие owner/migrator/runtime роли, upgrade 0004 → head,
отрицательные DDL/catalog/audit проверки и реальные package upload/reverify наряду с прежними Core operations.
Compose поддерживает разные runtime/migration credentials. **Рабочий dev автоматически не переведён**:
его core_app всё ещё schema owner (audit это показывает). Maintenance rollout с backup описан отдельно
в [runtime-database-roles.md](runtime-database-roles.md); новых DDL requirements у runtime нет.

## 7. Совместимость / dependencies / diff

SemVer 2 precedence, строгая documented conjunction-range grammar, prerelease/build handling,
отказ неизвестным schema/protocol и пустым ranges. Publisher-pinned dependencies: transitive missing,
ambiguity, cycles/complexity report; нет newest-version fallback или auto-install.
Diff: added/removed/modified permissions, namespace, dependencies, protocol, runtime type, Core range и artifacts.
Structural/cryptographic/current trust/Core compatibility/dependency metadata/deployment readiness разделены.
Frontend bundles остаются inert; CSP/origin/runtime loading не меняются. Active permissions не регистрируются.

## 8. Security-проверки и найденные проблемы

Закрыты: неоднозначный ZIP и скрытый хвост DEFLATE; filename/case/Unicode interpretation collisions;
неограниченный/chunked/неверный Content-Length body; доверие к старому authorization snapshot;
overwriting CAS; orphan gap без recovery; premature file/lease cleanup при native cancellation;
зависание при open FIFO до проверки regular-file type (теперь nonblocking open + fstat);
перехват существующего namespace owner; прямой DML revive/delete-reinsert ModuleInstance.
Для negative ZIP duplicate case Python намеренно выдаёт один warning о создании вредоносного fixture.

В промежуточном расширении privilege fixture были исправлены тестовые INSERT без `active` и выбор native
JWT без test MFA context. Это fixture ошибки, не изменение production MFA-policy и не скрытый skip.
Новая threat model содержит 35 сценариев и явные residual risks. Лицензирования/DRM/activation нет.

## 9. Реально выполненные команды

| Проверка | Результат |
|---|---|
| `make check` | 447 unit/API tests, coverage 75.08% при сохранённом gate 70%; Ruff/format/MyPy/Bash/metadata/Bandit/pip-audit/Compose прошли |
| `make integration-test` | 87 passed на настоящих PostgreSQL/Keycloak/CAS, 357.81s; прежние Sprints 1–4A regression tests сохранены |
| Последний `tests/integration/test_package_registry.py` | 16 passed на реальных PostgreSQL/Keycloak/CAS, включая fault/concurrency/auth/namespace сценарии |
| `make dev-up`, `make dev-test` | Реальный existing volume upgrade, healthy и smoke OK |
| `make docker-build IMAGE=xarionix-core:sprint-4b` | Production multi-stage image + non-root/read-only/OCI/live/unready/401 smoke OK |
| `make docker-scan IMAGE=xarionix-core:sprint-4b` | Trivy HIGH/CRITICAL gate прошёл |
| `python -m scripts.ci secrets` | Full history + non-ignored worktree Gitleaks прошли, без новых исключений |
| `python -m scripts.compose_check --nginx` | Dev/external/managed interpolation/mounts/security и реальный Nginx `-t` прошли |
| `make package-benchmark` | Выполнен локально, таблица ниже; не SLA |
| Offline CLI smoke | Реально выполнены keygen → pack → sign → verify → diff на документированном примере; outputs deterministic, временные ключи удалены |

Последний benchmark: small 64 KiB — 0.00091s; 16 MiB — 0.01585s/146774 bytes Python peak;
512 files — 0.08380s/910148 bytes; 4×16 MiB через 2 threads — 0.03955s/326235 bytes;
invalid early — 0.00005s. Process peak RSS 43.6–46.6 MiB. OS page cache/локальная машина влияют на цифры.
Unit regression дополнительно проверяет peak memory verifier <6 MiB на payload 16 MiB.
Локальные JUnit/coverage/security/benchmark reports лежат в ignored `reports/`, не содержат private keys.
GitLab Pipeline в рамках этой работы **не запускался**, production TLS/DNS и реальный human OTP flow не проверялись.
Native Keycloak test JWT подписаны настоящим провайдером, но test ACR/auth_time — synthetic fixture policy.

## 10. Ограничения

Local POSIX CAS, не NFS/multi-host HA/object store. Не произвольный ZIP import: строгое V1 subset.
Offline trust store нужно защищать и обновлять после revoke. CLI private keys пока без passphrase/provider/HSM.
Подпись не доказывает отсутствие вредоносного кода, secret filename preflight не полноценный secret scanner.
Registry report ограничен 256 packages/4096 dependency edges; trust store — 1024 keys и ≤64 grants на publisher,
включая retained history. Это защитные resource caps, не коммерческие лимиты.
Metadata readiness не проверяет все dependency blobs; deployment_ready всегда false.
Смена существующих DB owners/credentials остаётся явной DBA maintenance-операцией, не autoupgrade.

## 11. Граница следующего этапа

Предложение для 4C: explicit approved install plan, reverify live trust/blob перед применением,
dependency pinning + permission diff approval, sandboxed runtime/migrations/rollback и install history.
Frontend trust/runtime требует отдельного решения 4D/5. В этом этапе 4C не начат: содержимое пакетов,
модульные миграции и контейнеры не запускаются, credentials и permissions автоматически не выдаются.

## Изменённые файлы

Список ниже соответствует рабочему дереву, включая новые untracked файлы; commit не создавался.

- `.dockerignore`
- `.env.example`
- `.gitignore`
- `.gitlab-ci.yml`
- `Dockerfile`
- `Makefile`
- `README.md`
- `app/api/v1/package_schemas.py`
- `app/api/v1/packages.py`
- `app/api/v1/routes.py`
- `app/core/config.py`
- `app/core/database.py`
- `app/core/module_body_limit.py`
- `app/domains/packages/__init__.py`
- `app/domains/packages/archive.py`
- `app/domains/packages/codec.py`
- `app/domains/packages/model.py`
- `app/domains/packages/reports.py`
- `app/domains/packages/schema.py`
- `app/domains/packages/semver.py`
- `app/domains/packages/service.py`
- `app/domains/packages/storage.py`
- `app/domains/packages/work.py`
- `app/domains/registry.py`
- `app/main.py`
- `app/version.py`
- `compose.dev.yaml`
- `compose.yaml`
- `docs/architecture.md`
- `docs/frontend-module-trust.md`
- `docs/module-development-guide.md`
- `docs/module-permission-contract.md`
- `docs/package-registry.md`
- `docs/publisher-trust.md`
- `docs/runtime-database-roles.md`
- `docs/security-model.md`
- `docs/sprint-4b-validation.md`
- `docs/xpkg-security.md`
- `docs/xpkg-signatures.md`
- `docs/xpkg-specification.md`
- `examples/xpkg/distribution/resources/readme.txt`
- `examples/xpkg/manifest.json`
- `migrations/versions/0006_package_registry.py`
- `migrations/versions/0007_instance_history.py`
- `pyproject.toml`
- `scripts/docker_job.py`
- `scripts/package_registry.py`
- `scripts/setup.py`
- `scripts/validate.py`
- `scripts/xpkg.py`
- `scripts/xpkg_benchmark.py`
- `tests/fixtures/xpkg-v1-vector.json`
- `tests/integration/test_managed_stack.py`
- `tests/integration/test_module_db_privileges.py`
- `tests/integration/test_package_registry.py`
- `tests/package_helpers.py`
- `tests/test_packages.py`
