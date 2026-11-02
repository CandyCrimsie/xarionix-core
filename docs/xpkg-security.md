# Package threat model и границы доверия

Модель: недоверенные HTTP/ZIP/JSON/metadata → bounded verifier → approved external trust → CAS + registry.
Подпись не является sandbox, human authorization, лицензией, антивирусом или разрешением на execution.
Core никогда не импортирует Python, не загружает JavaScript, не запускает shell/Docker/миграции из пакета.
Ни один этап не создаёт Keycloak credentials, ModuleService, company scope или active permission.

| Угроза | Защита и остаточный риск |
|---|---|
| 1. Подделка publisher | Внешний approved public key; signed publisher/key identity; ручная сверка fingerprint обязательна |
| 2. Подмена public key | Immutable DB binding/key ID, unique fingerprint; package не является trust anchor |
| 3. Отозванный key | Live trust на import/read/reverify; future install обязан повторить проверку |
| 4. Украденный private key | Отзыв и ротация; до отзыва подпись может быть валидной, нужна экспертиза содержимого |
| 5. Перепаковка ZIP | Strict layout + immutable archive SHA/logical version; semantic-preserving repack не ломает подпись, но не заменяет публикацию |
| 6. Изменение manifest | Domain-separated complete canonical manifest signature |
| 7. Изменение backend bytes | Signed SHA/size + actual streamed hash |
| 8. Изменение frontend bytes | Тот же inventory; signature не разрешает выполнение JS |
| 9. Скрытый файл | Exact inventory, нет ignored service entries, дырок/хвостов |
| 10. ZIP Slip | ASCII POSIX paths, no dots/drives/backslashes; вообще нет extract |
| 11. ZIP Bomb | Compressed/inflated/count/ratio/metadata caps и фактический byte counter |
| 12. Duplicate ZIP names | Casefold collision rejection, central/local equality |
| 13. Duplicate JSON keys | object_pairs_hook, strict schemas, canonical bytes |
| 14. Symlink/hardlink traversal | Archive special types/extras denied; no extraction; CAS/source O_NOFOLLOW, CLI source ancestor dirfds |
| 15. Unknown compression | Только STORED/raw DEFLATE, no encryption/ZIP64/descriptors |
| 16. Ложный Content-Length | Проверка header и фактического stream size, mismatch 400, over-limit 413 |
| 17. Chunked limitless body | Тот же byte counter + deadline, auth до body consumption |
| 18. Concurrent duplicate upload | Two storage slots + DB unique constraints, short admin serialization, same SHA idempotent |
| 19. Crash между FS/COMMIT | Blob-first, orphan-only gap, explicit exclusive-lock reconcile; не обещается distributed atomicity |
| 20. Blob tampering | Rehash actual publication bytes, immutable non-overwrite CAS, digest at manifest read/full reverify, quarantine |
| 21. Foreign namespace | Separate exclusive publisher namespace grants, live final trust check |
| 22. Protected Core permission | `core` namespace/IDs denied; active catalog неизменен и защищён старым DB guard |
| 23. Downgrade | Нет автоматического выбора/активации версии; 4C должен потребовать explicit reviewed downgrade plan |
| 24. Dependency ambiguity | Publisher pin, strict SemVer, bounded transitive cycle/missing/ambiguity report, no newest fallback |
| 25. Metadata execution | Только data schemas; никаких scripts/entrypoint callbacks/dynamic imports |
| 26. SSRF homepage/runtime URL | Homepage только строка, HTTP fetch отсутствует |
| 27. Arbitrary server file read | API принимает bytes/UUID, CAS reference только SHA; нет client path/download API |
| 28. Log injection/secret echo | Stable error codes, JSON escaping, no request body/header/traceback logs |
| 29. Trust store replacement | File operator trust boundary; offline store необходимо защищать и обновлять после revoke |
| 30. Signing вместо user authorization | Dedicated Platform Admin + recent MFA, machine JWT отвергается human dependency |
| 31. Admin/key revoked during upload | Начальная транзакция закрыта; live JWT, admin, MFA и trust проверяются вновь после filesystem work |
| 32. Cancellation/slow client | Deadline, cleanup finally, finite slots; worker не оставляется писать удалённый staging |
| 33. Disk exhaustion | Bounded staging (~512 MiB), free-space gate, no startup cleanup; quota/monitoring нужны отдельно |
| 34. DEFLATE unused data/polyglot | Full stream EOF/CRC/size verification, no unused_data, no arbitrary prefixes or trailing records |
| 35. Namespace/key reactivation через DML | Новая migration terminal guards, DELETE/TRUNCATE denied; DDL owner остаётся доверенным оператором |

## Состояния и ошибки

Не переводить исторический `available` в unconditional `trusted=true`. Active publisher/key/grant проверяются
отдельно. Quarantine отражает byte failure; trust revoke — политика, а не повреждение архива.
API/listing не обещает целостность каждого blob без I/O; поле `blob_integrity=not_checked` явно это показывает.
Metadata-only dependency readiness не является проверенным install plan.

Поддерживается один local POSIX CAS, не hostile shared filesystem/NFS и не active-active multi-host.
Владелец Core runtime/volume/DB credentials находится внутри доверенной границы; DDL owner может удалить
триггеры. Read-only root/cap-drop/noexec tmpfs не превращают скомпрометированный Core в недоверенный код.
Защищённый процесс Core имеет право управлять publisher trust через DB; компрометация самого Core критична.

Runtime/migrator separation не применяется незаметно к старым deployments. Аудит и поддержанный maintenance
путь описаны в `runtime-database-roles.md`; текущий dev нельзя объявлять restricted только по rehearsal.
Новые package endpoints не требуют CREATE/ALTER/DDL privileges у runtime.

## CI

Сохранены Ruff/format/MyPy, unit coverage gate, реальный PostgreSQL/Keycloak integration stage,
Bandit, pip-audit двух locks, Gitleaks, Trivy и rootless DinD/TLS wrapper. Новых внешних scanners нет.
Private keys генерируются только в pytest temporary directories/явной offline signing directory,
не попадают в artifacts или Docker context. Тестовый vector содержит публичный RFC seed, не production key.
Pipeline/release settings, Runner и deployment не менялись; локальные проверки не доказывают GitLab run.
