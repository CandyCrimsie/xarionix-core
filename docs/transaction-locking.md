# Транзакционная модель Sprint 3

## Порядок и области

`0003_locking` удаляет singleton `core_mutation_gate()` из Python HTTP dependency, JIT и statement triggers. Функция `mutation_gate()` оставлена только для эксклюзивного изменения PlatformSettings, не для Employee/Role/обычных company writes.

| Ресурс | Синхронизация |
|---|---|
| Глобальная политика | PlatformSettings `FOR SHARE` для create/quota/invite, `FOR UPDATE` при policy mutation |
| Platform Admin | Отдельный transaction advisory lock `administration/singleton` |
| Quota владельца | Transaction advisory lock `quota/{User UUID}`, несколько UUID сортируются |
| Компания и её RBAC/участники | Transaction advisory lock `company/{Company UUID}`, shared чтение / exclusive mutation |
| Request | Своя строка `FOR UPDATE` перед review |
| Invitation | Company lock, затем своя строка `FOR UPDATE` |
| Отсутствующая Identity | Keyed transaction advisory lock по issuer+subject, без policy gate |

Общий порядок для нужных ресурсов: **policy → administration → quota (sorted User UUID) → company (sorted Company UUID) → дочерние строки**. Операции не берут ненужные области. Review заявки берёт policy до administration; создание/передача владения — quota до company; обычная запись Employee/Role не блокирует policy. Company lifecycle заранее фиксирует owner set и отказывает с retry-conflict, если он изменился до захвата lock, не нарушая порядок новым quota lock.

`core_lock(scope,identifier,shared)` использует PostgreSQL `hashtextextended('xarionix-core/v3/' || scope || '/' || identifier,0)` и **transaction-scoped** advisory locks. Одинаковая SQL-функция используется Python и triggers. 64-bit hash collision может дать лишнее ожидание, но не выдать чужой scope или обойти FK. Session-level locks и Python mutex для DB authorization не используются. JIT имеет отдельный SHA-256-derived 64-bit key; возможная hash collision также только сериализует. Unique `(issuer,subject)` остаётся обязательным.

User suspension берёт административную область, затем компании его Membership в UUID-порядке. Прямой DML на Users/Company/Membership использует targeted BEFORE ROW guards; они получают нужные company/quota/admin locks. UPDATE может уже владеть row lock до BEFORE ROW trigger: произвольный multi-row direct DML должен следовать тому же порядку; PostgreSQL deadlock victim откатывается. Не обещается отсутствие deadlock для произвольного SQL вне API.

## Проверки и MVCC

Read Committed остаётся выбранной isolation policy. После lock заново читаются User, Membership, RoleAssignments, активность permissions и delegation; ORM `populate_existing`/refresh не дают использовать identity-map snapshot до ожидания. Policy `FOR SHARE` совместима с такими же чтениями независимых создателей и конфликтует с policy UPDATE. После ожидания новый statement читает актуальное состояние, не старый process cache. Модель соответствует [PostgreSQL locks](https://www.postgresql.org/docs/18/explicit-locking.html) и [Read Committed](https://www.postgresql.org/docs/18/transaction-iso.html).

`core_check_owners()` проверяет только затронутые Company UUID. При User status mutation рассматриваются его компании через индекс memberships.user_id. Проверяются final active Company → active owner Membership → active User. Deferred guard допускает промежуточное отсутствие владельца внутри атомарной передачи и отказывает при невалидном COMMIT. User/Company/Member identity не перепривязывается произвольным UPDATE. `core_check_admins()` относится только к global grants/соответствующим Users, не сериализует обычные company writes.

DB composite FK, PK/unique/check и protected RBAC triggers дополняют сервисную авторизацию. SQL-оператор, способный менять DDL/отключать triggers, остаётся доверенной границей. Append-only audit guard сохранён.

FastAPI function-scoped dependency делает COMMIT до HTTP success. FK/unique/check failure → безопасный 409 `data_conflict`; SQLSTATE 40P01/40001/55P03/57014 → 409 `transaction_conflict`, без SQL/parameters. `lock_timeout=5s`, statement timeout=10s. Автоматического replay небезопасных POST после неопределённого результата нет; клиент явно обновляет состояние/повторяет запрос. Бесконечных retry нет.

## Воспроизводимый benchmark

`make locking-benchmark` создаёт отдельный disposable project и проходит 0001 → 0002 (замер baseline) → 0003 (замер новых locks) → head. Старый baseline действительно использует `0002_platform`, а не придуманную задержку. Workload: SQL gate, UPDATE Employee и INSERT audit, COMMIT; без искусственного sleep в critical section. По 100 операций (200 при concurrency 50), одна либо разные компании, concurrency 1/5/10/20/50. Sampling PostgreSQL wait_event_type=Lock — каждые ~10ms; отдельно измеряется время приобретения lock вместе с сетевым RTT. Это DB critical-section microbenchmark, **не** end-to-end HTTP/JWT/RBAC throughput и не production SLA.

Измерено 02.11.2026, macOS/Docker Desktop Linux arm64, PostgreSQL 18.6. В каждой ячейке latency — p50/p95/p99, ms. Throughput включает создание worker connections.

| Scope / concurrency | До, ops/s | После, ops/s | Latency до | Latency после | Lock wait samples до → после |
|---|---:|---:|---|---|---|
| Одна / 1 | 767.29 | 762.07 | 1.168/1.370/3.016 | 1.191/1.458/3.184 | 0 → 0 |
| Одна / 5 | 982.16 | 918.67 | 3.953/6.130/8.633 | 4.056/6.482/10.371 | 25 → 25 |
| Одна / 10 | 870.92 | 870.90 | 8.447/14.708/16.704 | 8.239/15.160/16.836 | 57 → 61 |
| Одна / 20 | 752.54 | 709.55 | 17.095/31.955/34.011 | 17.511/34.066/36.365 | 141 → 137 |
| Одна / 50 | 669.90 | 695.84 | 44.653/81.588/86.671 | 48.242/81.807/85.999 | 850 → 808 |
| Разные / 1 | 819.38 | 824.21 | 1.125/1.291/2.897 | 1.124/1.235/2.982 | 0 → 0 |
| Разные / 5 | 993.04 | 2046.62 | 3.977/6.350/9.928 | 1.614/3.266/3.685 | 25 → 0 |
| Разные / 10 | 867.83 | 1778.73 | 8.117/14.572/16.834 | 3.197/5.149/9.739 | 67 → 0 |
| Разные / 20 | 750.70 | 1279.89 | 16.758/30.129/31.721 | 8.793/12.077/15.856 | 145 → 0 |
| Разные / 50 | 682.02 | 1431.33 | 45.148/80.101/84.335 | 18.234/27.463/33.168 | 837 → 0 |

Сырые generated JSON: `reports/benchmark-0002_platform.json`, `reports/benchmark-0003_locking.json`; содержат также p50/p95/p99 lock acquisition и число samples. Нулевая sampled wait не доказывает нулевое ожидание во все моменты; отдельные integration tests удерживают singleton/другую company lock и требуют успешного независимого API mutation до release blocker. Одна компания ожидаемо сериализуется; таблица не утверждает ускорение для неё.

## Upgrade Sprint 2 → Sprint 3

1. Проверить исходную revision 0002 и целостность owners/admins. Сделать согласованный backup Core и Keycloak DB, сохранить секреты вне Git; проверить восстановление.
2. Maintenance: остановить входящие writes и старый Core. Zero-downtime совместимость не заявлена.
3. Собрать новый image; не менять credentials или volumes. Штатным `migrate` выполнить `alembic upgrade head`: 0003 меняет locks/guards, 0004 создаёт каталог/RBAC и backfill.
4. Проверить head=`0004_rbac`; UUID Users/Identity/Membership/Company, owner markers и бизнес-записи сохранены; системные assignments соответствуют старым markers. 0001/0002 не переписаны.
5. Запустить новый Core, проверить live/ready, 401 без JWT, tenant/RBAC/MFA и application smoke. Для dev — `make dev-up`, затем `make dev-test`.
6. При ошибке остановить writes и анализировать rollback транзакции. Не выполнять destructive downgrade: восстановление из проверенного backup под maintenance, с учётом всех writes после cutover. Старый бинарник поверх новой схемы без отдельной проверки не запускать.

Никаких `down -v`, prune, пересоздания рабочих databases или ротации SQL passwords миграция не делает.
