# Runtime / migrator: поддерживаемая maintenance-граница

Существующие dev/production базы **не переводятся автоматически**. Их `core_app` по-прежнему может
владеть таблицами; это отражается `python -m scripts.db_privileges`, а не скрывается словом hardening.
В 4B подготовлены отдельные Compose credentials:

- `XARIONIX_DB_USER` / `XARIONIX_DB_PASSWORD` — только Core runtime.
- `XARIONIX_MIGRATION_DB_USER` / `XARIONIX_MIGRATION_DB_PASSWORD` — только migrate container.
- Defaults сохраняют старый `core_app`; пустой migration password использует прежний DB password.

Ни один пароль SQL автоматически не меняется. Core **не получает migration password** в environment.
Установщик проверяет имена/длину отдельно заданного migration secret; не создаёт скрыто роли в существующей БД.

## Порядок для новой restricted установки или upgrade

Это явная операция PostgreSQL DBA, не обычный `dev-up`:

1. Maintenance: остановить writers, сделать проверяемый backup Core DB + package volume, записать текущие роли/head.
2. В bootstrap DBA session создать отдельный NOLOGIN owner и LOGIN migrator/runtime, secrets в защищённом
   SQL input/libpq, не в shell argv/логах. Не переиспользовать Keycloak account.
3. При переносе existing schema: сначала COMMIT всех deferred constraints; затем transfer DB/schema,
   **всех** Core tables/functions к NOLOGIN owner. Нужны проверенный object inventory и pinned search_path.
4. Migrator — член owner, с default `SET role` для этой конкретной БД. Runtime не member owner/migrator,
   без superuser/CREATEDB/CREATEROLE/replication, без CREATE/TEMP, без schema CREATE/ownership.
5. Runtime: CONNECT/USAGE/SELECT, business INSERT/UPDATE/DELETE (включая publisher/package tables),
   audit INSERT без DELETE/UPDATE/TRUNCATE; catalogs/alembic read-only; требуемый EXECUTE Core functions.
   Существующие immutable/revoke/audit/owner guards не отключать. Package tables не требуют DDL.
6. Явно выставить новые пары Compose env после проверки credentials; выполнить migrate как migrator,
   проверить head/readiness и функциональность под runtime. Не передавать migration credentials процессу Core.
7. Выполнить negative checks ALTER/DISABLE TRIGGER/catalog write/audit DELETE/TRUNCATE/SET ROLE owner;
   сверить сохранённые UUID/row counts, RBAC, приглашения, machine control, package upload/reverify.
8. Только после проверки закончить maintenance. При неуспехе — восстановление согласованного backup,
   не destructive downgrade и не произвольный ownership rollback на работающих writers.

Точный воспроизводимый rehearsal: `tests/integration/test_module_db_privileges.py`: отдельная disposable DB,
настоящие owner/migrator/runtime роли, migration 0004 → head, перечисленные отрицательные проверки,
Core identity/company/role/employee/machine/package operations и readiness. Это тест работоспособности
модели и upgrade-пути, **не утверждение, что рабочая dev DB уже переведена**.

Автоматизация DBA ownership transfer для произвольных existing installations намеренно не запускается:
нужно учитывать extensions/внешние объекты/backups и конкретные административные процессы.
Старая схема bootstrap остаётся совместимой; для production рекомендован описанный restricted rollout.
