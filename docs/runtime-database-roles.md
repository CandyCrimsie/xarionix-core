# Runtime / migrator: поддерживаемая maintenance-граница

Sprint 4C вводит третью, **отдельную** restricted installer LOGIN и две NOLOGIN capability роли.
[Точная процедура](module-installation-executor.md), SQL `deploy/postgres/module-executor.sql`.
Не выдавайте HTTP runtime `EXECUTE ON ALL FUNCTIONS`: обязательно исключить
`core_apply_module_catalog(uuid,text,uuid)`. Runtime не должен быть участником
`xarionix_module_executor` или `xarionix_module_catalog`; у catalog owner вообще нет участников.
Installer не получает DDL/catalog DML, пароль мигратора или DELETE audit. Existing dev не
провизионируется автоматически. Bootstrap выполняется DBA явно, не в install.sh/Alembic/Core.

После upgrade 4C DBA выдаёт существующему runtime только новые необходимые ACL
(имя `core_runtime` заменить на фактическое). Миграции не угадывают имена LOGIN ролей:

```sql
GRANT SELECT ON module_installations,module_dependency_pins,module_install_plans,
  module_install_operations,module_installation_history,module_instance_bindings TO core_runtime;
GRANT INSERT,UPDATE ON module_install_plans,module_instance_bindings TO core_runtime;
GRANT EXECUTE ON FUNCTION core_module_available(text,integer),core_module_authorized(uuid,integer) TO core_runtime;
REVOKE ALL ON FUNCTION core_apply_module_catalog(uuid,text,uuid) FROM core_runtime;
```

Новые protected installation/operation/history таблицы не требуют runtime DML. Epoch trigger
после `0009_catalog_read_checks` использует обычный SELECT permissions, не `FOR SHARE`, который
потребовал бы UPDATE privilege. Конкурентная смена epoch оставляет старое назначение неэффективным,
а не даёт дополнительный доступ.

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
