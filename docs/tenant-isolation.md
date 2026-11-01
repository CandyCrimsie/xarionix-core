# Tenant isolation и транзакционные инварианты

Компания — граница domain access, а не произвольный claim/URL параметр. В `app/core/access.py` `require_company(ctx, company_id, permission)` проверяет active human User, Membership `(company_id, user_id, status=active)`, action→roles mapping и состояние компании. Platform Admin **не** fallback для этой проверки. Недоступная компания и чужие UUID дают 404 без enumeration.

Employee, Membership, Invitation detail/mutation queries всегда включают одновременно resource UUID и company_id. Company ID/role из JWT/frontend headers не используются. Employee user link дополнительно проверяет active Membership целевой компании. Invitation accept ищет хеш только в запрошенной компании и проверяет recipient, TTL, lifecycle и действующие полномочия издателя. Глобальный профиль не содержит company roles.

## Concurrency

- Критические мутации берут `platform_settings WHERE id=1 FOR UPDATE` до чтения изменяемой авторизации/политик. Это общий PostgreSQL transaction gate, сериализующий роли, quota, settings, approve, invitation accept и ownership transfer. CLI использует тот же порядок.
- JIT для отсутствующего `(issuer,subject)` берёт gate и keyed `pg_advisory_xact_lock`, повторно читает Identity и создаёт User/Identity атомарно. Existing identity fast path не сериализует обычные profile GET.
- FK/unique/check constraints обеспечивают корректные links/status/роль, unique slug, unique `(company,user)`, unique token hash.
- Deferred PostgreSQL triggers защищают последнего active company owner с active User и последнего Platform Admin; statement gate защищает соответствующий direct DML. Они проверяют конечное состояние транзакции, поэтому transfer/create не блокируются промежуточным отсутствием owner.
- CompanyRequest row дополнительно `FOR UPDATE`, статус pending меняется вместе с Company/owner/audit. Invitation row также `FOR UPDATE`, Membership и accepted меняются вместе. Два конкурентных запроса не принимают/одобряют одну запись дважды.
- FastAPI dependency function scope завершает COMMIT **до** выдачи ответа. Integration test принудительно ломает deferred COMMIT: клиент получает 409, company/membership/audit не остаются наполовину сохранёнными.

Блокировки используют [официальную PostgreSQL transaction semantics](https://www.postgresql.org/docs/18/explicit-locking.html). Это не только Python count перед UPDATE. Privileged DB operator остаётся частью доверенной границы: он может менять DDL/отключать trigger; platform owner не является полномочием DB.

## Ограничения и следующий hardening

ORM-level scoping централизован и покрыт реальными PostgreSQL/Keycloak API тестами для двух компаний. RLS не внедряется без отдельного анализа trusted context/migration/runtime grants. Один DB app user пока также выполняет Alembic; разделение runtime и DDL прав нужно до более строгого production hardening.

Singleton mutation gate сознательно ограничивает throughput. Перед масштабированием замените его на согласованную и протестированную иерархию per-company/per-owner locks, а глобальные policy/admin изменения оставьте отдельной сериализованной зоной. Сохраняйте тесты last owner/admin, quota, invite accept, approval и transfer; не заменяйте DB guarantees mutex в одном процессе.

Sprint 3 должен расширить текущую action→role mapping до company-scoped permissions/role assignments, не переносить realm roles в бизнес-полномочия и не добавлять скрытый Platform Admin bypass. Machine principal authorization — отдельная permission policy, не автоматическое разрешение human APIs. Rate limiting и quotas на число pending-заявок/приглашений также требуют отдельного operational hardening; cryptographic secret предотвращает угадывание, но не заменяет защиту от resource abuse.
