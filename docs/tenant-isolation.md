# Tenant isolation и транзакционные инварианты — Sprint 3

Компания — граница domain access, а не произвольный claim/URL параметр. `require_company` делегирует проверку engine `app/domains/rbac/authorization.py`: active human User, Membership `(company_id,user_id,status=active)`, текущие permission keys и состояние компании. Platform Admin **не** fallback. Недоступная компания и чужие UUID дают 404 без enumeration.

Employee, Membership, Invitation detail/mutation queries всегда включают одновременно resource UUID и company_id. Company ID/role из JWT/frontend headers не используются. Employee user link дополнительно проверяет active Membership целевой компании. Invitation accept ищет хеш только в запрошенной компании и проверяет recipient, TTL, lifecycle и действующие полномочия издателя. Глобальный профиль не содержит company roles.

Role/RolePermission/MembershipRole/PermissionDelegation/InvitationRole также scoped; composite FK запрещают смешение tenants даже direct SQL. Нет доверия имени роли, JWT permissions или `X-Company-Id` как доказательству доступа. Owner marker и Platform Admin отделены от custom grants. [Модель RBAC](rbac.md), [grantability и invitation snapshot](permission-delegation.md).

## Concurrency

- Критические company mutations берут свой transaction advisory lock, reads — shared. После lock повторно читаются User/Membership/RoleAssignments/delegation. Нет внешнего authorization cache и grant по stale snapshot. Независимые компании не сериализуются через singleton.
- Глобальная policy читается `FOR SHARE` только зависимыми create/quota/invite операциями и меняется `FOR UPDATE`. Platform Admin имеет независимый global lock. Quota защищена отдельным per-user lock. [Порядок, targeted guards, SQLSTATE и benchmarks](transaction-locking.md).
- JIT для отсутствующего `(issuer,subject)` берёт только keyed `pg_advisory_xact_lock`, повторно читает Identity и создаёт User/Identity атомарно. Existing identity fast path не сериализует обычные profile GET.
- FK/unique/check constraints обеспечивают корректные links/status/роль, unique slug, unique `(company,user)`, unique token hash.
- Deferred PostgreSQL triggers защищают последнего active company owner с active User и последнего Platform Admin; targeted row guards защищают direct DML, не сканируя все компании после каждого изменения. Они проверяют конечное состояние транзакции, поэтому transfer/create не блокируются промежуточным отсутствием owner.
- CompanyRequest row дополнительно `FOR UPDATE`, статус pending меняется вместе с Company/owner/audit. Invitation row также `FOR UPDATE`, Membership и accepted меняются вместе. Два конкурентных запроса не принимают/одобряют одну запись дважды.
- FastAPI dependency function scope завершает COMMIT **до** выдачи ответа. Integration test принудительно ломает deferred COMMIT: клиент получает 409, company/membership/audit не остаются наполовину сохранёнными.

Блокировки используют [официальную PostgreSQL transaction semantics](https://www.postgresql.org/docs/18/explicit-locking.html). Это не только Python count перед UPDATE. Privileged DB operator остаётся частью доверенной границы: он может менять DDL/отключать trigger; platform owner не является полномочием DB.

## Ограничения и следующий hardening

ORM-level scoping централизован и покрыт реальными PostgreSQL/Keycloak API тестами для двух компаний. RLS не внедряется без отдельного анализа trusted context/migration/runtime grants. Один DB app user пока также выполняет Alembic; разделение runtime и DDL прав нужно до более строгого production hardening.

Sprint 3 заменил action→role mapping на company-scoped permissions/role assignments и singleton gate на targeted locks. Один tenant всё ещё намеренно сериализует критические writes. Arbitrary multi-row direct DML должен следовать документированному порядку; deadlock victim откатывается. Machine principal authorization остаётся отдельной будущей policy, не автоматическим разрешением human APIs. Rate limiting/pending-invitation quotas и внешний защищённый audit sink требуют дальнейшего operational hardening.
