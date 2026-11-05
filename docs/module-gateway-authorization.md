# Company authorization и concurrency boundary

```mermaid
sequenceDiagram
  participant User
  participant Core
  participant DB
  participant Agent
  participant Module
  User->>Core: Human JWT + company UUID + operation ID
  Core->>DB: Identity / user / membership / effective RBAC / live trust / runtime
  DB-->>Core: Short immutable verdict; transaction closed
  Agent->>Core: Authenticated poll
  Core-->>Agent: Typed dispatch, no human token
  Agent->>Core: Claim correlation
  Core->>DB: Recheck current authorization and exact generations
  DB-->>Core: Permit; transaction closed
  Core-->>Agent: Claim accepted once
  Agent->>Module: Fixed local IPC with Core execution context
  Module-->>Agent: Bounded JSON
  Agent->>Core: Bound result
  Core->>DB: Recheck before releasing response
  Core-->>User: JSON body + operation request UUID
```

Используется существующий `rbac.authorization.require`: active human identity/user,
membership и company; active role/definitions/namespace; RolePermission generation;
SQL `core_module_available` со всеми exact dependency pins. PermissionDelegation
по-прежнему ограничивает grant authority, а не даёт право вызова сама по себе.
Owner/Platform Admin не получают module permission автоматически.

Дополнительно сверяются trusted publisher/key/grant, package state, signed operation,
private profile, host, успешный ACK, fresh health, digest и поколения. Additive SQL
wrapper сохраняет прежний `core_module_authorized_4d` и требует approved private
profile/API digest/protocol/active gateway identity для пакета с API resource.

Actor/company/permission не принимаются из `X-User-Id`, `X-Company-Id`, cookies или
body. Поля execution context создаёт Core. Context — данные приватного IPC, не
Bearer token и не credential для human/machine/deployment Core endpoints.

Нет положительного authorization cache. Revocation перед claim запрещает dispatch;
изменение после выполнения блокирует выдачу ответа при повторной проверке.
Между разрешённым claim и началом/окончанием remote operation есть concurrency
boundary: начатую запись нельзя обещать откатить одновременно с отзывом прав.
Gateway не даёт exactly-once и не повторяет write при потерянном ответе.
