# Recovery, delivery и отзыв доверия

Job delivery — at-least-once. UUID стабилен, generation монотонен, lease 120 секунд,
fence меняется при повторной выдаче, максимум 8 attempts, срок не дольше approval.
Plan живёт 600 секунд и дополнительно ограничен MFA freshness. После expiry нужен новый
план и новое подтверждение; продление старой approval не допускается.

```mermaid
sequenceDiagram
  participant Agent
  participant Core
  Agent->>Core: Check-in sequence N
  Core-->>Agent: Job ID + generation + fence A + lease
  Agent->>Agent: Persist accepted generation in SQLite
  Agent->>Core: Recheck authorization before critical step
  Agent->>Agent: Execute idempotently, persist receipt
  Agent->>Core: ACK fence A
  Note over Agent,Core: Lost response or agent restart
  Agent->>Core: Next durable sequence
  Core-->>Agent: Same job, new fence B if lease expired
  Agent->>Core: Durable same receipt with fence B
```

SQLite имеет exclusive writer flock, WAL и FULL synchronous; credentials в нём не хранятся.
Каждая installation имеет собственные `installations/<UUID>/cache` и `data` под 0700.
V1 runtime stateless: data directory не монтируется в контейнер и не удаляется cleanup.
Staging очищается после receipt и при restart, затем пакет проверяется заново.
Expiry не подтверждённого execution job создаёт artifact-free quarantine нового поколения;
поздний ACK старого поколения не может вернуть availability.
Не запускайте два агента с одним STORAGE_ROOT. После падения журнал сохраняет sequence,
последнее поколение и receipt. Deterministic container identity предотвращает дубликаты.
Частичный package staging не исполняется: доставка повторяет полную проверку байтов.
После healthy deployment сохраняются active и один предыдущий stopped container.
Более старые rollback images повторно импортируются из подписанного CAS. GC адресует только
owned stopped containers и их неиспользуемые images: без force/prune/удаления volumes.

```mermaid
flowchart LR
  Observe[Inspect owned containers] --> Compare[Compare exact desired generation and digest]
  Compare --> Match[Refresh verified health]
  Compare --> Missing[Report missing or drift]
  Missing --> Approval[Fresh approved reconcile]
  Approval --> Verify[Recheck trust and resource policy]
  Verify --> Recover[Idempotent recover and ACK]
```

```mermaid
sequenceDiagram
  participant Admin
  participant Core
  participant Agent
  participant Runtime
  Admin->>Core: Revoke publisher/key/namespace or retire installation
  Core->>Core: Availability immediately false
  Agent->>Core: Next authenticated check-in
  Core-->>Agent: Artifact-free quarantine/retire job
  Agent->>Runtime: Stop owned processes, retain data
  Agent->>Core: Stopped ACK
```

Safe retirement: `POST /api/v1/platform/module-installations/{id}/retire` с
`{expected_installation_generation,state: quarantined|retired}`. Это отдельный terminal
security flag, не восстановление revoked key/grant и не обход catalog executor.
После остановки можно approved deprovision без возвращения trust. Аудит/установка/пакеты
сохраняются. Revoked host не получает jobs; authentication rejection приводит к локальной
остановке собственных runtime. Недоступный host физически нельзя остановить из Core.

Сохраняйте backup Core DB + XPKG CAS + agent journal отдельно и согласованно. Нельзя
сбрасывать host sequence или переиспользовать host UUID с новым daemon без явной процедуры.
При ручном drift/утрате daemon ID восстановите host под новой identity через администратора;
автоматического перепривязывания к случайному engine нет.
