# Installation и runtime lifecycle

```mermaid
stateDiagram-v2
  [*] --> NotProvisioned
  NotProvisioned --> Stopped: approved provision
  Stopped --> Running: approved start + ready
  Running --> Stopped: approved stop
  Running --> Running: approved restart or reconcile
  Running --> Failed: health or isolation failure
  Failed --> Running: fresh approved recovery
  Stopped --> NotProvisioned: approved deprovision
  Running --> Quarantined: trust or policy revoked
  Quarantined --> Retired: explicit retirement
```

Сначала 4C install plan, approve и trusted executor apply. Затем отдельный
`POST /api/v1/platform/deployment-plans`:

```json
{
  "idempotency_key": "00000000-0000-4000-8000-000000000001",
  "installation_id": "00000000-0000-4000-8000-000000000002",
  "host_id": "00000000-0000-4000-8000-000000000003",
  "operation": "start",
  "expected_installation_generation": 1,
  "expected_deployment_generation": 0,
  "profile": "offline-small-v1"
}
```

UUID здесь только пример структуры, не реальные объекты. Проверьте серверный body/digest,
подтвердите через `/deployment-plans/{id}/approve` с `{digest}` и свежим MFA.
Поддержаны provision/start/stop/restart/upgrade/rollback/deprovision/inspect/reconcile/
quarantine/retire. GET plan, cancel pending, runtime list и paginated job history доступны
в том же Platform Admin API. Повтор approve applied plan возвращает исходное job ID.

Provision создаёт stopped container; start ждёт liveness/readiness. Только после healthy
разрешён отдельный 4C enable. Stop не удаляет package/catalog/history. Deprovision требует
сначала observed stopped и удаляет только помеченные runtime containers без `-v`.
В текущем offline profile пользовательских persistent mounts нет.

```mermaid
sequenceDiagram
  participant Operator
  participant Core
  participant Agent
  participant Runtime
  Operator->>Core: Approve provision / start plan
  Agent->>Core: Poll + claim fenced job
  Agent->>Runtime: Verified import + create or start
  Agent->>Runtime: Fixed live + ready + isolation probe
  Agent->>Core: ACK exact generation + image + fence
  Operator->>Core: Separate installation enable
  Operator->>Core: Approved stop
  Agent->>Runtime: Stop only owned container
```

```mermaid
sequenceDiagram
  participant Installer
  participant Core
  participant Agent
  Installer->>Core: Apply metadata update to exact signed package
  Core->>Core: Availability closed until matching runtime ready
  Agent->>Core: Approved upgrade job
  Agent->>Agent: Verify new image, stop old, start new, check ready
  Agent->>Core: ACK new image or failure
  Installer->>Core: Explicit approved metadata rollback
  Agent->>Core: Separate approved runtime rollback job
  Agent->>Agent: Restore exact prior digest, check ready
```

Нет автоматического восстановления trust или отката DB migrations. Неуспешный upgrade
оставляет fail-closed state; rollback требует новой проверки package и одобрения.
`inspect` не создаёт и не запускает отсутствующий контейнер. Restart также не provision.
