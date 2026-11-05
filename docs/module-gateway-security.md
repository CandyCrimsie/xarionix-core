# Gateway security model

См. исходный [аудит и решение до реализации](module-gateway-architecture-audit.md).
Недоверенные: browser JSON/headers, пакет и его process, неаутентифицированный peer,
late/replayed frames. Доверенные: Core, IdP, deployment/Gateway Agent и dedicated
rootless host/kernel. Это явная граница, а не обещание защиты от root хоста.

| Угроза | Enforcement |
|---|---|
| Cross-company / privilege escalation | Live human membership + company permission, без admin bypass |
| Forged actor/company headers | Context создаёт Core; headers не пересылаются |
| SSRF / arbitrary forwarding | Signed operation allowlist, фиксированные loopback port/path |
| Package/key/namespace revoke | Live SQL availability + trust, два pre-dispatch verdicts |
| Stale runtime/package/generation | Signed digests + ACK + exact local journal + post-inspect |
| Stolen deployment credential used as human | Separate principal/audience/identity binding |
| Module returns Set-Cookie/redirect/CORS | Возвращается только typed JSON body, без module headers |
| Queue/JSON/process exhaustion | Byte/depth/count/queue/concurrency/deadline caps |
| Duplicate/missing/late result | Server request UUID + session + generations + one claim/result |
| Module egress | Network none, no mounts/socket/ports, measured kernel constraints |
| Secret/body leakage | No token forwarding, no persistent body, metadata-only audit |

Нет новых DDL/deployment/catalog прав у модуля. Agent не имеет Core DB credentials.
Installer SELECT новых metadata tables не меняет catalog guard. Autonomous 4A не
подменяется синхронным RPC и продолжает работать через существующий outbound protocol.

Ограничения: начатая write может завершиться после revoke/disconnect; no blind retry,
no exactly-once. Relay однопроцессный. При полном захвате trusted Agent/daemon TLS
не доказывает честность reported health. Эти ограничения нельзя исправить отключением
проверок или переходом на открытый сетевой bridge.

Core проверяет, кто может вызвать операцию, и передаёт проверенный context. Сам backend
остаётся ответственным за фильтрацию своих business данных по этому context. Shared
module process владеет своим dataset; Core не обещает защитить его данные от самого
злонамеренного кода этого модуля. Company isolation тестируется на внешнем gateway
и корректном demo handler; per-company execution sandbox здесь не реализуется.
