# Sprint 4D — исходный аудит и решения

Baseline `dc29ca064df38cfd1b8393ed6158553f4a884360`, Alembic `0010_instance_enrollment`.
Рабочее дерево перед началом чистое. Соседние репозитории и исторические revisions не изменяются.

Сохраняются: Ed25519/V1 ZIP verifier и CAS, административный MFA, generation/fence
оператора 4C, фиксированная PostgreSQL catalog capability, автономный outbound 4A.
Deployment principal не является ModuleService или User и не получает их права.
Core не импортирует engine adapter, Docker CLI и socket остаются только у отдельного агента.

Выбран ограниченный **OCI runtime profile V1 внутри XPKG V1**, а не увеличение лимитов.
Подписанный inventory включает `payload/resources/runtime-v1.json`, OCI index, manifest,
config и все blobs. Образ не загружается по URL/tag. Лимиты 128/32/256 MiB сохранены;
дополнительно ограничивается распакованный размер OCI layers. Большие ERP images требуют
будущего отдельного blob transport/V2, а не обхода текущих лимитов.
Профиль не содержит shell commands, env, mounts, capabilities или registry credentials.

Control plane: отдельные host/plan/runtime/job сущности поверх ModuleInstallation.
Планы привязаны к exact установленному package и generation; approval — новый свежий
Platform Admin/MFA workflow, не замена install plan. Agent только сообщает факты,
а Core проверяет trust, назначенный host, срок, lease/fence и поколения.
Desired и observed состояния независимы. Safe retirement закрывает availability,
останавливает/quarantine runtime, но не восстанавливает trust и не меняет каталог.

Engine policy: отдельный закреплённый rootless daemon, network=none для первого
профиля, non-root, read-only, cap-drop ALL, no-new-privileges, tmpfs, seccomp,
CPU/RAM/PID limits. Проверяются реальные cgroup controls, а не только запрошенные
Docker flags. При отсутствии enforcement — отказ. Первый health contract —
loopback HTTP через фиксированный Python probe в namespace runtime; произвольных URLs нет.
Offline runtime не получает Core JWT/DB/IdP credentials и не публикует порты.

Основание: [OCI layout 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md),
[Docker rootless](https://docs.docker.com/engine/security/rootless/),
[resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).
Rootless без cgroup delegation недостаточен для ресурсной изоляции; это отдельная
проверяемая предпосылка deployment host, а не свойство слова «rootless».
