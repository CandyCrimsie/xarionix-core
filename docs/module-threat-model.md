# Threat model — control plane 4A

Доверенная граница: TLS PKI, настроенный issuer/IdP operator, Platform Admin с реальным MFA, оператор Core/DB/deployment. Company admin и автономный модуль не получают Core DB credentials, DDL, namespace registration или IdP administrative access. Client secret доказывает только идентичность зарегистрированного приложения, не пользователя.

| Угроза | Защита / остаточный риск |
|---|---|
| Неизвестный service account с JWT | Dedicated audience/purpose + точный явный binding; неизвестный service 403, без JIT |
| Подмена instance | service_id в instance query, 1:1 constraint, 404 |
| Подмена company_id | Явный active scope + operation + active Company; только metadata |
| Подмена user_id | DTO extra forbid; user delegation endpoint отсутствует |
| Human RBAC от machine | Отдельные audiences/dependencies, нет Membership/User на machine path |
| Валидный JWT после revoke | DB status каждый запрос под service share lock |
| Утечка client secret | Core revoke + IdP rotate/revoke; secret не в DB/package/logs |
| Компрометированный agent | Ограниченные capabilities/instance/scopes; нет remote execution; token действует до DB revoke |
| Replay ACK | Command/instance binding; одинаковый result идемпотентен, другой 409 |
| Подмена команды | Core HTTPS, фиксированный enum/bounded schema, нет shell/URL handlers |
| Двойная доставка | DB lease/attempts + bounded cache; handlers идемпотентны, не exactly-once |
| Потеря сети после ACK | Повтор результата, идемпотентный COMMIT; реальные network/replay tests |
| Чужой namespace | Machine registrar отсутствует; module_key не namespace authority |
| DB credentials у модуля | Отдельные agent config/network, нет mounts/socket; integration inspection |
| URL/SSRF/internal fetch | Core не принимает callback URL и не подключается к модулю; destinations агента задаёт оператор |
| Секреты в logs | Фиксированные events, без body/header/traceback; redaction tests |
| Protocol flood | 16 KiB JSON, bounded queue/result/list, persisted rate limit; perimeter DoS policy остаётся эксплуатационной задачей |
| Глобальная сериализация | Service SHARE + отдельный instance UPDATE; settings gate отсутствует |

Агент может лгать о health. Ping/status не являются доверенным мониторингом ERP/Billing. Нет host attestation, mTLS/DPoP, packet signing или business tunnel. HTTPS bearer theft требует обычного endpoint/PKI hardening; user delegation и подпись пакетов — будущие этапы.

Privilege rehearsal проверяет NOLOGIN owner, отдельный migrator/runtime, запреты DDL/catalog/audit и штатные mutations на **новой disposable DB**. Существующие установки автоматически не переводятся: до maintenance rollout их owner credentials остаются доверенной границей. Модуль этих credentials не получает.
