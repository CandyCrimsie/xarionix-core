# Контракт namespaces будущих модулей

Реализованы `permission_namespaces`, stable-key каталог и строгие `NamespaceManifest` / `PermissionDefinition`, `DeploymentAuthority`, `validate_registration`. Это validation/ownership foundation для доверенного deployment, **не** публичный registrar, Module Manager или `.xpkg` installer.

| Namespace | Владелец | Состояние Sprint 3 |
|---|---|---|
| core | xarionix-core | active, явный V1 catalog |
| erp | xarionix-erp | reserved, ни одного доступного permission |
| oss | xarionix-oss | reserved, ни одного доступного permission |
| billing | xarionix-billing | reserved, ни одного доступного permission |

Manifest содержит namespace, положительную version и до 100 уникальных definitions: key, description, scope=company, protected, owner_grantable. Namespace prefix обязан совпадать с key. Wildcard, global scope, подмена core/platform authority, дубликаты и protected+owner_grantable запрещены.

Authority создаётся доверенным серверным deployment-кодом, не берётся из пользовательского JWT/JSON/header. Validator сверяет authority с сохранённым immutable namespace owner и active lifecycle. Нельзя активировать reserved namespace одной передачей manifest. Применение проверенного manifest в Sprint 3 — только новая reviewed Alembic revision: обычные INSERT/UPDATE/DELETE/TRUNCATE каталога блокирует PostgreSQL `core_catalog_guard`. Не выдавайте модулю DB-credentials ради регистрации.

Будущий процесс Sprint 4 должен проверить подпись/происхождение `.xpkg`, связать пакет с зарегистрированным namespace owner, проверить semantic version и diff keys, получить административное подтверждение чувствительных permissions, применить доверенную миграцию каталога с аудитом и только затем объявить availability. Runtime регистрация, подписи пакетов и RPC/service authorization сейчас **не реализованы**.

`billing.payments.refund` и другие примеры не зарегистрированы и не могут быть назначены. Owner не получает module permissions автоматически: current system role sets конечны; grant authority дополнительно ограничена owner_grantable metadata. Чувствительное module действие может оставаться protected и потребовать отдельного доверенного policy contract, не произвольного company role.

Модуль в будущем обращается к Core через аутентифицированный API с проверенной delegation/resource context. Неподписанные user_id/company_id не доказательство авторизации. Прямой SQL, собственная выдача platform tokens и наследование Keycloak realm roles модулем не входят в контракт. Полноценный M2M token issuance, machine permission policy, Module Manager и agent отложены.
