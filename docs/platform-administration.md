# Platform Administration

Platform Admin — отдельная PostgreSQL grant, не company owner/admin и не Keycloak realm admin. JWT никогда не создаёт grant. Company данные не раскрываются автоматически: `/platform/companies` возвращает только имя/slug/status/UUID/creator/timestamps; `/companies/{id}/employees|members|invitations` всё равно требует собственное Membership.

## Human admission и первый администратор

1. Пользователь входит в доверенный IdP и вызывает `/api/v1/me`. Запишите **Identity id**; не подменяйте его User id/email.
2. Оператор с административным DB/server-доступом сверяет UUID, issuer, subject с нужным IdP account. Отдельно убеждается, что это человек, не service account. Наличие email/username/realm role этого не доказывает.
3. В настроенном Core container выполните:

```bash
python -m scripts.platform_admin classify --identity-id <existing-identity-uuid> --principal-type human
python -m scripts.platform_admin bootstrap --identity-id <existing-identity-uuid>
```

Для managed dev можно предварить команды `docker compose --env-file .env.dev -f compose.dev.yaml exec -T core`; production использует свою проверенную Compose-конфигурацию. CLI читает DB settings из container environment, не принимает password/token аргументом и не печатает конфигурацию. Не давайте обычным пользователям доступ к Docker/DB ради bootstrap.

Bootstrap допускается только при отсутствии active admins; повтор для того же действующего admin идемпотентен, другой target после bootstrap отклоняется. Секретных стандартных credentials и публичного bootstrap route нет. Все реальные изменения — audit в одной транзакции; offline действия имеют actor_kind=operator и null actor User/Identity, а UUID назначения находится в resource_id. Это не приписывает действия DB-оператора самому целевому пользователю. Human admission не даёт company membership или admin сама по себе. Уже human principal нельзя переключить на service обычной classify-командой/API без отдельного operator review/migration: так не теряются права действующих владельцев.

Последующие grants/revokes выполняются через защищённый `/platform/admins` API. Последний действующий Platform Admin не может быть снят, в том числе конкурентно. Изменение status User напрямую также проверяется DB guard. Обычный владелец компании не управляет этими grants.

## Обязательная IdP-политика MFA

По умолчанию `XARIONIX_ADMIN_ACR_VALUES=[]`: **весь Platform HTTP API закрыт**, даже после bootstrap. Это безопасный результат отсутствующей настройки, не ошибка, которую нужно обходить фиктивным claim.

Оператор Keycloak должен настроить и проверить реальный step-up flow: нужный уровень ACR должен достигаться только после требуемого MFA, включая правильные LoA/ACR mappings, max age и session/token refresh поведение. Добавьте проверяемые `acr` и `auth_time` в **access token**, не только ID token. Убедитесь, что вход без второго фактора не выдаёт этот ACR. См. [Keycloak authentication flows](https://www.keycloak.org/docs/latest/server_admin/index.html#_authentication-flows), [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html).

Затем в защищённой конфигурации Core задайте JSON exact allowlist фактически настроенных значений и максимальный возраст, например:

```dotenv
XARIONIX_ADMIN_ACR_VALUES=["your-enforced-mfa-acr"]
XARIONIX_ADMIN_AUTH_MAX_AGE_SECONDS=300
```

Пример не настраивает IdP сам по себе. Hardcoded claim mapper, `realm-admin` role, наличие токена или свежий `iat` не являются MFA. Core проверяет exact ACR и конечный числовой auth_time, не boolean/NaN, свежесть 30–900 секунд по настройке и допустимое отклонение часов. Нужен NTP. Старый auth_time нельзя заменить временем выдачи access token. Неизвестный/отсутствующий context даёт 403 `configured_recent_mfa_required`; JWT по-прежнему обязан пройти signature/issuer/audience/expiry/typ.

Managed provisioning не объявляет обычный вход прошедшим MFA и не переписывает существующий realm. Настройка production MFA требует настоящего IdP и пользователя; её нельзя подтвердить тестовым hardcoded context. Integration fixtures используют отдельный disposable test realm с явно тестовыми claims только для проверки enforcement, не как доказательство реальной MFA.

## API

Все маршруты требуют active human User + active Platform Admin + configured recent MFA:

- GET/PATCH `/api/v1/platform/settings` — typed policy/owner quota/invitation switch, сохраняются в PostgreSQL без рестарта.
- GET `/api/v1/platform/users`, PATCH `/api/v1/platform/users/{user_id}` — глобальные профили / только active или suspended. Приостановка запрещает даже `/me`; попытка лишить действующую компанию последнего owner или платформу последнего usable admin откатывается DB constraint на COMMIT.
- GET `/api/v1/platform/companies` — безопасные company metadata, не tenant bypass.
- GET `/api/v1/platform/company-requests` — заявки.
- POST `/api/v1/platform/company-requests/{id}/approve|reject` — review; `comment` необязателен.
- GET/POST `/api/v1/platform/admins`, DELETE `/api/v1/platform/admins/{user_id}` — назначения, body создания только target user_id.
- PATCH `/api/v1/platform/identities/{identity_id}` — явная классификация principal, не linking/email matching.
- GET `/api/v1/platform/audit` — bounded pagination и safe metadata; записи не редактируются API.

Bootstrap и recovery не endpoints. Клиент не передаёт actor/created_by/reviewed_by. При ошибке deferred check COMMIT выполняется до HTTP success и даёт безопасный 409; все staged изменения и audit откатываются.

## Recovery

При утрате доступа к IdP-учётным записям всех администраторов используйте отдельную offline процедуру:

1. Ограничьте административный доступ и сделайте backup DB; зафиксируйте incident/change.
2. Подготовьте **существующую active human Identity** нового оператора, сверив issuer/subject/UUID. Не объединяйте email и не выдавайте новый JWT в Core.
3. Явно выполните:

```bash
python -m scripts.platform_admin recover --identity-id <verified-existing-uuid> --confirm-recovery --reason "Approved incident reference and recovery rationale"
```

Recovery допускает восстановление дополнительной grant при потерянном IdP-доступе прежних admins, не автоматическое удаление их grants. Причина 10–500 символов попадает в audit, поэтому не помещайте туда секреты/персональные данные. Дальнейшие cleanup/revokes — обычным MFA API. Если User suspended/повреждена DB, требуется отдельно проверенная процедура обслуживания/restore, не скрытая автоматическая реактивация.

Это явная привилегия DB/server operator, не способ обхода пользователем. DB owner технически может менять DDL, поэтому append-only trigger не заменяет отдельные runtime/migration DB roles и защищённое внешнее хранение audit. Сохраните резервные копии и ограничивайте доступ к контейнерному environment.
