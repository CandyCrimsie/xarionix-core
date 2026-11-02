# Keycloak и идентичность

Sprint 4A добавляет отдельный [machine authentication path](service-authentication.md): dedicated audience/purpose, точный registry binding issuer/sub/azp и capabilities без User/Membership/JIT. Описанный ниже профиль первого входа относится к legacy human-audience пути. Machine JWT/purpose запрещён на нём до JIT. Production service clients настраиваются оператором отдельно; существующий managed browser realm не меняется автоматически.

## Managed

Keycloak 26.8.1 запускается в production server mode (`start --import-realm`), не `start-dev`. Установщик создаёт `deploy/generated/xarionix-realm.json` без секретов. При первой установке появляется realm `xarionix`:

- самостоятельная регистрация выключена;
- password grant и implicit flow выключены;
- включена brute-force protection;
- access token lifespan 5 минут;
- `xarionix-core` — bearer-only resource client;
- `xarionix-browser` — public Authorization Code client с обязательным PKCE S256, точными redirect URI и origins;
- audience mapper добавляет `xarionix-core` в access token, но не в ID token;
- обычные scopes `profile` и `email` используются клиентом; email не связывает учётные записи в Core.

Браузерный клиент подготовлен для будущего UI, сам callback пока не реализован. Не добавляйте wildcard redirect URI. Отсутствие client secret у public PKCE/resource clients — намеренная модель OAuth, не пропущенная генерация секрета.

Согласно [официальному поведению realm import](https://www.keycloak.org/server/importExport), существующий realm при старте пропускается. Повторный запуск не сбрасывает пользователей/политики, но **также не применяет новые настройки JSON**. Правки существующего realm выполняйте через Console или отдельный согласованный deployment change, не принудительным overwrite. Bootstrap admin создаётся только при первоначальной master DB; [bootstrap recovery](https://www.keycloak.org/server/bootstrap-admin-recovery) — отдельная административная процедура.

`KC_HOSTNAME` равен публичному HTTPS URL. Nginx перезаписывает xforwarded headers; [настройки hostname](https://www.keycloak.org/server/hostname) и [reverse proxy](https://www.keycloak.org/server/reverseproxy) согласованы. Не меняйте issuer на Docker hostname ради доступности сети.

## External: что настроить в существующем Keycloak

1. Создайте/выберите realm с доверенным HTTPS issuer, например `https://sso.organization.ru/realms/company`.
2. Создайте OIDC resource client `xarionix-core` (bearer-only / resource server по возможностям вашей версии).
3. В клиенте, который получает пользовательский токен, используйте Authorization Code + PKCE S256, точные callback и web origins; отключите implicit/password grants.
4. Добавьте Audience mapper: Included Client Audience `xarionix-core`, Add to access token on, Add to ID token off. Проверьте, что нужный scope включён в выдаваемый access token.
5. Разрешите Core читать публичные discovery/JWKS по HTTPS, подпись RS256, корректные часы сервера. Указанный issuer должен точно совпадать с claim `iss`, включая realm/path/case.
6. В конфигурации выберите `XARIONIX_KEYCLOAK_MODE=external`, точный `XARIONIX_OIDC_ISSUER`, `XARIONIX_OIDC_AUDIENCE=xarionix-core`, пустой `XARIONIX_OIDC_BACKCHANNEL`. Внешний client secret/пароль администратора Core не нужен.

External Compose не содержит Keycloak или его DB. Установщик и Core не вызывают внешний Admin API и не меняют realm. Политику MFA, регистрации и federation контролирует организация.

## Первый вход и проверка API

После первого валидного `GET /api/v1/me` создаются Identity и глобальный профиль User **без human-допуска и бизнес-полномочий**. Старые поля ответа сохранены; добавлены:

```json
{"id":"<identity-uuid>","issuer":"https://sso.organization.ru/realms/company","subject":"<verified-sub>","user_id":"<user-uuid>","principal_type":"unclassified","display_name":null,"status":"active","created_at":"<timestamp>","updated_at":"<timestamp>"}
```

Следующий запрос с теми же issuer/sub вернёт тот же UUID. Другой issuer или subject — другая идентичность, даже при одинаковом email. Смена issuer — осознанная миграция identity links, а не автоматическое объединение.

Получите **access token**, не ID token, через доверенный PKCE-клиент. Для ручной проверки используйте клиент, который умеет хранить секретные значения вне history/URL; не вставляйте JWT в shell-команду. Автоматические integration-тесты получают тестовый service-account token в отдельном disposable realm; production-клиенты такого grant не имеют.

Нет Core login/password/refresh-token endpoint или silent administrator provisioning. Realm roles не являются permissions. Principal type legacy Identity хранится в DB, не выводится из недоказанных sub/azp/email/claim. Оператор сверяет Identity UUID с IdP и явно допускает human; старые service/unclassified Identity с human audience могут читать свой `/me`, но не выполнять human mutations. Новые machine identities используют отдельный registry и `/module-agent/*`, без обычного профиля. Machine business API отложен. Один User может иметь несколько Identity, но автоматического/public linking нет.

Для допуска и bootstrap используйте [platform-administration.md](platform-administration.md). Platform HTTP administration дополнительно требует exact `acr` из конфигурационного allowlist и свежий `auth_time` в **проверенном access token**. Пустой allowlist по умолчанию запрещает административные HTTP-операции. Не подставляйте фиктивный `acr` mapper вместо реальной MFA: см. [Keycloak authentication flows](https://www.keycloak.org/docs/latest/server_admin/index.html#_authentication-flows) и [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html). Production realm не изменяется автоматически ради MFA; повторный import существующего realm по-прежнему не применяется.

## Google Identity Provider

Настраивается **в Keycloak**, не в Core:

1. В Google Cloud создайте OAuth Web application и согласуйте consent screen/политику организации.
2. В Keycloak → Identity Providers → Google создайте alias, например `google`.
3. Redirect URI возьмите из этой страницы Keycloak и зарегистрируйте в Google. Обычно это `https://auth.example.org/realms/xarionix/broker/google/endpoint`, но используйте фактический URI, а не предположение.
4. Client ID/secret Google введите через защищённую Console/secret process, не в Core `.env` или Git.
5. Настройте First Broker Login flow с подтверждённым связыванием существующих аккаунтов и политикой доверия email. Не включайте безусловное email auto-linking.
6. Проверьте вход обычным пользователем, MFA и account linking. Core по-прежнему доверяет только Keycloak issuer/sub, не Google access token.

Фактическая настройка Google требует внешних credentials и не выполняется установщиком автоматически.
