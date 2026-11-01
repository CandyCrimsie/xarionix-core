# Keycloak provisioning

Рендерер `scripts.setup.realm()` создаёт public initial import без паролей и client secrets. Managed Compose импортирует его только при отсутствии realm. Повторный startup не является обновлением существующего realm; используйте Console для осознанных дальнейших изменений.

Production — `start --import-realm`, отдельная PostgreSQL DB/SQL role, публичный hostname за Nginx. Dev realm генерируется отдельно и допускает loopback HTTP только через явный `compose.dev.yaml`. Bootstrap secret находится в закрытом `.env`, не в JSON.

Admin API для external realm не вызывается. Полный контракт — `docs/identity.md`.
