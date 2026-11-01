# Nginx

Production-конфигурация генерируется stdlib-рендерером `scripts.setup.nginx()` после проверки URL и сертификатов. В external в ней отсутствует upstream Keycloak. Не храните private keys в этом каталоге.

Результат: `deploy/generated/nginx.conf`; закрытые TLS files: `deploy/generated/tls/`. Предварительная проверка и safe reload реализованы установщиком / `python -m scripts.setup reload`. Детали — `docs/installation.md`.
