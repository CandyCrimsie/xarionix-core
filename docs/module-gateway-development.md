# Разработка реального Standard Module API

Пример: `examples/modules/hello-business`. Stdlib HTTP server слушает только
loopback:8080, поддерживает live/ready, status-read/items-read/items-create,
разделяет in-memory dataset по проверенному context.company_id. В ответе actor,
company, correlation UUID, version и случайный process nonce — доказательство
исполнения handler, а не фиксированного ответа внутри Core. Это volatile demo,
не модуль production persistence.

```bash
umask 077
gateway_demo_dir=$(mktemp -d)
docker build -t hello-business:local examples/modules/hello-business
docker save --output "$gateway_demo_dir/image.tar" hello-business:local
.venv/bin/python -m scripts.runtime_artifact "$gateway_demo_dir/image.tar" "$gateway_demo_dir/distribution"
cp examples/modules/hello-business/module-api-v1.json "$gateway_demo_dir/distribution/payload/resources/"
.venv/bin/python -m scripts.xpkg keygen \
  --private-key "$gateway_demo_dir/publisher.key" --public-key "$gateway_demo_dir/publisher-public.txt"
.venv/bin/python -m scripts.xpkg pack \
  --source "$gateway_demo_dir/distribution/payload" \
  --manifest examples/modules/hello-business/manifest.json \
  --signing-key "$gateway_demo_dir/publisher.key" --publisher example-runtime --key-id demo-key \
  --output "$gateway_demo_dir/hello-business.xpkg"
```

Существующим `runtime_artifact` преобразуйте Docker-save в OCI inventory, скопируйте
module-api-v1.json в `payload/resources/`, затем подпишите полный payload штатным
xpkg pack. Manifest содержит собственные permission definitions; не меняйте namespace
без соответствующей смены permission keys/handler. Private publisher key хранится
локально с restrictive permissions и не включается в архив/образ.

Далее обычный workflow: доверенный publisher/key/namespace → import → install plan
и MFA approval → trusted installation executor → отдельный approved deployment
`profile=module-api-private-v1` → healthy ACK → enable plan/approval/executor → явное
назначение company roles. Новый gateway OIDC client настраивается администратором
Keycloak без password grant/self-registration; точные audience/principal приведены
в [transport](module-gateway-transport.md). External realm не меняется Core автоматически.

Agent запускается с отдельным client secret через защищённый service environment,
`python -m scripts.gateway_agent`; не передавайте Core/admin DB environment.
`STORAGE_ROOT` — уже существующий private journal Deployment Agent, не каталог пакета.

```bash
make gateway-test
XARIONIX_RUNTIME_ENGINE_SOCKET=/absolute/private/native-rootless.sock make gateway-integration-test
make check
```

E2E самостоятельно создаёт disposable PostgreSQL/Keycloak/Core, подписанный OCI/XPKG,
раздельные principals/companies/RBAC, настоящие Agents и module process. Engine для
runtime должен быть отдельным native rootless Linux daemon с реальными cgroup v2
limits; Docker Desktop/DinD для Core stack не считается доказательством enforcement.
Весь workflow реализован в `tests/integration/test_module_gateway_e2e.py`; секреты
передаются только ephemeral process environment и не попадают в reports.

Следующий возможный Sprint 6B: SDK, per-module isolated DB/secrets/migrations и devex.
Они не реализованы здесь. Angular/ERP, uploads/streaming, public module ports и
Autonomous synchronous RPC также не добавлены.

После установки/enable/явного company grant пример вызова (переменные передаются
защищённым окружением; JWT не включается в argv, URL или вывод):

```bash
.venv/bin/python - <<'PY'
import os
import httpx

with httpx.Client(verify=True, trust_env=False, follow_redirects=False, timeout=20) as client:
    result = client.post(
        os.environ['CORE_URL'] + '/api/v1/companies/' + os.environ['COMPANY_ID']
        + '/modules/hello-business/operations/items-create',
        headers={'Authorization': 'Bearer ' + os.environ['HUMAN_ACCESS_TOKEN']},
        json={'name': 'Пример записи'},
    )
    result.raise_for_status()
    print({'status': result.status_code, 'request_id': result.json()['request_id']})
PY
```
