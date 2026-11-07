# Sprint 6B — изменённые файлы

Снимок рабочего дерева 7 ноября 2026. Commit/push не выполнялись.
`M` — изменён, `D` — перенесён из старого дерева Console, `??` — новый файл.

```text
 M .dockerignore
 M .gitignore
 M .gitlab-ci.yml
 M Dockerfile
 M Makefile
 M README.md
 M app/api/v1/deployments.py
 M app/api/v1/installations.py
 M app/api/v1/module_gateway.py
 M app/api/v1/packages.py
 M app/core/database.py
 M app/domains/deployments/artifacts.py
 M app/domains/deployments/contracts.py
 M app/domains/deployments/service.py
 M app/domains/installations/service.py
 M app/domains/module_gateway/authorization.py
 M app/domains/packages/archive.py
 M app/domains/packages/service.py
 M app/domains/registry.py
 M deploy/postgres/module-executor.sql
 M docs/ci-cd.md
 M pyproject.toml
 M scripts/ci.py
 M scripts/deployment_agent/__main__.py
 M scripts/deployment_agent/engine.py
 M scripts/docker_job.py
 M scripts/runtime_images.py
 M tests/integration/test_managed_stack.py
 M tests/integration/test_module_db_privileges.py
 M tests/test_deployments.py
?? app/domains/module_sdk/__init__.py
?? app/domains/module_sdk/contracts.py
?? app/domains/module_sdk/model.py
?? app/domains/module_sdk/service.py
?? docs/module-backup-restore.md
?? docs/module-configuration.md
?? docs/module-migrations.md
?? docs/module-sdk-development.md
?? docs/module-sdk.md
?? docs/module-storage-security.md
?? docs/module-storage.md
?? docs/sprint-6b-changes.md
?? docs/sprint-6b-validation.md
?? examples/modules/hello-business-stateful/Dockerfile
?? examples/modules/hello-business-stateful/README.md
?? examples/modules/hello-business-stateful/hello.py
?? examples/modules/hello-business-stateful/manifest.json
?? examples/modules/hello-business-stateful/module-api-v1.json
?? examples/modules/hello-business-stateful/module-sdk-v1.json
?? migrations/versions/0013_module_storage.py
?? scripts/deployment_agent/storage.py
?? scripts/sdk_wheel_smoke.py
?? sdk/python/pyproject.toml
?? sdk/python/src/xarionix_sdk/__init__.py
?? sdk/python/src/xarionix_sdk/__main__.py
?? sdk/python/src/xarionix_sdk/application.py
?? sdk/python/src/xarionix_sdk/cli.py
?? sdk/python/src/xarionix_sdk/configuration.py
?? sdk/python/src/xarionix_sdk/py.typed
?? sdk/python/src/xarionix_sdk/server.py
?? sdk/python/src/xarionix_sdk/storage.py
?? sdk/python/src/xarionix_sdk/validation.py
?? tests/integration/test_stateful_runtime_e2e.py
?? tests/stateful_helpers.py
?? tests/test_module_configuration.py
?? tests/test_module_sdk.py
?? tests/test_module_storage_plans.py
?? tests/test_module_storage_sdk.py
?? tests/test_stateful_storage_agent.py
?? tests/test_storage_metadata_access.py
```
