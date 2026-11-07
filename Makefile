.PHONY: install-dev validate lint typecheck test security check compose-check dev-config dev-up dev-down dev-status dev-logs dev-test integration-test locking-benchmark docker-build docker-scan
.PHONY: package-benchmark
.PHONY: deployment-agent-build runtime-example-build runtime-test runtime-integration-test runtime-images-check
.PHONY: gateway-agent-build gateway-test gateway-integration-test sdk-test stateful-integration-test
PYTHON ?= python3
IMAGE ?= xarionix-core:local
DEV_COMPOSE = docker compose --env-file .env.dev -f compose.dev.yaml
install-dev:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.lock
	.venv/bin/python -m pip install --no-deps -e .
validate:
	.venv/bin/python -m scripts.validate
lint:
	.venv/bin/ruff check app scripts tests migrations sdk/python/src
	.venv/bin/ruff format --check app scripts tests migrations sdk/python/src
	bash -n install.sh
	sh -n deploy/postgres/10-app-user.sh
typecheck:
	.venv/bin/mypy app scripts migrations sdk/python/src
test:
	.venv/bin/python -m pytest -vv -m "not integration" --junitxml=reports/unit.xml --cov=app --cov=scripts --cov=xarionix_sdk --cov-report=term-missing --cov-report=xml:reports/coverage.xml --cov-fail-under=70
security:
	.venv/bin/bandit -q -r app scripts sdk/python/src
	.venv/bin/pip-audit -r requirements.lock --strict --timeout 60 --progress-spinner off
	.venv/bin/pip-audit -r requirements-dev.lock --strict --timeout 60 --progress-spinner off
check: validate lint typecheck test security compose-check
compose-check:
	.venv/bin/python -m scripts.compose_check
dev-config:
	.venv/bin/python -m scripts.setup dev --language ru
dev-up: dev-config
	$(DEV_COMPOSE) build core
	$(DEV_COMPOSE) up -d --no-build --wait --wait-timeout 420
dev-down:
	$(DEV_COMPOSE) down
dev-status:
	$(DEV_COMPOSE) ps --all
dev-logs:
	$(DEV_COMPOSE) logs --tail 100
dev-test:
	.venv/bin/python -m scripts.ci dev-check
integration-test:
	.venv/bin/python -m scripts.ci preflight
	XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/python -m pytest -vv -m integration --junitxml=reports/integration.xml
locking-benchmark:
	XARIONIX_RUN_DOCKER_TESTS=1 XARIONIX_RUN_LOCK_BENCHMARKS=1 .venv/bin/pytest tests/integration/test_managed_stack.py -vv -k preserves_legacy_identity
docker-build:
	.venv/bin/python -m scripts.ci preflight
	.venv/bin/python -m scripts.ci build --image $(IMAGE)
	.venv/bin/python -m scripts.ci image-check --image $(IMAGE)
docker-scan:
	.venv/bin/python -m scripts.ci trivy --image $(IMAGE)
package-benchmark:
	.venv/bin/python -m scripts.xpkg_benchmark
deployment-agent-build:
	docker build --target deployment-agent --tag xarionix-deployment-agent:local .
runtime-example-build:
	docker build --tag xarionix-hello:local examples/modules/hello-runtime
runtime-test:
	.venv/bin/python -m pytest -vv tests/test_runtime_artifacts.py tests/test_deployment_agent.py tests/test_deployments.py
runtime-integration-test:
	XARIONIX_RUN_DOCKER_TESTS=1 XARIONIX_RUN_RUNTIME_TESTS=1 .venv/bin/python -m pytest tests/integration/test_runtime_e2e.py -vv -s --junitxml=reports/runtime-e2e.xml
runtime-images-check:
	.venv/bin/python -m scripts.runtime_images
gateway-agent-build:
	docker build --target gateway-agent --tag xarionix-gateway-agent:local .
gateway-test:
	.venv/bin/python -m pytest tests/test_module_gateway*.py -vv
gateway-integration-test:
	@test -n "$(XARIONIX_RUNTIME_ENGINE_SOCKET)" || { echo "Set the dedicated native rootless runtime socket"; exit 1; }
	XARIONIX_RUN_DOCKER_TESTS=1 XARIONIX_RUN_GATEWAY_TESTS=1 .venv/bin/python -m pytest tests/integration/test_module_gateway_e2e.py -vv --junitxml=reports/gateway-e2e.xml
sdk-test:
	.venv/bin/python -m pytest tests/test_module_sdk.py tests/test_module_configuration.py tests/test_module_storage_sdk.py tests/test_module_storage_plans.py tests/test_stateful_storage_agent.py -vv
stateful-integration-test:
	@test -n "$(XARIONIX_RUNTIME_ENGINE_SOCKET)" || { echo "Set the dedicated native rootless runtime socket"; exit 1; }
	XARIONIX_RUN_DOCKER_TESTS=1 XARIONIX_RUN_STATEFUL_TESTS=1 .venv/bin/python -m pytest tests/integration/test_stateful_runtime_e2e.py -vv --junitxml=reports/stateful-e2e.xml
