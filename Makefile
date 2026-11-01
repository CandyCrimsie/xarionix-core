.PHONY: install-dev validate lint typecheck test security check compose-check dev-config dev-up dev-down dev-status dev-logs dev-test integration-test docker-build docker-scan
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
	.venv/bin/ruff check app scripts tests migrations
	.venv/bin/ruff format --check app scripts tests migrations
	bash -n install.sh
	sh -n deploy/postgres/10-app-user.sh
typecheck:
	.venv/bin/mypy app scripts migrations
test:
	.venv/bin/pytest -vv -m "not integration" --junitxml=reports/unit.xml --cov=app --cov=scripts --cov-report=term-missing --cov-report=xml:reports/coverage.xml --cov-fail-under=70
security:
	.venv/bin/bandit -q -r app scripts
	.venv/bin/pip-audit -r requirements.lock --strict
	.venv/bin/pip-audit -r requirements-dev.lock --strict
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
	XARIONIX_RUN_DOCKER_TESTS=1 .venv/bin/pytest -vv -m integration --junitxml=reports/integration.xml
docker-build:
	.venv/bin/python -m scripts.ci preflight
	.venv/bin/python -m scripts.ci build --image $(IMAGE)
	.venv/bin/python -m scripts.ci image-check --image $(IMAGE)
docker-scan:
	.venv/bin/python -m scripts.ci trivy --image $(IMAGE)
