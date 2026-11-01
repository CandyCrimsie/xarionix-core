.PHONY: install-dev lint typecheck test security check dev-config dev-up dev-down
install-dev:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.lock
	.venv/bin/python -m pip install --no-deps -e .
lint:
	.venv/bin/ruff check app scripts tests migrations
	.venv/bin/ruff format --check app scripts tests migrations
	bash -n install.sh
	sh -n deploy/postgres/10-app-user.sh
typecheck:
	.venv/bin/mypy app scripts migrations
test:
	.venv/bin/pytest -vv
security:
	.venv/bin/bandit -q -r app scripts
	.venv/bin/pip-audit -r requirements.lock --strict
check: lint typecheck test security
dev-config:
	.venv/bin/python -m scripts.setup dev --language ru
dev-up:
	docker compose --env-file .env.dev -f compose.dev.yaml up -d --build
dev-down:
	docker compose --env-file .env.dev -f compose.dev.yaml down
