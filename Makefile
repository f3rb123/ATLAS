.PHONY: test api worker
install:
	uv sync --frozen
test:
	uv run pytest -q
api:
	uv run uvicorn atlas.api:app --host 127.0.0.1 --port 8000
worker:
	uv run python -m atlas.worker research
