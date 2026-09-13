# gyra-user — 统一用户中心（uv 工程）
#
# 所有命令都走 uv，不要再直接用 pip 装依赖。

UV      ?= uv
RUN      = $(UV) run --no-sync
TMP     := $(CURDIR)/.tmp
PORT    ?= 8100
WORKERS ?= 1

.PHONY: help sync lock init-db db-upgrade migrate test lint fmt run start clean

help:
	@echo "sync        安装/同步依赖（含 dev 组）"
	@echo "init-db     建库 + 升级到最新 migration（可重复执行）"
	@echo "db-upgrade  只跑迁移"
	@echo "migrate     生成新迁移：make migrate m='说明'"
	@echo "test/lint/fmt"
	@echo "run         开发模式，单进程热重载 :$(PORT)"
	@echo "start       生产模式，gunicorn + uvicorn worker"

sync:
	$(UV) sync

lock:
	$(UV) lock

init-db:
	$(RUN) gyra-user init-db

db-upgrade:
	$(RUN) gyra-user db upgrade

db-current:
	$(RUN) gyra-user db current

migrate:
	@test -n "$(m)" || (echo "用法: make migrate m='添加 xxx 字段'" && exit 1)
	$(RUN) alembic revision --autogenerate -m "$(m)"

test:
	TMPDIR=$(TMP) $(RUN) pytest --basetemp=$(TMP)/pytest

lint:
	$(RUN) ruff check src tests examples migrations

fmt:
	$(RUN) ruff check src tests examples migrations --fix
	$(RUN) ruff format src tests examples migrations

run:
	$(RUN) uvicorn gyra_user.app:app --reload --port $(PORT)

# 生产启动：需先 uv sync --extra prod
start:
	$(RUN) gunicorn gyra_user.app:app \
		-k uvicorn.workers.UvicornWorker \
		--bind 0.0.0.0:$(PORT) \
		--workers $(WORKERS) \
		--access-logfile - --error-logfile -

clean:
	rm -rf .tmp .pytest_cache .ruff_cache dist build
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
