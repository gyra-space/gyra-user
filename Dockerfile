# syntax=docker/dockerfile:1.7
#
# gyra-user — 统一用户中心
# 多阶段构建：builder 用官方 uv 镜像按锁文件装依赖，runtime 只带 venv。

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# 先只拷贝依赖声明，最大化 Docker 层缓存命中
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev --no-editable --extra prod

# 再拷贝源码装项目本身（--no-editable：镜像里不留源码，只留 site-packages）
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --extra prod


FROM python:3.12-slim-bookworm AS runtime

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# PORT / WORKERS 由 docker-entrypoint.sh 读取，用来覆盖默认 CMD
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GYRA_USER_DATA_DIR=/data

WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
# 迁移脚本也要带上，entrypoint 起服前要跑 db upgrade
COPY --chown=app:app alembic.ini /app/alembic.ini
COPY --chown=app:app migrations /app/migrations
COPY --chown=app:app docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# 数据目录（SQLite 库、RS256 密钥）
RUN mkdir -p /data && chown -R app:app /data
VOLUME ["/data"]

USER app
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8100/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["gunicorn", "gyra_user.app:app", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8100", \
     "--workers", "2", \
     "--access-logfile", "-", "--error-logfile", "-"]
