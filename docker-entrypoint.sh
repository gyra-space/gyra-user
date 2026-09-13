#!/bin/sh
# 容器入口：先跑迁移，再交给 CMD 起的 ASGI 服务器。
#
# 迁移失败直接退出 —— 带着旧表结构启动比不启动更危险。
set -eu

: "${GYRA_USER_DATA_DIR:=/data}"
export GYRA_USER_DATA_DIR

echo "[entrypoint] applying database migrations..."
gyra-user db upgrade

# 允许用 PORT / WORKERS 覆盖 CMD 里写死的端口与进程数
if [ -n "${PORT:-}" ] || [ -n "${WORKERS:-}" ]; then
    set -- gunicorn gyra_user.app:app \
        -k uvicorn.workers.UvicornWorker \
        --bind "0.0.0.0:${PORT:-8100}" \
        --workers "${WORKERS:-2}" \
        --access-logfile - --error-logfile -
fi

echo "[entrypoint] starting: $*"
exec "$@"
