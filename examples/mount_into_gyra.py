"""把 gyra-user 挂进 Gyra 的最小改动示例。

文件: packages/gyra-app/src/gyra_app/openapi/api_v1/api_v1.py

    - from .auth_api import router as auth_router
    + from gyra_user import (
    +     create_account_router, create_admin_router,
    +     create_auth_router, create_oidc_router,
    + )
    + from gyra_user.config import load_settings
    +
    + _user_settings = load_settings(os.environ.get("GYRA_USER_CONFIG"))
    + auth_router = create_auth_router(_user_settings)
    + admin_router = create_admin_router(_user_settings)

    router.include_router(auth_router, prefix="/v1", tags=["Auth"])
    + router.include_router(admin_router, prefix="/v1", tags=["Admin"])
    + router.include_router(create_account_router(_user_settings),
    +                       prefix="/v1", tags=["Account"])
    + # OIDC（单点登录）端点；prefix 必须与挂载路径一致，否则 discovery 里的
    + # issuer 对不上，客户端校验 id_token 会失败。
    + app.include_router(create_oidc_router(_user_settings, prefix="/api/v1"))

前提（在 gyra-serve 的 pyproject 里加依赖）::

    dependencies = [..., "gyra-user @ file:///Users/yanghongjun/code/gyra-user"]

下面这段是可直接运行的最小复现：起一个 FastAPI，挂上 gyra-user 的路由，
验证 /api/v1/auth/*、/api/v1/admin/*、/api/v1/account/* 与 OIDC 端点都在。
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from gyra_user import (
    create_account_router,
    create_admin_router,
    create_auth_router,
    create_oidc_router,
)
from gyra_user.config import load_settings
from gyra_user.db import init_engine
from gyra_user.deps import get_current_active_user
from gyra_user.models import User


def build_app() -> FastAPI:
    # 1. 读配置（configs/auth.toml + GYRA_USER_* 环境变量）
    settings = load_settings(os.environ.get("GYRA_USER_CONFIG"))

    # 2. 建库建表（Gyra 已用 sqlite，这里直接复用同一份配置）
    init_engine(settings.resolved_database_url())

    app = FastAPI(title="Gyra + gyra-user")

    # 3. 一行挂载 —— 替换掉原来的 auth_api / users_api
    app.include_router(create_auth_router(settings), prefix="/api/v1")
    app.include_router(create_admin_router(settings), prefix="/api/v1")
    app.include_router(create_account_router(settings), prefix="/api/v1")
    # OIDC 端点；prefix 要和挂载路径完全一致
    app.include_router(create_oidc_router(settings, prefix="/api/v1"))

    # 4. 其它业务接口直接复用当前用户依赖
    @app.get("/api/v1/protected")
    async def protected(user: User = Depends(get_current_active_user)):
        return {"hello": user.name, "role": user.role}

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(build_app(), host="127.0.0.1", port=8101)
