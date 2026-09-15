# gyra-user — 统一用户中心 / OIDC Provider

独立的 OAuth2 / OIDC 认证服务：SQLite 存用户，支持 **GitHub**、**微信开放平台扫码登录**、
本地账号密码，自带**统一登录页 / 注册 / 个人中心 / 管理后台**，
并且**自身就是一个标准 OIDC Provider —— 其它应用接进来即可共享登录态（单点登录）**。

工程形态：**标准 uv 项目**（`uv.lock` + `.python-version`，`.venv` 由 uv 托管），
可独立部署（Docker / systemd），也可以**一行挂载进 Gyra 替换现有登录模块**。

设计上刻意保持了 Gyra 现有 `/api/v1/auth/*` 的请求/响应契约，
**Next.js 前端 `web/src/services/auth.ts` 不用改一行**。

---

## 30 秒跑起来

```bash
uv sync                                                       # 装依赖（含 dev）
cp .env.example .env                                          # 填 GitHub / 微信凭证
uv run gyra-user init-db --admin-password admin123            # 建库 + 迁移 + 建首个管理员
uv run uvicorn gyra_user.app:app --reload --port 8100         # 或 make run
```

| 页面 | 地址 |
|---|---|
| 统一登录页（含注册入口） | <http://127.0.0.1:8100/login> |
| 个人中心（改资料/改密码/绑第三方/踢设备/授权应用） | <http://127.0.0.1:8100/account> |
| 管理后台（用户 + 接入应用） | <http://127.0.0.1:8100/admin> |
| 接口文档 | <http://127.0.0.1:8100/docs> |
| OIDC 发现文档 | <http://127.0.0.1:8100/.well-known/openid-configuration> |

没配任何 OAuth 凭证时只有「账号密码」可用，`/api/v1/auth/oauth/status` 会如实反映。

---

## 能力一览

| 能力 | 说明 |
|---|---|
| **单点登录（OIDC Provider）** | 标准授权码流程 + PKCE + `id_token` + 发现文档 + JWKS，任何支持 OIDC 的应用零改造接入 |
| **接入应用管理** | `oauth_clients` 表 + 管理 API + 后台页面注册，回调白名单、scope 白名单、密钥轮换 |
| **授权确认页** | 首次授权展示应用请求的权限；内部应用可 `skip_consent` 直接静默通过 |
| 统一登录页 / 注册页 | `/login` 一个页面搞定第三方 + 账号密码 + 注册（邮箱/昵称/确认密码/条款勾选） |
| 个人中心 | `/account` 改资料、改密码、绑定解绑第三方、查看并踢掉设备、撤销应用授权 |
| 标准 OAuth2 授权码流程 | `state` 用短时效签名 token（无状态，多副本可用），OIDC provider 自动启用 PKCE S256 |
| GitHub 登录 | 自动取 `/user` + `/user/emails` 的主邮箱 |
| 微信扫码登录 | 开放平台「网站应用」`qrconnect`，支持整页跳转和 **iframe 内嵌**两种形态 |
| 微信公众号网页授权 | `wechat_mp`（`snsapi_userinfo`），与网站应用通过 **unionid 打通为同一账号** |
| 任意 OIDC / 自定义 | 填 `authorization_url` / `token_url` / `userinfo_url` + 字段点路径即可 |
| JWT | Access Token（默认 30min）+ Refresh Token（默认 7 天），HS256 / RS256 |
| Refresh 轮换 | 每次刷新轮换旧 token；**重放旧 token 判定为盗用，整族吊销** |
| 账号合并 | 同一 unionid、或同一已验证邮箱，自动挂到已有账号而不是新建 |
| 本地账号 | bcrypt 哈希；兼容 Gyra 前端的 base64 密码；支持「注册需管理员审核」 |
| 用户管理 | 列表/搜索/改角色/启停/重置密码/踢下线/登录审计 |
| 灰度迁移 | 能验签 Gyra 现有 HMAC session token，新旧 token 可并行一段时间 |

---

## 单点登录（把其它应用接进来）

gyra-user 既是**登录服务的消费者**（GitHub/微信），也是**提供方**（OIDC IdP）。
接入方只需要知道一个发现地址：

```
GET /.well-known/openid-configuration
```

### 1. 注册应用

方式一 · 后台页面：<http://127.0.0.1:8100/admin> → 「接入应用（SSO）」。
回调地址必须与实际**完全一致**（含协议、端口、路径），密钥**只在创建时显示一次**。

方式二 · 命令行：

```bash
python -m gyra_user.cli create-client "Gyra Web" \
  --redirect-uri http://localhost:3000/api/auth/callback \
  --skip-consent            # 内部应用：跳过授权确认页，实现真正的静默单点
python -m gyra_user.cli list-clients
```

`--public` 表示 SPA / 移动端（不存密钥，强制 PKCE）；默认机密客户端。

### 2. 接入方三行跳转

```
GET /oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=xxx
    &scope=openid profile email&state=xxx&code_challenge=xxx&code_challenge_method=S256
  → 未登录：302 到 /login?next=<原始 authorize URL>（登录完自动回到该 URL）
  → 需要授权：渲染确认页，用户点「允许」后 POST 回同一个地址
  → 302 回应用：redirect_uri?code=xxx&state=xxx

POST /oauth2/token   (grant_type=authorization_code | refresh_token)
GET  /oauth2/userinfo   Bearer access_token
POST /oauth2/introspect /oauth2/revoke
GET  /oauth2/logout     RP 发起的全局登出
```

可运行的最小接入方示例：[`examples/sso_client.py`](examples/sso_client.py)

```bash
GYRA_USER_ISSUER=http://127.0.0.1:8100 \
DEMO_CLIENT_ID=xxx DEMO_CLIENT_SECRET=yyy \
DEMO_USERNAME=admin DEMO_PASSWORD=admin123 \
python examples/sso_client.py --selftest     # 命令行跑完整流程
# 或 python examples/sso_client.py           # 起一个 8200 端口的演示应用
```

### 3. 安全设计

| 措施 | 说明 |
|---|---|
| 回调白名单 | 未注册的 `redirect_uri` 直接 400，**不会**带着错误码跳到攻击者 URL |
| scope 白名单 | 应用只能请求注册时声明过的 scope；`prompt=consent` 可强制重新确认 |
| PKCE | 公开客户端（SPA / 移动端）强制要求 `code_challenge`，不支持 `plain` 之外的绕过 |
| 授权码一次性 | 用过即失效；**跨 client 重放会立刻作废该用户在该应用下的全部授权码** |
| Refresh 绑定 client | A 应用拿到的 refresh token 拿到 B 应用用 → 判定盗用，整族吊销 |
| `id_token` | `aud` = client_id，`nonce` 防重放；RS256 时打 `kid`，应用用 JWKS 离线验签 |
| 全局登出 | `/oauth2/logout` 吊销会话 + 清 SSO cookie，再跳回应用 |

### 4. 生产建议：切 RS256

HS256 下所有应用共享同一个密钥，且 `/.well-known/jwks.json` 为空（不能公开对称密钥）。
生成密钥对并把算法切过去：

```bash
python -m gyra_user.cli gen-keys --out-dir data
```

```toml
jwt_algorithm = "RS256"
jwt_private_key_file = "data/jwt_private.pem"
jwt_public_key_file  = "data/jwt_public.pem"
```

之后应用可以拿 JWKS 离线验签，不用每次都来 `/introspect`。

### 5. 跨子域共享登录态

同域下的多个子应用（`a.example.com` / `b.example.com`）把 cookie 提到父域即可：

```toml
cookie_domain = ".example.com"
cookie_samesite = "lax"     # 跨站跳转场景需要 "none"，且必须 https
```

`cookie_domain` 留空时会自动按请求的父域名推导，`localhost` 和纯 IP 不设置（浏览器会拒绝）。

---

## 目录结构

```
src/gyra_user/
├── config.py      四层配置（默认值 < auth.toml < auth.local.toml < GYRA_USER_* 环境变量）
├── db.py          SQLAlchemy engine/session，SQLite 开 WAL + 外键
├── models.py      User / OAuthAccount / RefreshToken / LoginEvent
│                  OAuthClient / AuthorizationCode / UserConsent
├── security.py    bcrypt、JWT 签发验签、PKCE、client 密钥、旧 Gyra token 兼容
├── providers/     base(抽象) · github · wechat · generic(OIDC) · registry
├── service.py     账号创建/合并、token 签发与轮换、审计
├── oidc_service.py  接入应用注册表、授权码、consent（OIDC 业务层）
├── oidc.py        OIDC Provider 端点：发现 / authorize / token / userinfo / 登出
├── deps.py        FastAPI 依赖：current_user / require_admin
├── router.py      /auth/*    —— 与 Gyra 契约一致
├── admin.py       /admin/*   —— 用户管理 + 接入应用管理
├── account.py     /account/* —— 自助服务（资料/密码/会话/授权应用）
├── app.py         create_app()，独立服务入口
├── cli.py         init-db / create-user / create-client / gen-keys / ...
└── static/        login.html · account.html · admin.html
```

数据表：`users`、`oauth_accounts`（一人可绑多个第三方身份）、
`refresh_tokens`（可吊销，存的是 hash，带 client_id 归属）、`login_events`（审计）、
`oauth_clients`（接入应用）、`oauth_authorization_codes`（一次性授权码）、
`oauth_consents`（记录已授权，避免重复弹确认页）。

---

## 工程结构

```
.
├── pyproject.toml      uv 工程（依赖、ruff、pytest 配置都在这）
├── uv.lock             锁定 48 个包，CI/生产用 uv sync --frozen
├── .python-version     3.12
├── alembic.ini
├── migrations/         Alembic 版本化迁移（SQLite 用 batch 模式）
├── Dockerfile          多阶段构建，非 root，带 HEALTHCHECK
├── docker-compose.yml
├── deploy/             systemd unit + nginx 反代片段
├── configs/auth.toml   非敏感配置
└── src/gyra_user/      源码（见下）
```

`src/gyra_user/`：

```
├── config.py        四层配置（默认值 < auth.toml < auth.local.toml < GYRA_USER_* 环境变量）
├── db.py            SQLAlchemy engine/session，SQLite 开 WAL + 外键 + busy_timeout
├── migrate.py       补齐历史库漂移 + 调 Alembic
├── models.py        User / OAuthAccount / RefreshToken / LoginEvent
│                    OAuthClient / AuthorizationCode / UserConsent
├── security.py      bcrypt、JWT 签发验签、PKCE、client 密钥、旧 Gyra token 兼容
├── service.py       账号创建/合并、token 签发与轮换、审计
├── oidc_service.py  接入应用注册表、授权码、consent（OIDC 业务层）
├── oidc.py          OIDC Provider 端点：发现 / authorize / token / userinfo / 登出
├── deps.py          FastAPI 依赖：current_user / require_admin
├── router.py        /auth/*    —— 与 Gyra 契约一致
├── admin.py         /admin/*   —— 用户管理 + 接入应用管理
├── account.py       /account/* —— 自助服务（资料/密码/会话/授权应用）
├── app.py           create_app()，独立服务入口（含生产配置自检）
├── cli.py           init-db / db upgrade / create-user / create-client / gen-keys
└── static/          login.html · account.html · admin.html
```

数据表：`users`、`oauth_accounts`（一人可绑多个第三方身份）、
`refresh_tokens`（可吊销，存的是 hash，带 client_id 归属）、`login_events`（审计）、
`oauth_clients`（接入应用）、`oauth_authorization_codes`（一次性授权码）、
`oauth_consents`（记录已授权，避免重复弹确认页）。

---

## 接口

挂载前缀 `/api/v1`（与 Gyra 一致）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/auth/oauth/status` | 可用登录方式，前端登录页据此渲染 |
| GET | `/auth/oauth/login?provider=github` | 302 到第三方授权页；`display=qr` 返回微信扫码页 |
| GET | `/auth/oauth/callback` | 回调：换 token → 建号 → 302 到 `/auth/callback/#token=...` 并种 cookie |
| GET | `/auth/oauth/qr/{provider}` | 微信内嵌扫码页（iframe 里跑，扫完导航顶层窗口） |
| GET | `/auth/me` | 当前用户（兼容 Gyra 的 `user_channel/user_no/nick_name/role` 结构） |
| POST | `/auth/local/login` | 账号密码登录，密码明文或 base64 都收 |
| POST | `/auth/local/register` | 注册（可开启需审核） |
| POST | `/auth/refresh` | 轮换 refresh token |
| POST | `/auth/token` | RFC 6749 token 端点，支持 `password` / `refresh_token` grant |
| POST | `/auth/introspect` | RFC 7662，其他服务可无共享 DB 校验 token |
| POST | `/auth/logout` | 吊销当前 refresh token + 清 cookie |
| GET | `/auth/bindings` | 我绑定的第三方身份 |
| DELETE | `/auth/bindings/{provider}` | 解绑（只剩一个登录方式时拒绝） |
| GET | `/admin/users` | 用户列表（关键字/角色/状态筛选 + 分页） |
| PATCH | `/admin/users/{id}` | 改资料/角色/启停（停用会顺带踢下线） |
| POST | `/admin/users/{id}/reset-password` | 重置密码 |
| POST | `/admin/users/{id}/revoke-sessions` | 全部下线 |
| GET | `/admin/login-events` | 登录审计 |
| GET/POST | `/admin/clients` | 接入应用列表 / 注册（**密钥仅此一次返回**） |
| PATCH/DELETE | `/admin/clients/{id}` | 改配置 / 删除（连带清掉所有授权） |
| POST | `/admin/clients/{id}/rotate-secret` | 轮换密钥，旧密钥立即失效 |

### 个人中心（需登录）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/PATCH | `/account/profile` | 查看 / 修改昵称、邮箱、头像 |
| POST | `/account/password` | 改密码（校验旧密码） |
| GET | `/account/sessions` | 我的登录会话（含来源应用、IP、UA） |
| DELETE | `/account/sessions/{jti}` | 踢掉指定设备 |
| GET | `/account/apps` | 我授权过的应用 |
| DELETE | `/account/apps/{client_id}` | 撤销授权 + 吊销该应用的会话 |
| GET | `/account/login-events` | 我的登录记录 |

### OIDC Provider（无 `/api/v1` 前缀，位于 issuer 根路径）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | 发现文档 |
| GET | `/.well-known/jwks.json` | 公钥集（RS256） |
| GET/POST | `/oauth2/authorize` | 授权端点（GET 发起，POST 提交 consent 决定） |
| POST | `/oauth2/token` | 令牌端点（`authorization_code` / `refresh_token`） |
| GET/POST | `/oauth2/userinfo` | 用户信息 |
| POST | `/oauth2/introspect` | RFC 7662 令牌自省 |
| POST | `/oauth2/revoke` | RFC 7009 令牌吊销 |
| GET/POST | `/oauth2/logout` | RP 发起的全局登出 |

---

## 接入 GitHub

1. <https://github.com/settings/developers> → New OAuth App
2. **Authorization callback URL** 填 `{public_base_url}/api/v1/auth/oauth/callback`，
   本地是 `http://localhost:8100/api/v1/auth/oauth/callback`，
   线上是 `https://user.gyra.chat/api/v1/auth/oauth/callback`（必须和实际访问地址完全一致）
3. 填到 `.env`：

```bash
GYRA_USER_GITHUB_CLIENT_ID=Iv1.xxxxxxxx
GYRA_USER_GITHUB_CLIENT_SECRET=xxxxxxxx
```

## 接入微信（开放平台网站应用）

1. <https://open.weixin.qq.com> → 管理中心 → 网站应用（**需企业认证**，个人主体开不了）
2. **授权回调域** 填域名（**不要带 `http://`、不要带路径**，这是最常见的踩坑点）：
   本地 `localhost`，线上 `user.gyra.chat`
3. 填到 `.env`：

```bash
GYRA_USER_WECHAT_APP_ID=wxXXXXXXXX
GYRA_USER_WECHAT_APP_SECRET=xxxxxxxx
```

两种用法：

```html
<!-- 内嵌二维码（推荐，不打断当前页） -->
<iframe src="/api/v1/auth/oauth/qr/wechat" width="300" height="400"></iframe>

<!-- 或整页跳转 -->
<a href="/api/v1/auth/oauth/login?provider=wechat">微信登录</a>
```

微信的两个坑，代码里已经处理：

- 授权地址参数名是 **`appid`** 不是 `client_id`，且 URL 必须以 `#wechat_redirect` 结尾
- 接口出错时 **HTTP 仍是 200**，错误藏在 `errcode` 里 —— 只看状态码会漏掉 `40029 invalid code`

如果同时开了公众号，`unionid` 会把两边识别成同一个人（`link_by_unionid` 默认开）。

---

## 集成进 Gyra

### 1. 加依赖

`packages/gyra-app/pyproject.toml`（或 gyra-serve）加一行：

```toml
dependencies = [..., "gyra-user @ file:///Users/yanghongjun/code/gyra-user"]
```

### 2. 替换路由

`packages/gyra-app/src/gyra_app/openapi/api_v1/api_v1.py`：

```diff
- from .auth_api import router as auth_router
+ from gyra_user import (
+     create_account_router, create_admin_router,
+     create_auth_router, create_oidc_router,
+ )
+ from gyra_user.config import load_settings
+
+ _user_settings = load_settings()
+ auth_router  = create_auth_router(_user_settings)
+ admin_router = create_admin_router(_user_settings)

  router.include_router(auth_router, prefix="/v1", tags=["Auth"])
+ router.include_router(admin_router, prefix="/v1", tags=["Admin"])
+ router.include_router(create_account_router(_user_settings),
+                       prefix="/v1", tags=["Account"])
+ # OIDC：prefix 必须与挂载路径一致，否则 discovery 里的 issuer 对不上
+ app.include_router(create_oidc_router(_user_settings, prefix="/api/v1"))
```

完整可运行版本见 [`examples/mount_into_gyra.py`](examples/mount_into_gyra.py)。

### 3. 迁存量用户

```bash
python examples/migrate_gyra_users.py \
  --source sqlite:////Users/yanghongjun/code/Gyra/data/gyra.db \
  --target sqlite:////Users/yanghongjun/code/gyra-user/data/gyra_user.db \
  --dry-run   # 确认无误后去掉
```

保留主键 `id`（其它表的 `user_id` 外键不用动）、bcrypt 密码哈希、`oauth_provider/oauth_id`。

### 4. 灰度切换（可选）

把 Gyra 的 session secret 配进来，新旧 token 就能并行一段时间：

```bash
GYRA_USER_LEGACY_SESSION_SECRET=<gyra 的 OAUTH2_SESSION_SECRET>
```

旧 token 过期后摘掉这个配置即可。

### 5. 其它业务接口取当前用户

```python
from gyra_user.deps import get_current_active_user
from gyra_user.models import User

@router.get("/something")
async def something(user: User = Depends(get_current_active_user)):
    ...
```

---

## 部署

### 项目形态

标准 **uv 工程**：`pyproject.toml` + `uv.lock` + `.python-version`（3.12），`.venv` 由 uv 托管。
不要再用 pip 直接装依赖。

```bash
uv sync                      # 本地/开发（含 dev 组）
uv sync --frozen --extra prod  # 生产/容器（锁文件版本，装 gunicorn）
uv run <cmd>                 # 在受管环境里跑任何命令
make help                    # 常用命令一览
```

### Docker（推荐）

```bash
cp .env.example .env                      # 至少改 JWT_SECRET 和 PUBLIC_BASE_URL
docker compose up -d --build
curl http://localhost:8100/healthz
```

镜像是三阶段产物：builder 用官方 uv 镜像按锁文件装依赖（`--no-editable`，镜像里不留源码），
runtime 只带 `.venv` + 迁移脚本，以 uid 10001 非 root 运行，自带 `HEALTHCHECK` 打 `/healthz`。
入口脚本会**先跑 `gyra-user db upgrade` 再起 gunicorn**，迁移失败就不起服。

数据落在卷 `gyra-user-data`（容器里 `/data`），SQLite 库和 RS256 密钥都在那。

### systemd（裸机）

```bash
sudo useradd -r -s /usr/sbin/nologin gyra
sudo mkdir -p /opt/gyra-user /var/lib/gyra-user /etc/gyra-user
sudo rsync -a --exclude .venv --exclude data /path/to/gyra-user/ /opt/gyra-user/
cd /opt/gyra-user && uv sync --frozen --no-dev --extra prod
sudo install -m 644 deploy/systemd/gyra-user.service /etc/systemd/system/
sudo tee /etc/gyra-user/env >/dev/null <<'EOF'
GYRA_USER_ENVIRONMENT=production
GYRA_USER_PUBLIC_BASE_URL=https://auth.example.com
GYRA_USER_JWT_SECRET=...      # openssl rand -base64 48
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now gyra-user
```

### 生产启动自检

`environment = "production"` 时，`create_app()` 会**拒绝启动**并列出问题，而不是带病上线：

| 检查 | 触发条件 |
|---|---|
| JWT 密钥 | HS256 下密钥为空/过短/是占位值 |
| RS256 密钥对 | 开了 RS256 但没配公私钥 |
| `public_base_url` | 开了 OIDC 却是空（issuer 与 redirect_uri 必须是绝对地址） |
| 明文传输 | `public_base_url` 是 `http://` |

非 production 环境同样的问题只打 warning，不阻断开发。

### 数据库迁移

```bash
uv run gyra-user db upgrade          # 修历史漂移 + 应用待执行 revision
make migrate m='加 xxx 字段'          # 改完 models.py 后生成新 revision
```

`db upgrade` 做了两件事，所以**对老库也安全**：先用模型补齐缺失的表和列
（历史上 `create_all` 不会给已存在的表加列，很容易静默漂移），再交给 Alembic 应用后续 revision。
SQLite 用 batch 模式做变更。

### 多进程注意

SQLite + 多 worker 有两个坑，代码里都处理了：

- `PRAGMA journal_mode=WAL` 需要短暂排他锁，多个 worker 同时启动会抢 → 已加 `busy_timeout` 并吞掉这个特定错误（WAL 是文件级持久属性，谁抢到都行）
- 每个 worker 都 `create_all` 会撞 `table already exists` → **生产环境启动时根本不建表**，schema 只由迁移负责

写多读少没问题；要是并发写压力大，把 `GYRA_USER_DATABASE_URL` 换成 Postgres。

### 反代

用 `deploy/nginx/gyra-user.conf` 作为参考，**务必传 `X-Forwarded-Proto`**，
并把 `GYRA_USER_PUBLIC_BASE_URL` 设成对外地址，否则回调地址会被拼成 http。

---

## 和现有实现的主要差异

| 维度 | Gyra 现状（`gyra_app/auth/`） | gyra-user |
|---|---|---|
| 会话凭证 | 自研 HMAC 签名串，无过期轮换、无法吊销 | JWT access + 可轮换/可吊销 refresh，重放即整族吊销 |
| OAuth provider | 硬编码 github / alibaba-inc | 注册表 + 配置驱动，内置 github / wechat_open / wechat_mp / 任意 OIDC |
| 微信 | 无 | 支持，含 unionid 跨应用打通、errcode 处理、iframe 扫码 |
| 第三方身份 | 一人只有一组 `oauth_provider/oauth_id` | `oauth_accounts` 一对多，可绑定/解绑 |
| state | 进程内存 dict，多副本会失效 | 签名 token，无状态 |
| 存储 | 复用 `gyra.storage` | 独立 SQLite，不依赖 Gyra 内部模块 |
| 密码 | bcrypt | bcrypt（同一哈希，可直接迁） |
| 接口契约 | `/api/v1/auth/*` | **完全一致**，前端零改动 |

---

## 配置

优先级：**默认值 < `configs/auth.toml` < `configs/auth.local.toml` < `GYRA_USER_*` 环境变量**。
所有字段见 [`configs/auth.toml`](configs/auth.toml) 里的注释，环境变量清单见
[`.env.example`](.env.example)。

- `configs/auth.local.toml` 已被 gitignore，用来放密钥和本机覆盖。复制
  [`configs/auth.local.toml.example`](configs/auth.local.toml.example)，**只写要覆盖的键即可**：
  `[[providers]]` 按 `id` 合并字段，给 GitHub 补密钥不用把整段抄一遍。
- **第三方登录入口只在凭据齐全时出现**：`client_id` 为空 = 该 provider 未启用，
  登录页对应的按钮整块隐藏（不是报错），`/api/v1/auth/oauth/status` 会如实反映。

  登录页只显示「账号密码」、GitHub / 微信 不出现时，按这个顺序查：

  ```bash
  # 1. 服务端到底广告了哪些登录方式？只有 local 就是没配到凭据。
  curl -s https://<你的域名>/api/v1/auth/oauth/status
  #    {"enabled":true,"providers":[{"id":"local",...}]}   <- 缺 github / wechat

  # 2. 凭据在生效位置吗？三种写法都可以，但都要能落到进程环境或 .env：
  #    configs/auth.local.toml 的 [[providers]] / GYRA_USER_* 环境变量 / .env
  #    改了必须重启服务（配置只在启动时读一次）

  # 3. 直接问配置：能打印出 enabled=True 就说明读到了
  python -c "from gyra_user.config import load_settings as L; \
             print([(p.id,p.enabled) for p in L().providers])"
  ```

  两个容易踩的点：`.env` 里的 provider 凭据过去会被静默忽略（已在 `config.py`
  的 `env_lookup()` 修掉，真实环境变量仍优先）；凭据从 TOML 里删掉后仅靠环境变量
  提供的，现在会自动补回 shipped 定义，不再静默丢失。
- `GYRA_USER_JWT_SECRET` 生产环境必须配，否则会在 `data/.jwt_secret` 生成随机密钥（多副本会互相验签失败）
- 服务在反代后面时配 `GYRA_USER_PUBLIC_BASE_URL`，否则 `redirect_uri` 会算成内网地址
- `require_approval = true` 开启「注册需管理员审核」

### 邮箱作为身份锚点（账号绑定）

`link_by_email` 在 OAuth 首次登录时把新身份并进已有账号。为了防止「先抢注别人
邮箱、再等对方登录」这种吞号，**双方都验证过**邮箱才允许合并：

| 场景 | 结果 |
|---|---|
| provider 声明已验证 + 已有账号已验证 | 合并（正常的绑定） |
| provider 未声明验证 | 拒绝合并，记 `link_refused`，新账号不带该邮箱 |
| provider 已验证 + 已有账号**未**验证 | 不合并；邮箱**交还给邮箱主人**，记 `email_reclaimed` |
| 改邮箱（自助/后台） | `email_verified` 自动重置为 `False` |

- 本地注册的邮箱**永远是未验证**的——没接邮箱验证通道之前，它只是「暂借」，
  不能作为锚点。接上验证通道后再把它置 `True`。
- `reclaim_unverified_email = false` 时改为「两边都不给」：新账号邮箱留空，
  原账号保留。`link_by_email_requires_verified = false` 是退回旧行为的逃生阀，
  **生产不要关**。

---

## 登录页文案（品牌）

`/login` 左侧那块**不是写死的**，按 `(接入应用, 语言)` 解析后由服务端内联进页面：

```
app + locale → app + 默认语言 → default + locale → default + 默认语言 → 内置文案
```

三个来源，优先级从高到低：

| 来源 | 改哪里 | 生效方式 |
|---|---|---|
| 后台覆盖 | `/admin` →「品牌文案」 | 保存后刷新登录页即生效，**不用重启** |
| 配置文件 | `configs/auth.toml` 的 `[branding]` | 重启 |
| 内置文案 | [`gyra_user/branding.py`](src/gyra_user/branding.py) | — |

- **多屏轮播**：`slides` 写多条就是多屏，`rotate_interval` 控制间隔（0 = 不轮播，页面出现指示点）
- **多语言**：`locales` 列出可切换的语言，页面右上出现语言切换；按钮/提示等界面文案也在同一份数据里
  （`ui` 键，对应 HTML 上的 `data-i18n`），**加一门语言只需要加数据**
- **按接入应用**：`?app=<client_id>` 换一套文案与主题色（`[branding.theme]`）
- **接口**：`GET /api/v1/auth/branding?app=&lang=`（公开，登录页也用它做语言切换），
  后台预览用 `GET /api/v1/admin/branding/resolve?app=&lang=`

页面里带 `data-i18n` 的元素由 `ui` 填充；只有 JS 完全不可用时才会退回到 HTML 里那一屏静态兜底。


---

## 测试

```bash
make test     # 或 uv run pytest          —— 78 个用例
make lint     # 或 uv run ruff check src tests examples migrations
```

覆盖：注册/登录/刷新轮换/重放吊销/权限守卫/微信 errcode/unionid 合并/
邮箱合并/开放重定向防护/旧 Gyra token 兼容；
OIDC 侧覆盖发现文档/JWKS/授权码全流程（含 PKCE）/consent 记忆与拒绝/
授权码重放/跨 client refresh 盗用/introspect/revoke/全局登出/个人中心；
另有**迁移测试**（历史库补列、幂等、显式 URL 命中正确库）与
**生产配置守卫测试**（弱密钥/http 地址/缺 public_base_url 必须拒绝启动）。
第三方 OAuth 全流程用 mock provider 跑通（不依赖真实凭证）。

## CLI

```bash
uv run gyra-user init-db --admin-password xxx   # 建库 + 迁移 + 建管理员，可重复执行
uv run gyra-user db upgrade                     # 只跑迁移
uv run gyra-user db current                     # 当前 revision
uv run gyra-user db history
uv run gyra-user create-user alice --password xxx --role admin
uv run gyra-user list-users
uv run gyra-user set-role 1 admin
uv run gyra-user disable 2                      # 停用并踢下线
uv run gyra-user reset-password 1 --password xxx
python -m gyra_user.cli create-client "Gyra Web" --redirect-uri http://localhost:3000/cb
python -m gyra_user.cli list-clients
python -m gyra_user.cli gen-keys --out-dir data   # 生成 RS256 密钥对
python -m gyra_user.cli show-config
```
