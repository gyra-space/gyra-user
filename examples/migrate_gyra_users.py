"""把 Gyra 现有 user 表的数据迁到 gyra-user。

会保留主键 id（这样其它表里 user_id 外键不用动）、bcrypt 密码哈希、
oauth_provider/oauth_id、role、is_active 和时间戳。

    python examples/migrate_gyra_users.py \
        --source sqlite:////Users/yanghongjun/code/Gyra/data/gyra.db \
        --target sqlite:////Users/yanghongjun/code/gyra-user/data/gyra_user.db

    # 先演练一遍，不写库：
    python examples/migrate_gyra_users.py --source ... --dry-run

源库可以是 sqlite 也可以是 mysql（SQLAlchemy URL 能连即可）；
源表结构以 Gyra 的 UserEntity 为准，缺列自动按空值处理。
"""

from __future__ import annotations

import argparse
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import create_engine, text

from gyra_user.config import load_settings
from gyra_user.db import init_engine, session_scope
from gyra_user.models import User

SOURCE_COLUMNS = [
    "id",
    "name",
    "fullname",
    "oauth_provider",
    "oauth_id",
    "email",
    "avatar",
    "password_hash",
    "role",
    "department_1",
    "department_2",
    "is_active",
    "gmt_create",
    "gmt_modify",
]


def read_source(source_url: str, table: str = "user") -> List[Dict[str, Any]]:
    engine = create_engine(source_url)
    with engine.connect() as conn:
        existing = (
            {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = :t"
                    ),
                    {"t": table},
                )
            }
            if engine.dialect.name != "sqlite"
            else {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
        )

        columns = [c for c in SOURCE_COLUMNS if c in existing] or ["*"]
        col_sql = ", ".join(columns)
        rows = conn.execute(text(f"SELECT {col_sql} FROM {table}")).mappings().all()
    return [dict(row) for row in rows]


def _as_datetime(value: Any) -> datetime:
    """SQLite hands back timestamps as strings; normalise them."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return datetime.now()


def _as_bool(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return str(value) not in ("0", "false", "False", "")


def migrate(target_url: str, rows: List[Dict[str, Any]], dry_run: bool) -> int:
    if dry_run:
        for row in rows:
            print(f"[dry-run] would import id={row.get('id')} name={row.get('name')}")
        return 0

    init_engine(target_url)
    imported = 0
    with session_scope() as session:
        existing = session.query(User).all()
        by_name = {u.name: u for u in existing}
        by_id = {u.id for u in existing}
        for row in rows:
            name = row.get("name")
            row_id = row.get("id")
            if row_id is not None and row_id in by_id:
                print(f"skip: id {row_id} already exists")
                continue
            if name and name in by_name:
                print(f"skip existing user: {name}")
                continue
            session.add(
                User(
                    id=row.get("id"),
                    name=name,
                    fullname=row.get("fullname") or name,
                    email=row.get("email"),
                    avatar=row.get("avatar"),
                    password_hash=row.get("password_hash"),
                    oauth_provider=row.get("oauth_provider"),
                    oauth_id=row.get("oauth_id"),
                    role=row.get("role") or "normal",
                    department_1=row.get("department_1"),
                    department_2=row.get("department_2"),
                    is_active=_as_bool(row.get("is_active")),
                    gmt_create=_as_datetime(row.get("gmt_create")),
                    gmt_modify=_as_datetime(row.get("gmt_modify")),
                )
            )
            imported += 1
        session.flush()
    return imported


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Gyra 的数据库连接串")
    parser.add_argument("--target", default="", help="留空则用 gyra-user 自己的配置")
    parser.add_argument("--table", default="user")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    target = args.target or load_settings().resolved_database_url()
    rows = read_source(args.source, args.table)
    print(f"read {len(rows)} users from source")
    count = migrate(target, rows, args.dry_run)
    print(f"imported {count} users into {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
