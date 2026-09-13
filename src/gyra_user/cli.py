"""Command line helper: init DB, manage users, inspect config.

python -m gyra_user.cli init-db
python -m gyra_user.cli create-user admin --password secret --role admin
python -m gyra_user.cli list-users
python -m gyra_user.cli set-role 1 admin
python -m gyra_user.cli disable 2
python -m gyra_user.cli create-client "Gyra Web" --redirect-uri http://localhost:3000/cb
python -m gyra_user.cli list-clients
python -m gyra_user.cli gen-keys --out-dir data
python -m gyra_user.cli show-config
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from gyra_user.config import load_settings
from gyra_user.db import init_engine, session_scope
from gyra_user.models import User
from gyra_user.oidc_service import DEFAULT_SCOPES, OIDCService
from gyra_user.service import UserService, ensure_bootstrap_admin


def _settings(args: argparse.Namespace):
    return load_settings(getattr(args, "config", None))


def cmd_init_db(args: argparse.Namespace) -> int:
    """Create/upgrade the schema and optionally bootstrap an admin.

    Safe to run on every deploy: it repairs schema drift, then applies any
    pending Alembic revisions.
    """
    from gyra_user.migrate import run as migrate_run

    settings = _settings(args)
    url = settings.resolved_database_url()
    engine = init_engine(url, create_tables=False)
    changes, revision = migrate_run(url)
    for change in changes:
        print(f"  · {change}")
    print(f"database ready: {engine.url} (revision {revision or 'baseline'})")
    if args.admin_password:
        user = ensure_bootstrap_admin(settings, args.admin_password)
        if user:
            print(f"created admin '{user.name}'")
        else:
            print("users already exist, skipped admin bootstrap")
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        service = UserService(session, settings)
        try:
            user = service.create_local_user(
                username=args.username,
                password=args.password,
                email=args.email or "",
                fullname=args.fullname or args.username,
                role=args.role,
                is_active=not args.disabled,
            )
            service.update_user(user.id, is_pending=False)
        except Exception as exc:  # noqa: BLE001
            print(f"failed: {exc}", file=sys.stderr)
            return 1
        session.flush()
        print(json.dumps(user.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_list_users(args: argparse.Namespace) -> int:
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        users = session.query(User).order_by(User.id).all()
        if not users:
            print("(no users)")
            return 0
        rows = [
            [
                str(u.id),
                u.name or "",
                u.fullname or "",
                u.email or "",
                u.role or "",
                "active" if u.is_active else "disabled",
                u.oauth_provider or "",
            ]
            for u in users
        ]
        headers = ["id", "name", "fullname", "email", "role", "status", "provider"]
        widths = [
            max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)
        ]
        print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
        for row in rows:
            print("  ".join(v.ljust(w) for v, w in zip(row, widths)))
    return 0


def _mutate(args: argparse.Namespace, **fields) -> int:
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        user = session.get(User, args.user_id)
        if user is None:
            print(f"user {args.user_id} not found", file=sys.stderr)
            return 1
        for key, value in fields.items():
            setattr(user, key, value)
        if fields.get("is_active") is False:
            UserService(session, settings).revoke_all_for_user(user.id)
        session.flush()
        print(json.dumps(user.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_set_role(args: argparse.Namespace) -> int:
    return _mutate(args, role=args.role)


def cmd_disable(args: argparse.Namespace) -> int:
    return _mutate(args, is_active=False)


def cmd_enable(args: argparse.Namespace) -> int:
    return _mutate(args, is_active=True, is_pending=False)


def cmd_reset_password(args: argparse.Namespace) -> int:
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        service = UserService(session, settings)
        try:
            service.set_password(args.user_id, args.password)
            service.revoke_all_for_user(args.user_id)
            session.flush()
        except Exception as exc:  # noqa: BLE001
            print(f"failed: {exc}", file=sys.stderr)
            return 1
    print("password updated")
    return 0


def cmd_create_client(args: argparse.Namespace) -> int:
    """Register a relying party without booting the admin UI."""
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        oidc = OIDCService(session, settings)
        try:
            client, secret = oidc.create_client(
                name=args.name,
                redirect_uris=args.redirect_uri,
                scope=args.scope,
                is_confidential=not args.public,
                skip_consent=args.skip_consent,
                homepage_url=args.homepage or "",
            )
            session.flush()
        except Exception as exc:  # noqa: BLE001
            print(f"failed: {exc}", file=sys.stderr)
            return 1
        print(f"client_id:     {client.client_id}")
        if secret:
            print(f"client_secret: {secret}   (shown once, store it now)")
        else:
            print("client_secret: (public client — no secret, PKCE required)")
        print(f"redirect_uris: {', '.join(client.redirect_uri_list)}")
    return 0


def cmd_list_clients(args: argparse.Namespace) -> int:
    settings = _settings(args)
    init_engine(settings.resolved_database_url())
    with session_scope() as session:
        clients, _total = OIDCService(session, settings).list_clients(limit=500)
        if not clients:
            print("(no applications registered)")
            return 0
        rows = [
            [
                c.client_id,
                c.name,
                "confidential" if c.is_confidential else "public",
                "yes" if c.skip_consent else "no",
                "active" if c.is_active else "disabled",
                str(len(c.redirect_uri_list)),
            ]
            for c in clients
        ]
        headers = ["client_id", "name", "type", "skip_consent", "status", "uris"]
        widths = [
            max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)
        ]
        print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
        for row in rows:
            print("  ".join(v.ljust(w) for v, w in zip(row, widths)))
    return 0


def cmd_gen_keys(args: argparse.Namespace) -> int:
    """Generate an RS256 key pair so the JWKS endpoint has something to serve."""
    from pathlib import Path

    from gyra_user.security import generate_rsa_keypair

    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_rsa_keypair()
    private_path = out_dir / "jwt_private.pem"
    public_path = out_dir / "jwt_public.pem"
    private_path.write_text(private_pem, encoding="utf-8")
    public_path.write_text(public_pem, encoding="utf-8")
    private_path.chmod(0o600)
    print(f"private key: {private_path}")
    print(f"public key:  {public_path}")
    print("")
    print("add to configs/auth.toml:")
    print('  jwt_algorithm = "RS256"')
    print(f'  jwt_private_key_file = "{private_path}"')
    print(f'  jwt_public_key_file = "{public_path}"')
    return 0


def cmd_db_upgrade(args: argparse.Namespace) -> int:
    from gyra_user.migrate import run as migrate_run

    url = _settings(args).resolved_database_url()
    init_engine(url, create_tables=False)
    changes, revision = migrate_run(url, args.revision)
    if not changes:
        print("already up to date")
    for change in changes:
        print(f"  · {change}")
    print(f"revision: {revision or 'baseline'}")
    return 0


def cmd_db_current(args: argparse.Namespace) -> int:
    from gyra_user.migrate import current as migrate_current

    url = _settings(args).resolved_database_url()
    init_engine(url, create_tables=False)
    print(migrate_current(url))
    return 0


def cmd_db_stamp(args: argparse.Namespace) -> int:
    """Mark an existing database as being at a revision (no DDL executed)."""
    from gyra_user.migrate import stamp as migrate_stamp

    url = _settings(args).resolved_database_url()
    init_engine(url, create_tables=False)
    migrate_stamp(url, args.revision)
    print(f"stamped {args.revision}")
    return 0


def cmd_db_history(args: argparse.Namespace) -> int:
    from gyra_user.migrate import history as migrate_history

    url = _settings(args).resolved_database_url()
    for line in migrate_history(url):
        print(line)
    return 0


def cmd_show_config(args: argparse.Namespace) -> int:
    settings = _settings(args)
    data = settings.model_dump()
    data["database_url"] = settings.resolved_database_url()
    data["providers"] = [
        {**p.model_dump(), "enabled": p.enabled} for p in settings.providers
    ]
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gyra-user", description=__doc__)
    parser.add_argument("--config", help="path to auth.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-db", help="create/upgrade tables")
    p.add_argument("--admin-password", dest="admin_password", default="")
    p.set_defaults(func=cmd_init_db)

    db = sub.add_parser("db", help="schema migrations").add_subparsers(
        dest="db_command", required=True
    )
    p = db.add_parser("upgrade", help="repair drift and apply pending revisions")
    p.add_argument("revision", nargs="?", default="head")
    p.set_defaults(func=cmd_db_upgrade)
    p = db.add_parser("current", help="show the applied revision")
    p.set_defaults(func=cmd_db_current)
    p = db.add_parser("stamp", help="mark the database as being at a revision")
    p.add_argument("revision", nargs="?", default="head")
    p.set_defaults(func=cmd_db_stamp)
    p = db.add_parser("history", help="list revisions")
    p.set_defaults(func=cmd_db_history)

    p = sub.add_parser("create-user", help="create a local user")
    p.add_argument("username")
    p.add_argument("--password", required=True)
    p.add_argument("--email", default="")
    p.add_argument("--fullname", default="")
    p.add_argument("--role", default="normal")
    p.add_argument("--disabled", action="store_true")
    p.set_defaults(func=cmd_create_user)

    p = sub.add_parser("list-users", help="list all users")
    p.set_defaults(func=cmd_list_users)

    p = sub.add_parser("set-role", help="change a user's role")
    p.add_argument("user_id", type=int)
    p.add_argument("role")
    p.set_defaults(func=cmd_set_role)

    p = sub.add_parser("disable", help="disable a user and revoke sessions")
    p.add_argument("user_id", type=int)
    p.set_defaults(func=cmd_disable)

    p = sub.add_parser("enable", help="enable a user")
    p.add_argument("user_id", type=int)
    p.set_defaults(func=cmd_enable)

    p = sub.add_parser("reset-password", help="set a new password")
    p.add_argument("user_id", type=int)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_reset_password)

    p = sub.add_parser("create-client", help="register an SSO application")
    p.add_argument("name")
    p.add_argument(
        "--redirect-uri",
        action="append",
        dest="redirect_uri",
        required=True,
        metavar="URI",
    )
    p.add_argument("--scope", default=DEFAULT_SCOPES)
    p.add_argument("--public", action="store_true", help="SPA / mobile (PKCE only)")
    p.add_argument(
        "--skip-consent", action="store_true", help="first-party app: no consent page"
    )
    p.add_argument("--homepage", default="")
    p.set_defaults(func=cmd_create_client)

    p = sub.add_parser("list-clients", help="list registered SSO applications")
    p.set_defaults(func=cmd_list_clients)

    p = sub.add_parser("gen-keys", help="generate an RS256 key pair for the JWKS")
    p.add_argument("--out-dir", dest="out_dir", default="data")
    p.set_defaults(func=cmd_gen_keys)

    p = sub.add_parser("show-config", help="dump resolved configuration")
    p.set_defaults(func=cmd_show_config)
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
