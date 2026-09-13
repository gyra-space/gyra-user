"""Self-service account router — what a logged-in user can do to their own
account: edit their profile, change their password, inspect and kill sessions,
review login history.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from gyra_user import deps
from gyra_user.config import Settings
from gyra_user.models import LoginEvent, User
from gyra_user.oidc_service import OIDCService
from gyra_user.schemas import ChangePasswordRequest, ProfileUpdateRequest
from gyra_user.security import decode_frontend_password, verify_password
from gyra_user.service import UserService, UserServiceError


def create_account_router(settings: Optional[Settings] = None) -> APIRouter:
    router = APIRouter(prefix="/account", tags=["Account"])

    def cfg() -> Settings:
        return settings or deps.get_settings()

    guard = [Depends(deps.get_current_active_user)]

    @router.get("/profile")
    async def get_profile(current_user: User = Depends(deps.get_current_active_user)):
        return current_user.to_dict(include_sensitive=True)

    @router.patch("/profile", dependencies=guard)
    async def update_profile(
        body: ProfileUpdateRequest,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        fields = body.model_dump(exclude_none=True)
        email = fields.get("email")
        if email:
            existing = service.get_by_email(email)
            if existing is not None and existing.id != current_user.id:
                raise HTTPException(status_code=400, detail="Email already in use")
        try:
            user = service.update_user(current_user.id, **fields)
        except UserServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.message
            ) from exc
        session.commit()
        return user.to_dict(include_sensitive=True)

    @router.post("/password", dependencies=guard)
    async def change_password(
        body: ChangePasswordRequest,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        if current_user.password_hash and not verify_password(
            decode_frontend_password(body.old_password), current_user.password_hash
        ):
            raise HTTPException(status_code=400, detail="Current password is wrong")
        service.set_password(current_user.id, body.new_password)
        # Keep the current device signed in; everything else must re-authenticate.
        service.record_event(
            user_id=current_user.id,
            action="password_change",
            username=current_user.name or "",
            success=True,
        )
        session.commit()
        return {"success": True}

    @router.get("/sessions", dependencies=guard)
    async def list_sessions(
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        oidc = OIDCService(session, config)
        clients = {
            client.client_id: client.name for client in oidc.list_clients(limit=500)[0]
        }
        items = []
        for record in service.list_sessions(current_user.id, only_active=False):
            if record.revoked_at is not None:
                continue
            items.append(
                {
                    "jti": record.jti,
                    "client_id": record.client_id or "",
                    "client_name": clients.get(record.client_id or "", "用户中心"),
                    "ip": record.ip or "",
                    "user_agent": record.user_agent or "",
                    "created_at": record.gmt_create.isoformat()
                    if record.gmt_create
                    else None,
                    "expires_at": record.expires_at.isoformat()
                    if record.expires_at
                    else None,
                }
            )
        return {"items": items, "total": len(items)}

    @router.delete("/sessions/{jti}", dependencies=guard)
    async def revoke_session(
        jti: str,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        if not service.revoke_session(current_user.id, jti):
            raise HTTPException(status_code=404, detail="Session not found")
        session.commit()
        return {"success": True}

    @router.get("/login-events", dependencies=guard)
    async def my_login_events(
        limit: int = Query(20, ge=1, le=200),
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
    ):
        events = (
            session.query(LoginEvent)
            .filter(LoginEvent.user_id == current_user.id)
            .order_by(LoginEvent.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": e.id,
                "action": e.action,
                "provider": e.provider or "",
                "success": e.success,
                "detail": e.detail or "",
                "ip": e.ip or "",
                "gmt_create": e.gmt_create.isoformat() if e.gmt_create else None,
            }
            for e in events
        ]

    @router.get("/apps", dependencies=guard)
    async def my_apps(
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        """Applications this user has authorised (single sign-on footprint)."""
        oidc = OIDCService(session, config)
        items = []
        for consent in oidc.list_consents(current_user.id):
            client = oidc.get_client(consent.client_id)
            items.append(
                {
                    "client_id": consent.client_id,
                    "name": client.name if client else consent.client_id,
                    "logo_url": client.logo_url if client else "",
                    "homepage_url": client.homepage_url if client else "",
                    "scope": consent.scope,
                    "granted_at": consent.gmt_create.isoformat()
                    if consent.gmt_create
                    else None,
                }
            )
        return {"items": items, "total": len(items)}

    @router.delete("/apps/{client_id}", dependencies=guard)
    async def revoke_app(
        client_id: str,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.get_current_active_user),
        config: Settings = Depends(cfg),
    ):
        """Withdraw consent and kill every session that app holds."""
        service = UserService(session, config)
        oidc = OIDCService(session, config)
        oidc.revoke_consent(current_user.id, client_id)
        revoked = service.revoke_all_for_user(current_user.id, client_id=client_id)
        session.commit()
        return {"success": True, "revoked_sessions": revoked}

    return router


__all__ = ["create_account_router"]
