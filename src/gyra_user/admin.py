"""Admin router — user management (mount under ``/api/v1``)."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from gyra_user import deps
from gyra_user.config import Settings
from gyra_user.models import LoginEvent, User
from gyra_user.oidc_service import OIDCError, OIDCService
from gyra_user.schemas import (
    ClientCreateRequest,
    ClientUpdateRequest,
    ResetPasswordRequest,
    UpdateUserRequest,
    UserOut,
)
from gyra_user.service import UserService, UserServiceError


def create_admin_router(settings: Optional[Settings] = None) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["Admin"])

    def cfg() -> Settings:
        return settings or deps.get_settings()

    guard = [Depends(deps.require_admin)]

    @router.get("/users", dependencies=guard)
    async def list_users(
        keyword: str = Query("", description="match name/fullname/email"),
        role: str = Query(""),
        is_active: Optional[bool] = Query(None),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        users, total = service.list_users(
            keyword=keyword, role=role, is_active=is_active, limit=limit, offset=offset
        )
        return {
            "total": total,
            "items": [UserOut(**u.to_dict()).model_dump(mode="json") for u in users],
        }

    @router.get("/users/{user_id}", dependencies=guard)
    async def get_user(
        user_id: int,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        user = service.get_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        data = user.to_dict(include_sensitive=True)
        data["bindings"] = [b.to_dict() for b in service.list_bindings(user_id)]
        return data

    @router.patch("/users/{user_id}", dependencies=guard)
    async def update_user(
        user_id: int,
        body: UpdateUserRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        try:
            user = service.update_user(user_id, **body.model_dump(exclude_none=True))
        except UserServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.message
            ) from exc
        if body.is_active is False:
            service.revoke_all_for_user(user_id)
        session.commit()
        return user.to_dict()

    @router.delete("/users/{user_id}", dependencies=guard)
    async def delete_user(
        user_id: int,
        session: Session = Depends(deps.get_db),
        current_user: User = Depends(deps.require_admin),
        config: Settings = Depends(cfg),
    ):
        if current_user.id == user_id:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        service = UserService(session, config)
        if not service.delete_user(user_id):
            raise HTTPException(status_code=404, detail="User not found")
        session.commit()
        return {"success": True}

    @router.post("/users/{user_id}/reset-password", dependencies=guard)
    async def reset_password(
        user_id: int,
        body: ResetPasswordRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        try:
            service.set_password(user_id, body.password)
        except UserServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.message
            ) from exc
        service.revoke_all_for_user(user_id)
        session.commit()
        return {"success": True}

    @router.post("/users/{user_id}/revoke-sessions", dependencies=guard)
    async def revoke_sessions(
        user_id: int,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        service = UserService(session, config)
        count = service.revoke_all_for_user(user_id)
        session.commit()
        return {"success": True, "revoked": count}

    # ────────────────────── relying-party (SSO app) registry ──────────────

    @router.get("/clients", dependencies=guard)
    async def list_clients(
        keyword: str = Query(""),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        oidc = OIDCService(session, config)
        clients, total = oidc.list_clients(keyword=keyword, limit=limit, offset=offset)
        return {"total": total, "items": [c.to_dict() for c in clients]}

    @router.post("/clients", dependencies=guard, status_code=201)
    async def create_client(
        body: ClientCreateRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Register an app. The secret is returned **once** and never again."""
        oidc = OIDCService(session, config)
        try:
            client, secret = oidc.create_client(
                name=body.name,
                redirect_uris=body.redirect_uris,
                scope=body.scope,
                grant_types=body.grant_types,
                is_confidential=body.is_confidential,
                skip_consent=body.skip_consent,
                description=body.description or "",
                homepage_url=body.homepage_url or "",
                logo_url=body.logo_url or "",
                access_token_ttl=body.access_token_ttl,
                refresh_token_ttl=body.refresh_token_ttl,
            )
        except OIDCError as exc:
            raise HTTPException(status_code=400, detail=exc.description) from exc
        session.commit()
        data = client.to_dict()
        data["client_secret"] = secret  # only ever visible here
        return data

    @router.get("/clients/{client_id}", dependencies=guard)
    async def get_client(
        client_id: str,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        oidc = OIDCService(session, config)
        client = oidc.get_client(client_id)
        if client is None:
            raise HTTPException(status_code=404, detail="Client not found")
        return client.to_dict()

    @router.patch("/clients/{client_id}", dependencies=guard)
    async def update_client(
        client_id: str,
        body: ClientUpdateRequest,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        oidc = OIDCService(session, config)
        try:
            client = oidc.update_client(client_id, **body.model_dump(exclude_none=True))
        except OIDCError as exc:
            raise HTTPException(status_code=400, detail=exc.description) from exc
        session.commit()
        return client.to_dict()

    @router.delete("/clients/{client_id}", dependencies=guard)
    async def delete_client(
        client_id: str,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        oidc = OIDCService(session, config)
        if not oidc.delete_client(client_id):
            raise HTTPException(status_code=404, detail="Client not found")
        session.commit()
        return {"success": True}

    @router.post("/clients/{client_id}/rotate-secret", dependencies=guard)
    async def rotate_client_secret(
        client_id: str,
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ):
        """Issue a new secret; the old one stops working immediately."""
        oidc = OIDCService(session, config)
        try:
            client, secret = oidc.rotate_secret(client_id)
        except OIDCError as exc:
            raise HTTPException(status_code=400, detail=exc.description) from exc
        session.commit()
        data = client.to_dict()
        data["client_secret"] = secret
        return data

    @router.get("/login-events", dependencies=guard)
    async def login_events(
        user_id: Optional[int] = Query(None),
        limit: int = Query(50, ge=1, le=500),
        session: Session = Depends(deps.get_db),
        config: Settings = Depends(cfg),
    ) -> List[dict]:
        query = session.query(LoginEvent)
        if user_id is not None:
            query = query.filter(LoginEvent.user_id == user_id)
        events = query.order_by(LoginEvent.id.desc()).limit(limit).all()
        return [
            {
                "id": e.id,
                "user_id": e.user_id,
                "username": e.username or "",
                "provider": e.provider or "",
                "action": e.action,
                "success": e.success,
                "detail": e.detail or "",
                "ip": e.ip or "",
                "gmt_create": e.gmt_create.isoformat() if e.gmt_create else None,
            }
            for e in events
        ]

    return router


__all__ = ["create_admin_router"]
