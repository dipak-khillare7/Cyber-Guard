from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.rate_limit import enforce_rate_limit
from app.database import get_db
from app.models.analyst_access_request import AnalystAccessRequest
from app.models.user import User, UserRole
from app.schemas.analyst_access_request import (
    AnalystAccessRequestAdminRead,
    AnalystAccessRequestDecision,
    AnalystAccessRequestList,
    AnalystAccessRequestRead,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/access-requests", tags=["Access Requests"])


@router.post(
    "/analyst",
    response_model=AnalystAccessRequestRead,
    status_code=status.HTTP_201_CREATED,
)
def request_analyst_access(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != UserRole.VIEWER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Analyst access can only be requested by a Normal User account.",
        )

    enforce_rate_limit(
        db,
        f"analyst-access-request:user:{current_user.id}",
        limit=3,
        window_seconds=3600,
        action="analyst access request",
    )
    existing = db.query(AnalystAccessRequest).filter(
        AnalystAccessRequest.pending_user_id == current_user.id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An Analyst access request is already pending.",
        )

    access_request = AnalystAccessRequest(
        requester_user_id=current_user.id,
        pending_user_id=current_user.id,
    )
    db.add(access_request)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An Analyst access request is already pending.",
        ) from exc

    AuditService.log_event(
        db=db,
        action="ANALYST_ACCESS_REQUESTED",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="ANALYST_ACCESS_REQUEST",
        resource_id=str(access_request.id),
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("User-Agent", "unknown"),
        metadata={"request_status": "PENDING"},
    )
    db.refresh(access_request)
    return access_request


@router.get("/analyst/me", response_model=Optional[AnalystAccessRequestRead])
def get_my_analyst_access_request(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(AnalystAccessRequest)
        .filter(AnalystAccessRequest.requester_user_id == current_user.id)
        .order_by(AnalystAccessRequest.requested_at.desc(), AnalystAccessRequest.id.desc())
        .first()
    )


@router.get("/analyst", response_model=AnalystAccessRequestList)
def list_pending_analyst_access_requests(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _admin_user: User = Depends(require_admin),
):
    query = (
        db.query(AnalystAccessRequest, User)
        .join(User, User.id == AnalystAccessRequest.requester_user_id)
        .filter(AnalystAccessRequest.status == "PENDING")
    )
    total = query.count()
    rows = (
        query.order_by(AnalystAccessRequest.requested_at.asc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    items = []
    for access_request, requester in rows:
        item = AnalystAccessRequestRead.model_validate(access_request).model_dump()
        item.update(
            username=requester.username,
            email=requester.email,
            full_name=requester.full_name,
        )
        items.append(AnalystAccessRequestAdminRead.model_validate(item))
    return {"items": items, "total": total}


@router.post(
    "/analyst/{request_id}/decision",
    response_model=AnalystAccessRequestRead,
)
def decide_analyst_access_request(
    request_id: int,
    decision: AnalystAccessRequestDecision,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    access_request = (
        db.query(AnalystAccessRequest)
        .filter(AnalystAccessRequest.id == request_id)
        .with_for_update()
        .first()
    )
    if not access_request:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access request not found.")
    if access_request.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This access request has already been reviewed.",
        )

    requester = (
        db.query(User)
        .filter(User.id == access_request.requester_user_id)
        .with_for_update()
        .first()
    )
    if not requester:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Requesting account not found.")
    if decision.decision == "APPROVE" and not requester.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Inactive accounts cannot be granted Analyst access.",
        )

    approved = decision.decision == "APPROVE"
    if approved:
        requester.role = UserRole.ANALYST
        access_request.status = "APPROVED"
        action = "ANALYST_ACCESS_APPROVED"
    else:
        access_request.status = "REJECTED"
        action = "ANALYST_ACCESS_REJECTED"

    access_request.pending_user_id = None
    access_request.reviewed_by_user_id = admin_user.id
    access_request.reviewed_at = datetime.now(timezone.utc)
    AuditService.log_event(
        db=db,
        action=action,
        user_id=admin_user.id,
        username=admin_user.username,
        resource_type="ANALYST_ACCESS_REQUEST",
        resource_id=str(access_request.id),
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("User-Agent", "unknown"),
        metadata={
            "requester_user_id": requester.id,
            "request_status": access_request.status,
        },
    )
    db.refresh(access_request)
    return access_request
