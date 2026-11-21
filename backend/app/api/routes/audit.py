from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.audit_log import AuditLogListResponse, AuditLogResponse
from app.services.audit_service import AuditService
from app.api.deps import require_analyst

router = APIRouter(prefix="/audit-logs", tags=["Audit Logging & System Trails"])


@router.get("", response_model=AuditLogListResponse, summary="List Security Audit Trail Logs")
def get_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    action: Optional[str] = Query(None, description="Filter by action code"),
    username: Optional[str] = Query(None, description="Filter by username"),
    current_user=Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """
    Retrieves system audit logs recording authentication events, status changes, and administrative actions.
    Requires Analyst or Admin authorization.
    """
    items, total = AuditService.get_audit_logs(
        db=db,
        page=page,
        limit=limit,
        action=action,
        username=username
    )
    pages = (total + limit - 1) // limit if limit > 0 else 1

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )
