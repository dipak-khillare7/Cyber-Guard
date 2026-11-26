from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.alert import AlertRead, AlertUpdate
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.api.deps import analyst_owner_id, require_analyst

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=dict)
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    risk_level: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    threat_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    """
    Retrieves threat alerts with pagination and optional risk level, status, or threat type filtering.
    """
    alerts, total = AlertService.list_alerts(
        db,
        skip=skip,
        limit=limit,
        risk_level=risk_level,
        status=status_filter,
        threat_type=threat_type,
        owner_user_id=analyst_owner_id(current_user),
    )
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [AlertRead.model_validate(a) for a in alerts]
    }


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    """
    Retrieves a single alert by its ID.
    """
    alert = AlertService.get_alert_by_id(
        db,
        alert_id,
        owner_user_id=analyst_owner_id(current_user),
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ALERT_NOT_FOUND", "message": f"Alert with ID {alert_id} was not found."}
        )
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    request: Request,
    db: Session = Depends(get_db),
    analyst_user = Depends(require_analyst)
):
    """
    Updates the status of an alert (ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE).
    Requires Analyst or Admin role. Generates audit trail log.
    """
    alert = AlertService.update_alert_status(
        db,
        alert_id,
        alert_update,
        owner_user_id=analyst_owner_id(analyst_user),
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ALERT_NOT_FOUND", "message": f"Alert with ID {alert_id} was not found."}
        )

    ip_addr = request.client.host if request.client else "unknown"
    AuditService.log_event(
        db=db,
        action="ALERT_STATUS_UPDATED",
        user_id=analyst_user.id,
        owner_user_id=alert.owner_user_id,
        username=analyst_user.username,
        resource_type="ALERT",
        resource_id=str(alert_id),
        ip_address=ip_addr,
        status="SUCCESS",
        metadata={"new_status": alert.status}
    )
    return alert
