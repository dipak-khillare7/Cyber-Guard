from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.incident import IncidentCreate, IncidentRead, IncidentUpdate
from app.schemas.response_action import ResponseActionCreate, ResponseActionRead
from app.services.incident_service import IncidentService
from app.services.response_service import ResponseService
from app.services.audit_service import AuditService
from app.api.deps import require_analyst

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
    analyst_user = Depends(require_analyst)
):
    """
    Creates a new security incident manually or from an alert. Requires Analyst/Admin role.
    """
    new_inc = IncidentService.create_incident(
        db,
        incident_in,
        creator_user_id=analyst_user.id,
    )
    ip_addr = request.client.host if request.client else "unknown"
    AuditService.log_event(
        db=db,
        action="INCIDENT_CREATED",
        user_id=analyst_user.id,
        username=analyst_user.username,
        resource_type="INCIDENT",
        resource_id=str(new_inc.id),
        ip_address=ip_addr,
        status="SUCCESS",
        metadata={"title": new_inc.title, "severity": new_inc.severity}
    )
    return new_inc


@router.get("", response_model=dict)
def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    _analyst_user = Depends(require_analyst)
):
    """
    Retrieves security incidents with pagination and optional filtering.
    """
    incidents, total = IncidentService.list_incidents(
        db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status_filter,
    )
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [IncidentRead.model_validate(inc) for inc in incidents]
    }


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    _analyst_user = Depends(require_analyst)
):
    """
    Retrieves a single incident by its ID, including attached response action history.
    """
    incident = IncidentService.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INCIDENT_NOT_FOUND", "message": f"Incident with ID {incident_id} was not found."}
        )
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: int,
    update_in: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    analyst_user = Depends(require_analyst)
):
    """
    Updates incident status or assigned handler. Requires Analyst or Admin role.
    Generates audit log entry.
    """
    incident = IncidentService.update_incident(db, incident_id, update_in)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INCIDENT_NOT_FOUND", "message": f"Incident with ID {incident_id} was not found."}
        )
    
    ip_addr = request.client.host if request.client else "unknown"
    AuditService.log_event(
        db=db,
        action="INCIDENT_STATUS_UPDATED",
        user_id=analyst_user.id,
        username=analyst_user.username,
        resource_type="INCIDENT",
        resource_id=str(incident_id),
        ip_address=ip_addr,
        status="SUCCESS",
        metadata={"new_status": incident.status}
    )
    return incident


@router.post("/{incident_id}/response", response_model=ResponseActionRead, status_code=status.HTTP_201_CREATED)
def trigger_response_action(
    incident_id: int,
    action_in: ResponseActionCreate,
    request: Request,
    db: Session = Depends(get_db),
    analyst_user = Depends(require_analyst)
):
    """
    Executes a safe simulated response action for the specified incident.
    Requires Analyst or Admin role.
    """
    if action_in.incident_id != incident_id:
        action_in.incident_id = incident_id

    try:
        action = ResponseService.execute_simulated_action(db, action_in)
        ip_addr = request.client.host if request.client else "unknown"
        AuditService.log_event(
            db=db,
            action="RESPONSE_ACTION_TRIGGERED",
            user_id=analyst_user.id,
            username=analyst_user.username,
            resource_type="RESPONSE_ACTION",
            resource_id=str(action.id),
            ip_address=ip_addr,
            status="SUCCESS",
            metadata={"action_type": action.action_type, "incident_id": incident_id}
        )
        return action
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INCIDENT_NOT_FOUND", "message": "Incident not found."},
        ) from err
