from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from app.database.connection import get_db
from app.models.response_action import ResponseAction
from app.models.incident import Incident
from app.schemas.response_action import ResponseActionRead
from app.api.deps import analyst_owner_id, require_analyst

router = APIRouter(prefix="/response-actions", tags=["Response Actions"])


@router.get("", response_model=dict)
def list_response_actions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    action_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    analyst_user=Depends(require_analyst),
):
    """
    Retrieves safe simulated response action execution history.
    """
    query = db.query(ResponseAction).options(
        joinedload(ResponseAction.incident).joinedload(Incident.alert)
    )
    owner_user_id = analyst_owner_id(analyst_user)
    if owner_user_id is not None:
        query = query.filter(
            ResponseAction.owner_user_id == owner_user_id,
            Incident.owner_user_id == owner_user_id,
        ).join(Incident, ResponseAction.incident_id == Incident.id)
    if action_type:
        query = query.filter(ResponseAction.action_type == action_type.upper())

    total = query.count()
    actions = query.order_by(desc(ResponseAction.id)).offset(skip).limit(limit).all()

    from app.core.security import format_iso_utc

    items = []
    for act in actions:
        incident = act.incident
        alert = incident.alert if incident else None
        event_id = alert.event_id if alert else None
        items.append({
            "id": act.id,
            "incident_id": act.incident_id,
            "alert_id": incident.alert_id if incident else None,
            "event_id": event_id,
            "action_type": act.action_type,
            "action_status": act.action_status,
            "status": act.action_status,
            "description": act.description,
            "reason": act.description,
            "executed_at": format_iso_utc(act.executed_at),
            "threat_type": incident.threat_type if incident else "N/A",
            "severity": incident.severity if incident else "N/A",
            "is_simulated": True
        })

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": items
    }
