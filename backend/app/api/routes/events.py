from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.security_event import SecurityEventCreate, SecurityEventRead
from app.services.event_service import EventService
from app.services.alert_service import AlertService
from app.services.risk_service import calculate_risk
from app.ml.inference.predictor import ThreatPredictor
from app.schemas.alert import AlertCreate
from app.schemas.enums import ThreatType, AlertStatus
from app.api.deps import (
    analyst_owner_id,
    enforce_ingestion_ip_rate_limit,
    require_analyst,
)
from app.core.rate_limit import enforce_rate_limit

router = APIRouter(prefix="/events", tags=["Security Events"])
predictor = ThreatPredictor()


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def create_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db),
    _ingestion_ip_limit: None = Depends(enforce_ingestion_ip_rate_limit),
    current_user=Depends(require_analyst),
):
    """
    Accepts, validates, and stores a new security event.
    Evaluates ML threat prediction and generates an alert if suspicious activity is detected.
    """
    enforce_rate_limit(
        db,
        f"ingestion:user:{current_user.id}",
        limit=30,
        window_seconds=60,
        action="event ingestion",
    )
    event = EventService.create_event(
        db,
        event_in,
        owner_user_id=current_user.id,
    )

    feature_dict = {
        "destination_port": event.destination_port,
        "duration": event.duration,
        "packet_count": event.packet_count,
        "byte_count": event.byte_count,
        "raw_data": event.raw_data
    }

    # Execute ML Inference
    prediction_result = predictor.predict(feature_dict)
    
    if isinstance(prediction_result, tuple):
        predicted_threat_str, confidence = prediction_result
    else:
        predicted_threat_str = prediction_result.get("predicted_threat", ThreatType.NORMAL.value)
        confidence_value = prediction_result.get("confidence")
        confidence = float(confidence_value) if confidence_value is not None else 0.0

    try:
        predicted_threat = ThreatType(predicted_threat_str)
    except ValueError:
        predicted_threat = ThreatType.NORMAL

    if predicted_threat != ThreatType.NORMAL:
        risk_level, score, reason = calculate_risk(predicted_threat, confidence, feature_dict)
        alert_in = AlertCreate(
            event_id=event.id,
            threat_type=predicted_threat,
            confidence=confidence,
            risk_level=risk_level,
            message=reason,
            status=AlertStatus.NEW
        )
        AlertService.create_alert(db, alert_in)

    return event


@router.get("", response_model=dict)
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    event_type: Optional[str] = Query(None),
    scope: Literal["role", "own"] = Query("role"),
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """
    Retrieves security events with pagination and optional event_type filtering.
    """
    owner_user_id = analyst_owner_id(current_user)
    if owner_user_id is None and scope == "own":
        owner_user_id = current_user.id
    events, total = EventService.list_events(
        db,
        skip=skip,
        limit=limit,
        event_type=event_type,
        owner_user_id=owner_user_id,
    )
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [SecurityEventRead.model_validate(e) for e in events]
    }


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """
    Retrieves a single security event by its ID.
    """
    event = EventService.get_event_by_id(
        db,
        event_id,
        owner_user_id=analyst_owner_id(current_user),
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVENT_NOT_FOUND", "message": f"Security event with ID {event_id} was not found."}
        )
    return event
