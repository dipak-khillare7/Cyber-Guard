from typing import Literal, Optional
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database import get_db
from app.schemas.detection import AnalyzeEventRequest, DetectionResponseData, ApiResponse
from app.services.detection_service import DetectionService
from app.services.audit_service import AuditService
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.schemas.enums import ThreatType, RiskLevel
from app.api.deps import (
    enforce_ingestion_ip_rate_limit,
    get_current_user,
    get_data_owner_id,
    require_analyst,
)
from app.core.rate_limit import enforce_rate_limit

from app.core.security import is_valid_ip, is_valid_port, format_iso_utc

router = APIRouter(prefix="/detection", tags=["AI Threat Detection"])


@router.post("/analyze", response_model=ApiResponse[DetectionResponseData], status_code=status.HTTP_200_OK)
def analyze_security_event(
    analyze_in: AnalyzeEventRequest,
    request: Request,
    db: Session = Depends(get_db),
    _ingestion_ip_limit: None = Depends(enforce_ingestion_ip_rate_limit),
    current_user = Depends(require_analyst)
):
    """
    Ingests and analyzes a security event through the AI Threat Detection & Risk Pipeline.
    Integrates system integrity check and audit tracking.
    """
    enforce_rate_limit(
        db,
        f"ingestion:user:{current_user.id}",
        limit=30,
        window_seconds=60,
        action="event ingestion",
    )
    try:
        result = DetectionService.analyze_event(
            db,
            analyze_in,
            owner_user_id=current_user.id,
        )

        ip_addr = request.client.host if request.client else "unknown"
        AuditService.log_event(
            db=db,
            action="EVENT_ANALYZED",
            user_id=current_user.id,
            username=current_user.username,
            resource_type="DETECTION",
            resource_id=str(result.event_id),
            ip_address=ip_addr,
            status="SUCCESS",
            metadata={
                "threat_type": result.prediction.threat_type,
                "confidence": result.prediction.confidence,
                "risk_score": result.risk.score,
                "risk_level": result.risk.level
            }
        )

        return ApiResponse(success=True, data=result)
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "DETECTION_ENGINE_UNAVAILABLE",
                "message": "The detection service is temporarily unavailable.",
            },
        )
    except Exception as err:
        from app.core.logging import logger
        logger.error("Detection request failed (%s)", type(err).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "DETECTION_FAILED",
                "message": "The detection request could not be processed.",
            },
        ) from err


@router.get("/history", response_model=dict)
def get_detection_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    scope: Literal["role", "own"] = Query("role"),
    threat_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Retrieves paginated historical detection analyses with filtering support.
    """
    query = db.query(SecurityEvent).outerjoin(Alert, SecurityEvent.id == Alert.event_id)
    owner_user_id = (
        current_user.id if scope == "own" else get_data_owner_id(current_user)
    )
    if owner_user_id is not None:
        query = query.filter(SecurityEvent.owner_user_id == owner_user_id)

    if threat_type:
        query = query.filter(Alert.threat_type == threat_type.upper())
    if risk_level:
        query = query.filter(Alert.risk_level == risk_level.upper())
    if start_date:
        query = query.filter(SecurityEvent.timestamp >= start_date)
    if end_date:
        query = query.filter(SecurityEvent.timestamp <= end_date)

    total = query.count()
    events = query.order_by(desc(SecurityEvent.id)).offset(skip).limit(limit).all()

    items = []
    for ev in events:
        associated_alert = ev.alerts[0] if ev.alerts else None
        items.append({
            "event_id": ev.id,
            "timestamp": format_iso_utc(ev.timestamp),
            "source_ip": ev.source_ip,
            "destination_ip": ev.destination_ip,
            "destination_port": ev.destination_port,
            "duration": ev.duration,
            "packet_count": ev.packet_count,
            "byte_count": ev.byte_count,
            "event_type": ev.event_type,
            "raw_data": ev.raw_data,
            "detected_threat": associated_alert.threat_type if associated_alert else ThreatType.NORMAL.value,
            "risk_level": associated_alert.risk_level if associated_alert else RiskLevel.LOW.value,
            "confidence": associated_alert.confidence if associated_alert else None,
            "alert_id": associated_alert.id if associated_alert else None,
            "message": associated_alert.message if associated_alert else "Normal flow recorded"
        })

    return {
        "success": True,
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": items
    }


@router.get("/trend", response_model=dict)
def get_detection_trend(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Computes time-series detection trends grouped by time window in IST (Asia/Kolkata).
    """
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc.astimezone(ist_tz)
    cutoff_naive = (now_utc - timedelta(hours=hours)).replace(tzinfo=None)

    query = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff_naive)
    owner_user_id = get_data_owner_id(current_user)
    if owner_user_id is not None:
        query = query.filter(SecurityEvent.owner_user_id == owner_user_id)
    events = query.all()

    # Aggregate events by IST hour label
    trend_buckets = {}
    for i in range(hours):
        h_time = now_ist - timedelta(hours=hours - 1 - i)
        label = h_time.strftime("%H:00")
        trend_buckets[label] = {"time": label, "total": 0, "threats": 0, "normal": 0}

    for ev in events:
        ev_dt = ev.timestamp
        if ev_dt is not None:
            if ev_dt.tzinfo is None:
                ev_dt = ev_dt.replace(tzinfo=timezone.utc)
            ev_ist = ev_dt.astimezone(ist_tz)
            label = ev_ist.strftime("%H:00")
        else:
            label = now_ist.strftime("%H:00")

        if label not in trend_buckets:
            trend_buckets[label] = {"time": label, "total": 0, "threats": 0, "normal": 0}

        trend_buckets[label]["total"] += 1
        has_threat = any(a.threat_type != ThreatType.NORMAL.value for a in ev.alerts)
        if has_threat:
            trend_buckets[label]["threats"] += 1
        else:
            trend_buckets[label]["normal"] += 1

    return {
        "success": True,
        "hours": hours,
        "timezone": "Asia/Kolkata",
        "trend": list(trend_buckets.values())
    }
