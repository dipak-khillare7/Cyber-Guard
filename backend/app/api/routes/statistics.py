from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.enums import RiskLevel, AlertStatus, IncidentStatus, ThreatType
from app.ml.inference.predictor import ThreatPredictor
from app.api.deps import get_current_user, get_data_owner_id

router = APIRouter(prefix="/statistics", tags=["Statistics"])
predictor = ThreatPredictor()


@router.get("", response_model=dict)
def get_statistics(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Computes real, database-derived security metrics, threat distributions, and model metadata.
    """
    owner_user_id = get_data_owner_id(current_user)
    events_query = db.query(func.count(SecurityEvent.id))
    alerts_query = db.query(func.count(Alert.id))
    incidents_query = db.query(func.count(Incident.id))
    if owner_user_id is not None:
        events_query = events_query.filter(SecurityEvent.owner_user_id == owner_user_id)
        alerts_query = alerts_query.filter(Alert.owner_user_id == owner_user_id)
        incidents_query = incidents_query.filter(Incident.owner_user_id == owner_user_id)
    total_events = events_query.scalar() or 0
    total_alerts = alerts_query.scalar() or 0
    total_incidents = incidents_query.scalar() or 0

    suspicious_events_query = (
        db.query(func.count(func.distinct(SecurityEvent.id)))
        .join(Alert, SecurityEvent.id == Alert.event_id)
        .filter(Alert.threat_type != ThreatType.NORMAL.value)
    )
    if owner_user_id is not None:
        suspicious_events_query = suspicious_events_query.filter(
            SecurityEvent.owner_user_id == owner_user_id
        )
    suspicious_events = suspicious_events_query.scalar() or 0
    normal_events = max(total_events - suspicious_events, 0)

    active_alerts_query = db.query(func.count(Alert.id)).filter(
        Alert.status.in_([AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value])
    )
    if owner_user_id is not None:
        active_alerts_query = active_alerts_query.filter(Alert.owner_user_id == owner_user_id)
    active_alerts = active_alerts_query.scalar() or 0

    open_incidents_query = db.query(func.count(Incident.id)).filter(
        Incident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.IN_PROGRESS.value, IncidentStatus.INVESTIGATING.value])
    )
    if owner_user_id is not None:
        open_incidents_query = open_incidents_query.filter(Incident.owner_user_id == owner_user_id)
    open_incidents = open_incidents_query.scalar() or 0

    resolved_incidents_query = db.query(func.count(Incident.id)).filter(
        Incident.status.in_([IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value])
    )
    if owner_user_id is not None:
        resolved_incidents_query = resolved_incidents_query.filter(
            Incident.owner_user_id == owner_user_id
        )
    resolved_incidents = resolved_incidents_query.scalar() or 0

    critical_query = db.query(func.count(Alert.id)).filter(
        Alert.risk_level == RiskLevel.CRITICAL.value
    )
    high_query = db.query(func.count(Alert.id)).filter(
        Alert.risk_level == RiskLevel.HIGH.value
    )
    if owner_user_id is not None:
        critical_query = critical_query.filter(Alert.owner_user_id == owner_user_id)
        high_query = high_query.filter(Alert.owner_user_id == owner_user_id)
    critical_threats = critical_query.scalar() or 0

    high_threats = high_query.scalar() or 0

    # Group alerts by threat_type
    threat_type_query = db.query(Alert.threat_type, func.count(Alert.id))
    if owner_user_id is not None:
        threat_type_query = threat_type_query.filter(Alert.owner_user_id == owner_user_id)
    threat_type_counts = threat_type_query.group_by(Alert.threat_type).all()
    threats_by_type = {t_type: count for t_type, count in threat_type_counts if t_type}

    # Group alerts by risk_level
    severity_query = db.query(Alert.risk_level, func.count(Alert.id))
    if owner_user_id is not None:
        severity_query = severity_query.filter(Alert.owner_user_id == owner_user_id)
    severity_counts = severity_query.group_by(Alert.risk_level).all()
    threats_by_severity = {
        RiskLevel.LOW.value: 0,
        RiskLevel.MEDIUM.value: 0,
        RiskLevel.HIGH.value: 0,
        RiskLevel.CRITICAL.value: 0
    }
    for sev, count in severity_counts:
        if sev in threats_by_severity:
            threats_by_severity[sev] = count

    model_meta = predictor.metadata or {}

    return {
        "success": True,
        "data": {
            "total_events": total_events,
            "normal_events": normal_events,
            "suspicious_events": suspicious_events,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "high_threats": high_threats,
            "critical_threats": critical_threats,
            "threats_by_type": threats_by_type,
            "threats_by_severity": threats_by_severity,
            "model_metadata": {
                "name": model_meta.get("model_name", "HistGradientBoosting"),
                "version": model_meta.get("model_version", "1.0.0"),
                "dataset": model_meta.get("dataset", "CIC-IDS2017 Benchmark Subset"),
                "metrics": model_meta.get("metrics", {})
            }
        }
    }
