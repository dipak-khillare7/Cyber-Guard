from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.enums import RiskLevel, AlertStatus, IncidentStatus, ThreatType
from app.ml.inference.predictor import ThreatPredictor
from app.api.deps import require_analyst

router = APIRouter(prefix="/statistics", tags=["Statistics"])
predictor = ThreatPredictor()


@router.get("", response_model=dict)
def get_statistics(
    db: Session = Depends(get_db),
    _current_user=Depends(require_analyst),
):
    """
    Computes real, database-derived security metrics, threat distributions, and model metadata.
    """
    events_query = db.query(func.count(SecurityEvent.id))
    alerts_query = db.query(func.count(Alert.id))
    incidents_query = db.query(func.count(Incident.id))
    total_events = events_query.scalar() or 0
    total_alerts = alerts_query.scalar() or 0
    total_incidents = incidents_query.scalar() or 0

    suspicious_events_query = (
        db.query(func.count(func.distinct(SecurityEvent.id)))
        .join(Alert, SecurityEvent.id == Alert.event_id)
        .filter(Alert.threat_type != ThreatType.NORMAL.value)
    )
    suspicious_events = suspicious_events_query.scalar() or 0
    normal_events = max(total_events - suspicious_events, 0)

    active_alerts_query = db.query(func.count(Alert.id)).filter(
        Alert.status.in_([AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value])
    )
    active_alerts = active_alerts_query.scalar() or 0

    open_incidents_query = db.query(func.count(Incident.id)).filter(
        Incident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.IN_PROGRESS.value, IncidentStatus.INVESTIGATING.value])
    )
    open_incidents = open_incidents_query.scalar() or 0

    resolved_incidents_query = db.query(func.count(Incident.id)).filter(
        Incident.status.in_([IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value])
    )
    resolved_incidents = resolved_incidents_query.scalar() or 0

    critical_query = db.query(func.count(Alert.id)).filter(
        Alert.risk_level == RiskLevel.CRITICAL.value
    )
    high_query = db.query(func.count(Alert.id)).filter(
        Alert.risk_level == RiskLevel.HIGH.value
    )
    critical_threats = critical_query.scalar() or 0

    high_threats = high_query.scalar() or 0

    # Group alerts by threat_type
    threat_type_query = db.query(Alert.threat_type, func.count(Alert.id))
    threat_type_counts = threat_type_query.group_by(Alert.threat_type).all()
    threats_by_type = {t_type: count for t_type, count in threat_type_counts if t_type}

    # Group alerts by risk_level
    severity_query = db.query(Alert.risk_level, func.count(Alert.id))
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
