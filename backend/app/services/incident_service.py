from typing import List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from datetime import datetime, timezone
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.response_action import ResponseAction
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.schemas.enums import IncidentStatus, RiskLevel, ThreatType
from app.schemas.response_action import ResponseActionCreate
from app.services.response_service import ResponseService
from app.core.logging import logger


class IncidentService:
    """
    Business logic for storing, updating, and managing Security Incidents.
    """

    @staticmethod
    def create_incident(
        db: Session,
        incident_in: IncidentCreate,
        creator_user_id: Optional[int] = None,
        owner_user_id: Optional[int] = None,
    ) -> Incident:
        alert = None
        if incident_in.alert_id:
            alert_query = db.query(Alert).filter(Alert.id == incident_in.alert_id)
            if owner_user_id is not None:
                alert_query = alert_query.filter(Alert.owner_user_id == owner_user_id)
            alert = alert_query.first()
            if not alert:
                raise ValueError("Alert not found.")
        owner_user_id = alert.owner_user_id if alert else creator_user_id
        db_incident = Incident(
            owner_user_id=owner_user_id,
            alert_id=incident_in.alert_id,
            threat_type=incident_in.threat_type.value if hasattr(incident_in.threat_type, "value") else str(incident_in.threat_type),
            severity=incident_in.severity.value if hasattr(incident_in.severity, "value") else str(incident_in.severity),
            description=incident_in.description,
            status=incident_in.status.value if hasattr(incident_in.status, "value") else str(incident_in.status),
            assigned_to=incident_in.assigned_to,
            created_at=datetime.now(timezone.utc)
        )
        db.add(db_incident)
        db.commit()
        db.refresh(db_incident)
        # Auto-trigger response policy if severity is HIGH or CRITICAL
        sev_upper = (db_incident.severity or "").upper()
        if sev_upper in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
            try:
                try:
                    threat_enum = ThreatType(db_incident.threat_type)
                except Exception:
                    threat_enum = ThreatType.DOS_DDOS

                try:
                    risk_enum = RiskLevel(sev_upper)
                except Exception:
                    risk_enum = RiskLevel.HIGH

                act_type, act_desc = ResponseService.select_response_policy(risk_enum, threat_enum)
                res_in = ResponseActionCreate(
                    incident_id=db_incident.id,
                    action_type=act_type,
                    description=act_desc
                )
                ResponseService.execute_simulated_action(db, res_in)
            except Exception as err:
                logger.warning(
                    "Auto response action creation skipped for incident %s (%s)",
                    db_incident.id,
                    type(err).__name__,
                )

        return db_incident

    @staticmethod
    def get_incident_by_id(
        db: Session,
        incident_id: int,
        owner_user_id: Optional[int] = None,
    ) -> Optional[Incident]:
        response_actions = Incident.response_actions
        if owner_user_id is not None:
            response_actions = response_actions.and_(
                ResponseAction.owner_user_id == owner_user_id
            )
        query = (
            db.query(Incident)
            .options(joinedload(response_actions))
            .filter(Incident.id == incident_id)
        )
        if owner_user_id is not None:
            query = query.filter(Incident.owner_user_id == owner_user_id)
        return query.first()

    @staticmethod
    def list_incidents(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> Tuple[List[Incident], int]:
        response_actions = Incident.response_actions
        if owner_user_id is not None:
            response_actions = response_actions.and_(
                ResponseAction.owner_user_id == owner_user_id
            )
        query = db.query(Incident).options(joinedload(response_actions))
        if owner_user_id is not None:
            query = query.filter(Incident.owner_user_id == owner_user_id)
        if severity:
            query = query.filter(Incident.severity == severity.upper())
        if status:
            query = query.filter(Incident.status == status.upper())
        total = query.count()
        incidents = query.order_by(desc(Incident.id)).offset(skip).limit(limit).all()
        return incidents, total

    @staticmethod
    def update_incident(
        db: Session,
        incident_id: int,
        update_in: IncidentUpdate,
        owner_user_id: Optional[int] = None,
    ) -> Optional[Incident]:
        query = db.query(Incident).filter(Incident.id == incident_id)
        if owner_user_id is not None:
            query = query.filter(Incident.owner_user_id == owner_user_id)
        db_incident = query.first()
        if not db_incident:
            return None

        if update_in.status is not None:
            new_status = update_in.status.value if hasattr(update_in.status, "value") else str(update_in.status)
            db_incident.status = new_status
            if new_status in [IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value]:
                db_incident.resolved_at = datetime.now(timezone.utc)

        if update_in.assigned_to is not None:
            db_incident.assigned_to = update_in.assigned_to

        db.commit()
        db.refresh(db_incident)
        logger.info(f"Updated Incident ID {incident_id}: status={db_incident.status}, assigned={db_incident.assigned_to}")
        return db_incident
