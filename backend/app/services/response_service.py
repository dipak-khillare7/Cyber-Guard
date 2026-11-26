from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.response_action import ResponseAction
from app.models.incident import Incident
from app.schemas.enums import ActionType, ActionStatus, RiskLevel, ThreatType
from app.schemas.response_action import ResponseActionCreate
from app.core.logging import logger


class ResponseService:
    """
    Response Engine executing safe, simulated mitigation policy decisions.
    """

    @staticmethod
    def select_response_policy(risk_level: RiskLevel, threat_type: ThreatType) -> Tuple[ActionType, str]:
        """
        Determines the recommended response policy based on risk level and threat category.
        """
        risk_str = risk_level.value if hasattr(risk_level, "value") else str(risk_level)
        threat_str = threat_type.value if hasattr(threat_type, "value") else str(threat_type)

        if risk_str == RiskLevel.CRITICAL.value:
            action_type = ActionType.SIMULATED_ISOLATION
            desc = f"SIMULATED ISOLATION: Flagged target host for virtual isolation due to CRITICAL '{threat_str}' detection."
        elif risk_str == RiskLevel.HIGH.value:
            action_type = ActionType.SIMULATED_BLOCK
            desc = f"SIMULATED BLOCK: Virtual firewall buffer rule generated for HIGH risk '{threat_str}'."
        elif risk_str == RiskLevel.MEDIUM.value:
            action_type = ActionType.ALERT
            desc = f"ALERT: High priority security operations notification dispatched for '{threat_str}'."
        else:
            action_type = ActionType.LOG
            desc = f"LOG: Event details recorded to audit log for routine monitoring."

        return action_type, desc

    @staticmethod
    def execute_simulated_action(
        db: Session,
        action_in: ResponseActionCreate,
        owner_user_id: Optional[int] = None,
    ) -> ResponseAction:
        """
        Simulates and records a response action for a security incident.
        """
        incident_query = db.query(Incident).filter(Incident.id == action_in.incident_id)
        if owner_user_id is not None:
            incident_query = incident_query.filter(Incident.owner_user_id == owner_user_id)
        incident = incident_query.first()
        if not incident:
            logger.warning(f"Response action requested for non-existent incident ID {action_in.incident_id}")
            raise ValueError(f"Incident with ID {action_in.incident_id} not found.")

        desc = action_in.description or f"Simulated execution of {action_in.action_type.value}"

        db_action = ResponseAction(
            owner_user_id=incident.owner_user_id,
            incident_id=incident.id,
            action_type=action_in.action_type.value if hasattr(action_in.action_type, "value") else str(action_in.action_type),
            action_status=ActionStatus.SIMULATED.value,
            description=desc,
            executed_at=datetime.now(timezone.utc)
        )

        db.add(db_action)
        db.commit()
        db.refresh(db_action)

        logger.info(
            f"[SIMULATION MODE] Recorded safe action '{db_action.action_type}' "
            f"for Incident ID {incident.id}: {desc}"
        )

        return db_action

    @staticmethod
    def get_actions_by_incident(
        db: Session,
        incident_id: int,
        owner_user_id: Optional[int] = None,
    ):
        query = db.query(ResponseAction).filter(ResponseAction.incident_id == incident_id)
        if owner_user_id is not None:
            query = query.filter(ResponseAction.owner_user_id == owner_user_id)
        return query.all()
