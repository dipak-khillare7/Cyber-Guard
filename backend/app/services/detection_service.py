import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.detection import (
    AnalyzeEventRequest,
    DetectionResponseData,
    DetectionPrediction,
    DetectionRisk,
    DetectionAlertInfo,
    DetectionIncidentInfo,
    DetectionResponseInfo,
    DetectionModelInfo
)
from app.schemas.security_event import SecurityEventCreate
from app.schemas.alert import AlertCreate
from app.schemas.incident import IncidentCreate
from app.schemas.response_action import ResponseActionCreate
from app.schemas.enums import EventType, ThreatType, RiskLevel, AlertStatus, IncidentStatus
from app.services.event_service import EventService
from app.services.alert_service import AlertService
from app.services.incident_service import IncidentService
from app.services.risk_service import calculate_risk
from app.services.response_service import ResponseService
from app.ml.inference.predictor import ThreatPredictor
from app.core.logging import logger

# Initialize singleton ML Predictor
ml_predictor = ThreatPredictor()


def get_ml_predictor() -> ThreatPredictor:
    """Helper getter for ML predictor to allow reliable testing mocks."""
    return ml_predictor


class DetectionService:
    """
    Orchestration Engine executing end-to-end cybersecurity threat detection,
    risk evaluation, alert generation, incident creation, and response simulation.
    """

    @staticmethod
    def analyze_event(
        db: Session,
        request: AnalyzeEventRequest,
        owner_user_id: Optional[int] = None,
    ) -> DetectionResponseData:
        t_start = time.time()

        # 1. Store Raw Security Event in Database
        event_in = SecurityEventCreate(
            timestamp=request.timestamp or datetime.now(timezone.utc),
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            source_port=request.source_port,
            destination_port=request.destination_port,
            protocol=request.protocol,
            duration=request.duration,
            packet_count=request.packet_count,
            byte_count=request.byte_count,
            event_type=request.event_type,
            raw_data=request.raw_data
        )
        db_event = EventService.create_event(db, event_in, owner_user_id=owner_user_id)

        # 2. Feature Compatibility Layer: Extract ML Feature Dict
        feature_dict = {
            "Destination Port": request.destination_port or 80,
            "Flow Duration": request.duration or 1000.0,
            "Total Fwd Packets": request.packet_count or 10,
            "Total Backward Packets": max(1, int((request.packet_count or 10) * 0.8)),
            "Total Length of Fwd Packets": request.byte_count or 500,
            "Total Length of Bwd Packets": max(1, int((request.byte_count or 500) * 1.2)),
            "Flow Bytes/s": round((request.byte_count or 500) / ((request.duration or 1000.0) / 1000.0 + 1e-5), 2),
            "Flow Packets/s": round((request.packet_count or 10) / ((request.duration or 1000.0) / 1000.0 + 1e-5), 2),
            "SYN Flag Count": request.syn_flag_count if request.syn_flag_count is not None else 0,
            "ACK Flag Count": request.ack_flag_count if request.ack_flag_count is not None else 1
        }

        # 3. Call ML Predictor Inference Engine
        try:
            predictor = get_ml_predictor()
            pred_result = predictor.predict(feature_dict)
            predicted_threat_str = pred_result.get("predicted_threat", ThreatType.NORMAL.value)
            confidence_value = pred_result.get("confidence")
            if confidence_value is None:
                confidence = 0.0
            else:
                confidence = float(confidence_value)
            probabilities = pred_result.get("probabilities", {})
            model_version = pred_result.get("model_version", "1.0.0")
            model_name = getattr(predictor, "metadata", {}).get("model_name", "HistGradientBoosting")
        except Exception as e:
            logger.error("ML predictor inference failed (%s)", type(e).__name__)
            raise RuntimeError("ML Detection Engine unavailable.") from e

        processing_time_ms = round((time.time() - t_start) * 1000, 2)

        # Parse Threat Category
        try:
            predicted_threat = ThreatType(predicted_threat_str)
        except ValueError:
            predicted_threat = ThreatType.NORMAL

        # 4. Risk Engine Assessment
        risk_level, risk_score, risk_reason = calculate_risk(
            threat_type=predicted_threat,
            confidence=confidence,
            context={"destination_port": request.destination_port, "packet_count": request.packet_count}
        )

        # 5. Alert Engine Generation & Deduplication
        alert_generated = False
        alert_id = None
        alert_status = None

        if predicted_threat != ThreatType.NORMAL or risk_level != RiskLevel.LOW:
            alert_in = AlertCreate(
                event_id=db_event.id,
                threat_type=predicted_threat,
                confidence=confidence,
                risk_level=risk_level,
                message=risk_reason,
                status=AlertStatus.NEW
            )
            db_alert, is_new = AlertService.create_alert(db, alert_in, source_ip=request.source_ip)
            alert_generated = True
            alert_id = db_alert.id
            alert_status = db_alert.status

        # 6. Incident Engine Creation (Triggered for HIGH or CRITICAL risk)
        incident_created = False
        incident_id = None
        incident_status = None

        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] and alert_id:
            incident_in = IncidentCreate(
                alert_id=alert_id,
                threat_type=predicted_threat,
                severity=risk_level,
                description=f"Auto-escalated Incident for detected '{predicted_threat.value}' (Risk: {risk_level.value}). Reason: {risk_reason}",
                status=IncidentStatus.OPEN
            )
            db_incident = IncidentService.create_incident(
                db,
                incident_in,
                creator_user_id=owner_user_id,
            )
            incident_created = True
            incident_id = db_incident.id
            incident_status = db_incident.status

        # 7. Safe Simulation Response Policy
        action_type, action_desc = ResponseService.select_response_policy(risk_level, predicted_threat)
        action_status = "NONE"

        if incident_id:
            existing_actions = ResponseService.get_actions_by_incident(db, incident_id)
            if existing_actions:
                action_status = existing_actions[0].action_status
            else:
                response_in = ResponseActionCreate(
                    incident_id=incident_id,
                    action_type=action_type,
                    description=action_desc
                )
                db_action = ResponseService.execute_simulated_action(db, response_in)
                action_status = db_action.action_status

        logger.info(
            f"[DETECTION COMPLETE] Event #{db_event.id} -> Threat: {predicted_threat.value} "
            f"(Confidence: {confidence:.2f}, Risk: {risk_level.value}, Time: {processing_time_ms}ms)"
        )

        return DetectionResponseData(
            event_id=db_event.id,
            prediction=DetectionPrediction(
                threat_type=predicted_threat.value,
                confidence=confidence,
                probabilities=probabilities
            ),
            risk=DetectionRisk(
                level=risk_level.value,
                score=risk_score,
                reason=risk_reason
            ),
            alert=DetectionAlertInfo(
                generated=alert_generated,
                alert_id=alert_id,
                status=alert_status
            ),
            incident=DetectionIncidentInfo(
                created=incident_created,
                incident_id=incident_id,
                status=incident_status
            ),
            response=DetectionResponseInfo(
                action_type=action_type.value,
                action_status=action_status,
                description=action_desc
            ),
            model=DetectionModelInfo(
                name=model_name,
                version=model_version,
                processing_time_ms=processing_time_ms
            )
        )
