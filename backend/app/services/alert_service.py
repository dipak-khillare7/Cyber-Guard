from typing import List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.schemas.alert import AlertCreate, AlertUpdate
from app.schemas.enums import AlertStatus
from app.core.logging import logger


class AlertService:
    """
    Business logic for creating, deduplicating, querying, and updating Security Alerts.
    """

    @staticmethod
    def create_alert(db: Session, alert_in: AlertCreate, source_ip: Optional[str] = None) -> Tuple[Alert, bool]:
        """
        Generates a new Alert or deduplicates against recent active alerts from the same source IP.

        :return: Tuple of (Alert, generated_boolean)
        """
        threat_str = alert_in.threat_type.value if hasattr(alert_in.threat_type, "value") else str(alert_in.threat_type)
        risk_str = alert_in.risk_level.value if hasattr(alert_in.risk_level, "value") else str(alert_in.risk_level)
        status_str = alert_in.status.value if hasattr(alert_in.status, "value") else str(alert_in.status)

        now = datetime.now(timezone.utc)
        dedup_window = now - timedelta(minutes=5)
        owner_user_id = None
        if alert_in.event_id is not None:
            owner_user_id = db.query(SecurityEvent.owner_user_id).filter(
                SecurityEvent.id == alert_in.event_id
            ).scalar()

        # Basic alert deduplication check: same source_ip + same threat_type in 5 min window
        if source_ip:
            recent_alert = (
                db.query(Alert)
                .join(SecurityEvent, Alert.event_id == SecurityEvent.id)
                .filter(
                    SecurityEvent.source_ip == source_ip,
                    SecurityEvent.owner_user_id == owner_user_id,
                    Alert.threat_type == threat_str,
                    Alert.created_at >= dedup_window,
                    Alert.status.in_([AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value])
                )
                .order_by(desc(Alert.id))
                .first()
            )

            if recent_alert:
                logger.info(f"[DEDUPLICATION] Deduplicated alert for source IP {source_ip} (Existing Alert ID {recent_alert.id})")
                recent_alert.message = f"{recent_alert.message} (Repeated activity detected at {now.strftime('%H:%M:%S')})"
                db.commit()
                db.refresh(recent_alert)
                return recent_alert, False

        # Create new Alert record
        db_alert = Alert(
            owner_user_id=owner_user_id,
            event_id=alert_in.event_id,
            threat_type=threat_str,
            confidence=alert_in.confidence,
            risk_level=risk_str,
            message=alert_in.message,
            status=status_str,
            created_at=now
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        logger.info(f"Generated Alert ID {db_alert.id} - Threat: {db_alert.threat_type}, Level: {db_alert.risk_level}")
        return db_alert, True

    @staticmethod
    def get_alert_by_id(
        db: Session,
        alert_id: int,
        owner_user_id: Optional[int] = None,
    ) -> Optional[Alert]:
        query = db.query(Alert).filter(Alert.id == alert_id)
        if owner_user_id is not None:
            query = query.filter(Alert.owner_user_id == owner_user_id)
        return query.first()

    @staticmethod
    def list_alerts(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        threat_type: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> Tuple[List[Alert], int]:
        query = db.query(Alert)
        if owner_user_id is not None:
            query = query.filter(Alert.owner_user_id == owner_user_id)
        if risk_level:
            query = query.filter(Alert.risk_level == risk_level.upper())
        if status:
            query = query.filter(Alert.status == status.upper())
        if threat_type:
            query = query.filter(Alert.threat_type.ilike(f"%{threat_type}%"))
        total = query.count()
        alerts = query.order_by(desc(Alert.id)).offset(skip).limit(limit).all()
        return alerts, total

    @staticmethod
    def update_alert_status(db: Session, alert_id: int, alert_update: AlertUpdate) -> Optional[Alert]:
        db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if db_alert:
            db_alert.status = alert_update.status.value if hasattr(alert_update.status, "value") else str(alert_update.status)
            db.commit()
            db.refresh(db_alert)
            logger.info(f"Updated Alert ID {alert_id} status to {db_alert.status}")
        return db_alert
