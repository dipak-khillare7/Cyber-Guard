from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timezone
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate
from app.core.logging import logger


class EventService:
    """
    Business logic for storing and querying Security Events.
    """

    @staticmethod
    def create_event(
        db: Session,
        event_in: SecurityEventCreate,
        owner_user_id: Optional[int] = None,
    ) -> SecurityEvent:
        db_event = SecurityEvent(
            owner_user_id=owner_user_id,
            timestamp=event_in.timestamp or datetime.now(timezone.utc),
            source_ip=event_in.source_ip,
            destination_ip=event_in.destination_ip,
            source_port=event_in.source_port,
            destination_port=event_in.destination_port,
            protocol=event_in.protocol.upper() if event_in.protocol else "TCP",
            duration=event_in.duration,
            packet_count=event_in.packet_count,
            byte_count=event_in.byte_count,
            event_type=event_in.event_type.value if hasattr(event_in.event_type, "value") else str(event_in.event_type),
            raw_data=event_in.raw_data,
            created_at=datetime.now(timezone.utc)
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        logger.info(f"Created SecurityEvent ID {db_event.id} ({db_event.event_type})")
        return db_event

    @staticmethod
    def get_event_by_id(
        db: Session,
        event_id: int,
        owner_user_id: Optional[int] = None,
    ) -> Optional[SecurityEvent]:
        query = db.query(SecurityEvent).filter(SecurityEvent.id == event_id)
        if owner_user_id is not None:
            query = query.filter(SecurityEvent.owner_user_id == owner_user_id)
        return query.first()

    @staticmethod
    def list_events(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> Tuple[List[SecurityEvent], int]:
        query = db.query(SecurityEvent)
        if owner_user_id is not None:
            query = query.filter(SecurityEvent.owner_user_id == owner_user_id)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type.upper())
        total = query.count()
        events = query.order_by(desc(SecurityEvent.id)).offset(skip).limit(limit).all()
        return events, total
