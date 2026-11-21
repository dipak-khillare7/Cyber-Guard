from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database.connection import Base


def utc_now():
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    """
    ORM Model for collected Security/Network Events.
    """
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)      # IPv4 or IPv6
    destination_ip = Column(String(45), nullable=True, index=True) # IPv4 or IPv6
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True, index=True)       # TCP, UDP, ICMP, HTTP, etc.
    duration = Column(Float, nullable=True)                        # Connection duration in seconds
    packet_count = Column(Integer, nullable=True)
    byte_count = Column(Integer, nullable=True)
    event_type = Column(String(50), default="NETWORK", nullable=False, index=True)
    raw_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")
