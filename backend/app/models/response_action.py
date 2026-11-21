from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database.connection import Base


def utc_now():
    return datetime.now(timezone.utc)


class ResponseAction(Base):
    """
    ORM Model for Simulated/Executed Security Response Actions.
    """
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False, index=True)   # LOG, ALERT, SIMULATED_BLOCK, etc.
    action_status = Column(String(20), default="SIMULATED", nullable=False, index=True) # PENDING, EXECUTED, FAILED, SIMULATED
    description = Column(Text, nullable=False)
    executed_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="response_actions")
