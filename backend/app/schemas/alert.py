from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import ThreatType, RiskLevel, AlertStatus


class AlertBase(BaseModel):
    event_id: Optional[int] = Field(default=None)
    threat_type: ThreatType = Field(..., description="Enumerated threat category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score (0.0 - 1.0)")
    risk_level: RiskLevel = Field(..., description="Risk/Severity level (LOW, MEDIUM, HIGH, CRITICAL)")
    message: str = Field(..., min_length=3, description="Descriptive alert notification message")
    status: AlertStatus = Field(default=AlertStatus.NEW)


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    status: AlertStatus


class AlertRead(AlertBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
