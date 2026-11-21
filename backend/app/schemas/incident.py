from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import ThreatType, RiskLevel, IncidentStatus
from app.schemas.response_action import ResponseActionRead


class IncidentBase(BaseModel):
    alert_id: Optional[int] = Field(default=None)
    threat_type: ThreatType = Field(..., description="Threat type associated with incident")
    severity: RiskLevel = Field(..., description="Incident severity level")
    description: str = Field(..., min_length=3)
    status: IncidentStatus = Field(default=IncidentStatus.OPEN)
    assigned_to: Optional[str] = Field(default=None)


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None


class IncidentRead(IncidentBase):
    id: int
    created_at: datetime
    resolved_at: Optional[datetime] = None
    response_actions: List[ResponseActionRead] = []

    model_config = ConfigDict(from_attributes=True)
