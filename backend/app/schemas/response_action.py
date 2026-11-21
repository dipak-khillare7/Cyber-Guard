from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import ActionType, ActionStatus


class ResponseActionBase(BaseModel):
    incident_id: int
    action_type: ActionType
    action_status: ActionStatus = Field(default=ActionStatus.SIMULATED)
    description: str = Field(..., min_length=3)


class ResponseActionCreate(BaseModel):
    incident_id: int
    action_type: ActionType
    description: Optional[str] = Field(default="Simulated response action executed")


class ResponseActionRead(ResponseActionBase):
    id: int
    executed_at: datetime

    model_config = ConfigDict(from_attributes=True)
