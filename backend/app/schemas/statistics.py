from typing import Dict
from pydantic import BaseModel, Field


class StatisticsRead(BaseModel):
    total_events: int = Field(default=0, ge=0)
    total_alerts: int = Field(default=0, ge=0)
    total_incidents: int = Field(default=0, ge=0)
    critical_threats: int = Field(default=0, ge=0)
    threats_by_type: Dict[str, int] = Field(default_factory=dict)
    threats_by_severity: Dict[str, int] = Field(default_factory=dict)
