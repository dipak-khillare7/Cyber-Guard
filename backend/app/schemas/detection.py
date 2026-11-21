from datetime import datetime
from typing import Optional, Dict, Any, Generic, TypeVar
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.core.security import is_valid_ip, is_valid_port, normalize_network_protocol
from app.schemas.enums import EventType, ThreatType, RiskLevel, ActionType, ActionStatus

T = TypeVar('T')


class ApiResponse(BaseModel, Generic[T]):
    """Standardized API response container."""
    success: bool = True
    data: Optional[T] = None
    error: Optional[Dict[str, Any]] = None


class AnalyzeEventRequest(BaseModel):
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp (UTC)")
    source_ip: Optional[str] = Field(default="192.168.1.100", max_length=45, json_schema_extra={"example": "192.168.1.100"})
    destination_ip: Optional[str] = Field(default="10.0.0.1", max_length=45, json_schema_extra={"example": "10.0.0.1"})
    source_port: Optional[int] = Field(default=54321, ge=0, le=65535, json_schema_extra={"example": 54321})
    destination_port: Optional[int] = Field(default=80, ge=0, le=65535, json_schema_extra={"example": 80})
    protocol: Optional[str] = Field(default="TCP", max_length=20, json_schema_extra={"example": "TCP"})
    duration: Optional[float] = Field(default=1000.0, ge=0.0, le=86_400_000.0, allow_inf_nan=False, description="Flow duration in milliseconds")
    packet_count: Optional[int] = Field(default=10, ge=0, le=10_000_000, description="Total forward packets")
    byte_count: Optional[int] = Field(default=500, ge=0, le=1_000_000_000, description="Total length of forward packets")
    syn_flag_count: Optional[int] = Field(default=0, ge=0, le=10_000_000)
    ack_flag_count: Optional[int] = Field(default=1, ge=0, le=10_000_000)
    event_type: EventType = Field(default=EventType.NETWORK)
    raw_data: Optional[str] = Field(default=None, max_length=4096, description="Raw flow payload or reference log")

    @field_validator("source_ip", "destination_ip")
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if not is_valid_ip(v):
                raise ValueError("Invalid IP address.")
        return v

    @field_validator("source_port", "destination_port")
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            if not is_valid_port(v):
                raise ValueError("Port number must be between 0 and 65535.")
        return v

    @field_validator("protocol", mode="before")
    def validate_protocol(cls, v: Optional[str]) -> Optional[str]:
        return normalize_network_protocol(v)


class DetectionPrediction(BaseModel):
    threat_type: str
    confidence: float
    probabilities: Dict[str, float] = Field(default_factory=dict)


class DetectionRisk(BaseModel):
    level: str
    score: float
    reason: str


class DetectionAlertInfo(BaseModel):
    generated: bool
    alert_id: Optional[int] = None
    status: Optional[str] = None


class DetectionIncidentInfo(BaseModel):
    created: bool
    incident_id: Optional[int] = None
    status: Optional[str] = None


class DetectionResponseInfo(BaseModel):
    action_type: Optional[str] = None
    action_status: Optional[str] = None
    description: Optional[str] = None


class DetectionModelInfo(BaseModel):
    name: str
    version: str
    processing_time_ms: float


class DetectionResponseData(BaseModel):
    event_id: int
    prediction: DetectionPrediction
    risk: DetectionRisk
    alert: DetectionAlertInfo
    incident: DetectionIncidentInfo
    response: DetectionResponseInfo
    model: DetectionModelInfo

    model_config = ConfigDict(from_attributes=True)
