from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.core.security import is_valid_ip, is_valid_port, normalize_network_protocol
from app.schemas.enums import EventType


class SecurityEventBase(BaseModel):
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp (defaults to server current UTC time)")
    source_ip: Optional[str] = Field(default=None, max_length=45, json_schema_extra={"example": "192.168.1.100"})
    destination_ip: Optional[str] = Field(default=None, max_length=45, json_schema_extra={"example": "10.0.0.1"})
    source_port: Optional[int] = Field(default=None, ge=0, le=65535, json_schema_extra={"example": 443})
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535, json_schema_extra={"example": 80})
    protocol: Optional[str] = Field(default="TCP", max_length=20, json_schema_extra={"example": "TCP"})
    duration: Optional[float] = Field(default=0.0, ge=0.0, le=86_400_000.0, allow_inf_nan=False, description="Duration in seconds")
    packet_count: Optional[int] = Field(default=1, ge=0, le=10_000_000)
    byte_count: Optional[int] = Field(default=64, ge=0, le=1_000_000_000)
    event_type: EventType = Field(default=EventType.NETWORK)
    raw_data: Optional[str] = Field(default=None, max_length=4096, description="Raw event log or payload reference")

    @field_validator("source_ip", "destination_ip")
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if not is_valid_ip(v):
                raise ValueError("Invalid IP address.")
        return v

    @field_validator("source_port", "destination_port")
    def validate_port_number(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            if not is_valid_port(v):
                raise ValueError("Port number must be between 0 and 65535.")
        return v

    @field_validator("protocol", mode="before")
    def validate_protocol(cls, v: Optional[str]) -> Optional[str]:
        return normalize_network_protocol(v)


class SecurityEventCreate(SecurityEventBase):
    pass


class SecurityEventRead(SecurityEventBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
