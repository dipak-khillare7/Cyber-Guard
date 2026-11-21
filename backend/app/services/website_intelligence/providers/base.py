from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class ProviderStatus(str, Enum):
    FOUND = "FOUND"
    NO_RECORD = "NO_RECORD"
    NOT_QUERIED = "NOT_QUERIED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    INVALID_INDICATOR = "INVALID_INDICATOR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    PROVIDER_FORBIDDEN = "PROVIDER_FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ThreatIntelResult:
    provider: str
    indicator_type: str
    indicator_hash: Optional[str]
    status: ProviderStatus
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    provider_http_status: Optional[int] = None
    retry_after_seconds: Optional[int] = None
    data: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[str] = None
