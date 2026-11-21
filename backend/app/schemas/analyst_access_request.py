from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr


class AnalystAccessRequestRead(BaseModel):
    id: int
    requester_user_id: int
    status: Literal["PENDING", "APPROVED", "REJECTED"]
    requested_at: datetime
    reviewed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AnalystAccessRequestAdminRead(AnalystAccessRequestRead):
    username: str
    email: EmailStr
    full_name: Optional[str] = None


class AnalystAccessRequestList(BaseModel):
    items: list[AnalystAccessRequestAdminRead]
    total: int


class AnalystAccessRequestDecision(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
