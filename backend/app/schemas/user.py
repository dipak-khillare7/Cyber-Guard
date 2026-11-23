from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional
from datetime import datetime
from app.models.user import UserRole

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="User email address")
    role: UserRole = Field(default=UserRole.VIEWER, description="Role-based access level")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128, description="User password (min 8 chars)")

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_update_fields(self):
        if not self.model_fields_set:
            raise ValueError("At least one user field must be provided.")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("User update fields cannot be null.")
        return self

    @field_validator("password")
    @classmethod
    def validate_update_password_length(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be no more than 72 UTF-8 bytes.")
        return value

class UserResponse(UserBase):
    id: int
    full_name: Optional[str] = None
    is_active: bool
    email_verified: bool = True
    permissions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None

    @model_validator(mode="after")
    def add_role_permissions(self):
        if self.role == UserRole.VIEWER:
            self.permissions = []
        elif self.role == UserRole.ANALYST:
            self.permissions = ["soc:analyst"]
        elif self.role == UserRole.ADMIN:
            self.permissions = ["soc:analyst", "soc:admin"]
        return self

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username or email")
    password: str = Field(..., min_length=1, description="Password")


class RegistrationRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=72)
    confirm_password: str = Field(..., min_length=1, max_length=72)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Full name is required.")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_registration_password(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be no more than 72 UTF-8 bytes.")
        if not any(char.islower() for char in value):
            raise ValueError("Password must include a lowercase letter.")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must include an uppercase letter.")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must include a number.")
        if not any(not char.isalnum() for char in value):
            raise ValueError("Password must include a special character.")
        return value


class VerificationRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., pattern=r"^[0-9]{6}$")


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class AuthMessageResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
