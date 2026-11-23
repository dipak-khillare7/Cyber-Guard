import secrets
import warnings
from typing import List, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized Application Configuration loaded from environment variables or .env file.
    """
    APP_NAME: str = "AI Cybersecurity Threat Detection & Response System"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database Configuration (Supports MySQL pymysql and SQLite)
    DATABASE_URL: str = "sqlite:///./cyber_security.db"

    # Security Configuration
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480 # 8 hours

    # Initial Admin Seed Credentials
    ADMIN_USERNAME: str = "admin"
    ADMIN_INITIAL_PASSWORD: str = ""
    ADMIN_EMAIL: str = "admin@cyberguard.soc"

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = "Cyber Guard"

    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_security_configuration(self):
        is_production = self.APP_ENV.strip().lower() == "production"

        if not self.SECRET_KEY.strip():
            if is_production:
                raise ValueError("SECRET_KEY must be configured in production.")
            self.SECRET_KEY = secrets.token_urlsafe(32)
            warnings.warn(
                "SECRET_KEY is unset; a temporary key was generated for this non-production process.",
                RuntimeWarning,
                stacklevel=2,
            )
        elif is_production and len(self.SECRET_KEY.encode("utf-8")) < 32:
            raise ValueError("SECRET_KEY must be at least 32 bytes in production.")

        if is_production:
            password_bytes = self.ADMIN_INITIAL_PASSWORD.encode("utf-8")
            if len(password_bytes) < 12 or len(password_bytes) > 72:
                raise ValueError(
                    "ADMIN_INITIAL_PASSWORD must be between 12 and 72 UTF-8 bytes in production."
                )

        return self

    MODEL_DIR: str = "app/ml/models"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
