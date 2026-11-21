import json
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator


class WebsiteAssessmentCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    consent_to_share: bool

    @field_validator("consent_to_share")
    @classmethod
    def require_external_sharing_consent(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Explicit consent is required for external website analysis.")
        return value


class WebsiteAssessmentRead(BaseModel):
    id: int
    url_origin: Optional[str] = None
    target_domain: str
    scheme: str
    risk_level: str
    risk_score: Optional[float] = None
    risk_explanation: str
    analysis_status: str = "LEGACY"
    engine_version: str = "legacy"
    scoring_version: str = "legacy"
    provider: str = "VIRUSTOTAL"
    provider_status: str
    provider_reputation: Optional[int] = None
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    undetected_count: Optional[int] = None
    harmless_count: Optional[int] = None
    vendor_count: Optional[int] = None
    provider_analysis_at: Optional[datetime] = None
    provider_retrieved_at: datetime
    provider_http_status: Optional[int] = None
    dns_status: str = "NOT_CHECKED"
    dns_findings: dict = Field(
        default_factory=dict,
        validation_alias="dns_findings_json",
        serialization_alias="dns_findings",
    )
    ssl_status: str = "NOT_CHECKED"
    ssl_findings: dict = Field(
        default_factory=dict,
        validation_alias="ssl_findings_json",
        serialization_alias="ssl_findings",
    )
    evidence: list[dict] = Field(
        default_factory=list,
        validation_alias="evidence_json",
        serialization_alias="evidence",
    )
    risk_factors: list[dict] = Field(
        default_factory=list,
        validation_alias="risk_factors_json",
        serialization_alias="risk_factors",
    )
    risk_reducing_factors: list[dict] = Field(
        default_factory=list,
        validation_alias="risk_reducing_factors_json",
        serialization_alias="risk_reducing_factors",
    )
    limitations: list[str] = Field(
        default_factory=list,
        validation_alias="limitations_json",
        serialization_alias="limitations",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        validation_alias="recommendations_json",
        serialization_alias="recommendations",
    )
    created_at: datetime

    @field_validator(
        "dns_findings",
        "ssl_findings",
        "evidence",
        "risk_factors",
        "risk_reducing_factors",
        "limitations",
        "recommendations",
        mode="before",
    )
    @classmethod
    def decode_json_fields(cls, value, info: ValidationInfo):
        empty_value = {} if info.field_name in {"dns_findings", "ssl_findings"} else []
        if value is None:
            return empty_value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("Stored website assessment data is malformed.") from exc
        return value

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class WebsiteAssessmentPage(BaseModel):
    total: int
    skip: int
    limit: int
    items: list[WebsiteAssessmentRead]


class WebsiteAssessmentSummary(BaseModel):
    total_assessments: int
    risk_distribution: dict[str, int]
    recent_assessments: list[WebsiteAssessmentRead]
