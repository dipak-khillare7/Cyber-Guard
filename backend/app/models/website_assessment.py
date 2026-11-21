from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, Integer, String, Text

from app.database.connection import Base


def utc_now():
    return datetime.now(timezone.utc)


class WebsiteAssessment(Base):
    __tablename__ = "website_assessments"
    __table_args__ = (
        Index(
            "uq_website_assessments_owner_idempotency_key",
            "owner_user_id",
            "idempotency_key",
            unique=True,
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    owner_user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url_origin = Column(String(2048), nullable=True)
    target_domain = Column(String(260), nullable=False, index=True)
    scheme = Column(String(5), nullable=False)
    risk_level = Column(String(32), nullable=False, index=True)
    risk_score = Column(Float, nullable=True)
    risk_explanation = Column(String(500), nullable=False)
    analysis_status = Column(String(32), nullable=False, default="LEGACY", server_default="LEGACY")
    engine_version = Column(String(32), nullable=False, default="legacy", server_default="legacy")
    scoring_version = Column(String(32), nullable=False, default="legacy", server_default="legacy")
    provider_status = Column(String(32), nullable=False)
    provider_reputation = Column(Integer, nullable=True)
    malicious_count = Column(Integer, nullable=True)
    suspicious_count = Column(Integer, nullable=True)
    undetected_count = Column(Integer, nullable=True)
    harmless_count = Column(Integer, nullable=True)
    vendor_count = Column(Integer, nullable=True)
    provider_analysis_at = Column(DateTime(timezone=True), nullable=True)
    provider_retrieved_at = Column(DateTime(timezone=True), nullable=False)
    provider_http_status = Column(Integer, nullable=True)
    dns_status = Column(String(32), nullable=False, default="NOT_CHECKED", server_default="NOT_CHECKED")
    dns_findings_json = Column(Text, nullable=False, default="{}", server_default="{}")
    ssl_status = Column(String(32), nullable=False, default="NOT_CHECKED", server_default="NOT_CHECKED")
    ssl_findings_json = Column(Text, nullable=False, default="{}", server_default="{}")
    evidence_json = Column(Text, nullable=False, default="[]", server_default="[]")
    risk_factors_json = Column(Text, nullable=False, default="[]", server_default="[]")
    risk_reducing_factors_json = Column(Text, nullable=False, default="[]", server_default="[]")
    limitations_json = Column(Text, nullable=False, default="[]", server_default="[]")
    recommendations_json = Column(Text, nullable=False, default="[]", server_default="[]")
    idempotency_key = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
