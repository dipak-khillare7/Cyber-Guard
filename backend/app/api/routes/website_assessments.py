import json
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.database.connection import get_db
from app.models.website_assessment import WebsiteAssessment
from app.schemas.website_assessment import (
    WebsiteAssessmentCreate,
    WebsiteAssessmentPage,
    WebsiteAssessmentRead,
    WebsiteAssessmentSummary,
)
from app.services.website_intelligence.assessment_service import (
    INSUFFICIENT_INFORMATION,
    SCORING_VERSION,
    assess_website_evidence,
    get_target_origin,
)
from app.services.website_intelligence.dns_analyzer import analyze_dns_records
from app.services.website_intelligence.providers.base import ProviderStatus
from app.services.website_intelligence.providers.virustotal import VirusTotalProvider
from app.services.website_intelligence.tls_analyzer import inspect_tls

ENGINE_VERSION = "website-analysis-v1"

router = APIRouter(prefix="/website-assessments", tags=["Website Assessments"])
analysis_router = APIRouter(prefix="/website-analysis", tags=["Website Analysis"])


def _owned_assessments(db: Session, owner_user_id: int):
    return db.query(WebsiteAssessment).filter(
        WebsiteAssessment.owner_user_id == owner_user_id
    )


@router.post(
    "",
    response_model=WebsiteAssessmentRead,
    status_code=status.HTTP_201_CREATED,
)
@analysis_router.post(
    "/analyze",
    response_model=WebsiteAssessmentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_website_assessment(
    assessment_in: WebsiteAssessmentCreate,
    response: Response,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=16,
        max_length=128,
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    normalized_url = VirusTotalProvider.normalize_url(assessment_in.url)
    if normalized_url is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "INVALID_WEBSITE_URL",
                "message": "Enter a valid public HTTP or HTTPS website URL without embedded credentials.",
            },
        )

    existing = _owned_assessments(db, current_user.id).filter(
        WebsiteAssessment.idempotency_key == idempotency_key
    ).first()
    if existing:
        scheme, host = get_target_origin(normalized_url)
        if existing.url_origin != f"{scheme}://{host}":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The idempotency key was already used for a different website origin.",
            )
        response.status_code = status.HTTP_200_OK
        return existing

    enforce_rate_limit(
        db,
        f"website-assessment:user:{current_user.id}",
        limit=5,
        window_seconds=60,
        action="website assessment",
    )

    scheme, host = get_target_origin(normalized_url)
    parsed_url = urlsplit(normalized_url)
    dns_result = analyze_dns_records(parsed_url.hostname or "")
    if dns_result.contains_non_global_address:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "NON_PUBLIC_DNS_TARGET",
                "message": "The website resolves to a non-public address and cannot be analyzed.",
            },
        )

    enforce_rate_limit(
        db,
        "provider:virustotal:website-url",
        limit=settings.VIRUSTOTAL_LOOKUP_LIMIT_PER_MINUTE,
        window_seconds=60,
        action="VirusTotal website URL lookup",
    )
    provider_result = VirusTotalProvider().get_url_report(
        normalized_url,
        consent_to_share=assessment_in.consent_to_share,
    )
    standard_https_port = parsed_url.scheme == "https" and parsed_url.port in (None, 443)
    ssl_status, ssl_findings = inspect_tls(
        parsed_url.hostname or "",
        enabled=standard_https_port,
        not_applicable=parsed_url.scheme != "https",
        disabled_reason=(
            "The URL uses a non-standard HTTPS port; only port 443 is checked."
            if parsed_url.scheme == "https" and not standard_https_port
            else "The submitted URL does not use HTTPS."
        ),
    )
    assessment_result = assess_website_evidence(
        provider_result,
        dns_status=dns_result.status,
        ssl_status=ssl_status,
    )
    stats = provider_result.data.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        stats = {}
    provider_completed = provider_result.status in {ProviderStatus.FOUND, ProviderStatus.NO_RECORD}
    dns_completed = dns_result.status in {"AVAILABLE", "NO_RECORDS", "NOT_APPLICABLE"}
    tls_completed = ssl_status in {"VALID", "INVALID", "NOT_APPLICABLE"}
    if not provider_completed and not dns_completed and not tls_completed:
        analysis_status = "UNAVAILABLE"
    elif provider_completed and dns_completed and tls_completed:
        analysis_status = "COMPLETE"
    else:
        analysis_status = "PARTIAL"

    assessment = WebsiteAssessment(
        owner_user_id=current_user.id,
        url_origin=f"{scheme}://{host}",
        target_domain=host,
        scheme=scheme,
        risk_level=assessment_result["risk_level"],
        risk_score=assessment_result["risk_score"],
        risk_explanation=assessment_result["risk_explanation"],
        analysis_status=analysis_status,
        engine_version=ENGINE_VERSION,
        scoring_version=SCORING_VERSION,
        idempotency_key=idempotency_key,
        provider_status=provider_result.status.value,
        provider_reputation=provider_result.data.get("reputation"),
        malicious_count=stats.get("malicious"),
        suspicious_count=stats.get("suspicious"),
        undetected_count=stats.get("undetected"),
        harmless_count=stats.get("harmless"),
        vendor_count=provider_result.data.get("vendor_count"),
        provider_analysis_at=provider_result.data.get("last_analysis_date"),
        provider_retrieved_at=provider_result.retrieved_at,
        provider_http_status=provider_result.provider_http_status,
        dns_status=dns_result.status,
        dns_findings_json=json.dumps(dns_result.findings, separators=(",", ":")),
        ssl_status=ssl_status,
        ssl_findings_json=json.dumps(ssl_findings, separators=(",", ":")),
        evidence_json=json.dumps(assessment_result["evidence"], separators=(",", ":")),
        risk_factors_json=json.dumps(assessment_result["risk_factors"], separators=(",", ":")),
        risk_reducing_factors_json=json.dumps(
            assessment_result["risk_reducing_factors"],
            separators=(",", ":"),
        ),
        limitations_json=json.dumps(assessment_result["limitations"], separators=(",", ":")),
        recommendations_json=json.dumps(
            assessment_result["recommendations"],
            separators=(",", ":"),
        ),
    )
    db.add(assessment)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _owned_assessments(db, current_user.id).filter(
            WebsiteAssessment.idempotency_key == idempotency_key
        ).first()
        if existing:
            response.status_code = status.HTTP_200_OK
            return existing
        raise
    db.refresh(assessment)
    return assessment


@router.get("/summary", response_model=WebsiteAssessmentSummary)
def get_website_assessment_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = _owned_assessments(db, current_user.id)
    total = query.count()
    grouped = (
        query.with_entities(WebsiteAssessment.risk_level, func.count(WebsiteAssessment.id))
        .group_by(WebsiteAssessment.risk_level)
        .all()
    )
    distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
        INSUFFICIENT_INFORMATION: 0,
        "ANALYSIS_UNAVAILABLE": 0,
    }
    for level, count in grouped:
        if level in distribution:
            distribution[level] = count
    recent = query.order_by(WebsiteAssessment.created_at.desc()).limit(5).all()
    return {
        "total_assessments": total,
        "risk_distribution": distribution,
        "recent_assessments": recent,
    }


@router.get("", response_model=WebsiteAssessmentPage)
@analysis_router.get("/history", response_model=WebsiteAssessmentPage)
def list_website_assessments(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, min_length=1, max_length=260),
    risk_level: Optional[str] = Query(None),
    sort_order: str = Query("newest", pattern="^(newest|oldest)$"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = _owned_assessments(db, current_user.id)
    if search:
        query = query.filter(WebsiteAssessment.target_domain.ilike(f"%{search.strip()}%"))
    if risk_level:
        allowed_risks = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            INSUFFICIENT_INFORMATION,
            "ANALYSIS_UNAVAILABLE",
        }
        normalized_risk = risk_level.upper()
        if normalized_risk not in allowed_risks:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unsupported website assessment risk filter.",
            )
        query = query.filter(WebsiteAssessment.risk_level == normalized_risk)
    total = query.count()
    order_column = (
        WebsiteAssessment.created_at.asc()
        if sort_order == "oldest"
        else WebsiteAssessment.created_at.desc()
    )
    items = query.order_by(order_column, WebsiteAssessment.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "skip": skip, "limit": limit, "items": items}


@router.get("/{assessment_id}", response_model=WebsiteAssessmentRead)
@analysis_router.get("/{assessment_id}", response_model=WebsiteAssessmentRead)
def get_website_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    assessment = _owned_assessments(db, current_user.id).filter(
        WebsiteAssessment.id == assessment_id
    ).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Website assessment was not found.",
        )
    return assessment
