from urllib.parse import urlsplit

from app.services.website_intelligence.providers.base import (
    ProviderStatus,
    ThreatIntelResult,
)

INSUFFICIENT_INFORMATION = "INSUFFICIENT_INFORMATION"
SCORING_VERSION = "website-risk-v1"


def get_target_origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return parts.scheme, host.lower()


def assess_website_evidence(
    provider_result: ThreatIntelResult,
    *,
    dns_status: str,
    ssl_status: str,
) -> dict:
    """Score only evidence: VT malicious 60+15%, suspicious 30+20%, invalid TLS +25; thresholds 25/60/85."""
    evidence = []
    factors = []
    reducing_factors = []
    limitations = [
        "This assessment does not fetch website content or perform active vulnerability scanning.",
        "A valid HTTPS certificate does not establish that a website is benign.",
        "WHOIS/domain registration data is not configured.",
    ]
    recommendations = []
    score = 0
    has_scoring_evidence = False

    stats = provider_result.data.get("last_analysis_stats")
    if provider_result.status is ProviderStatus.FOUND and isinstance(stats, dict):
        malicious_value = stats.get("malicious", 0)
        suspicious_value = stats.get("suspicious", 0)
        malicious = (
            malicious_value
            if isinstance(malicious_value, int) and not isinstance(malicious_value, bool)
            and malicious_value >= 0
            else 0
        )
        suspicious = (
            suspicious_value
            if isinstance(suspicious_value, int) and not isinstance(suspicious_value, bool)
            and suspicious_value >= 0
            else 0
        )
        vendors = sum(
            value
            for value in stats.values()
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        )
        if vendors > 0:
            has_scoring_evidence = True
            if malicious > 0:
                points = min(75, 60 + round(15 * malicious / vendors))
                score += points
                factors.append({
                    "code": "VIRUSTOTAL_MALICIOUS_DETECTIONS",
                    "source": "VIRUSTOTAL",
                    "points": points,
                    "description": f"{malicious} vendor detection(s) marked this URL malicious.",
                })
                evidence.append({
                    "type": "THREAT_INTELLIGENCE",
                    "source": "VIRUSTOTAL",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "vendors": vendors,
                })
                recommendations.append(
                    "Treat the URL as potentially harmful and review the underlying provider detections before opening it."
                )
            elif suspicious > 0:
                points = min(50, 30 + round(20 * suspicious / vendors))
                score += points
                factors.append({
                    "code": "VIRUSTOTAL_SUSPICIOUS_DETECTIONS",
                    "source": "VIRUSTOTAL",
                    "points": points,
                    "description": f"{suspicious} vendor detection(s) marked this URL suspicious.",
                })
                evidence.append({
                    "type": "THREAT_INTELLIGENCE",
                    "source": "VIRUSTOTAL",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "vendors": vendors,
                })
                recommendations.append(
                    "Review the suspicious provider detections and verify the site through a trusted channel."
                )
            else:
                evidence.append({
                    "type": "THREAT_INTELLIGENCE",
                    "source": "VIRUSTOTAL",
                    "malicious": 0,
                    "suspicious": 0,
                    "vendors": vendors,
                })
                reducing_factors.append({
                    "code": "NO_PROVIDER_DETECTIONS",
                    "source": "VIRUSTOTAL",
                    "description": (
                        "The available provider report contained no malicious or suspicious detections; "
                        "this is not proof of safety."
                    ),
                })
        else:
            limitations.append("The VirusTotal report contained no usable vendor analysis statistics.")
    else:
        limitations.append(
            f"Threat intelligence was not available (provider status: {provider_result.status.value})."
        )

    if ssl_status == "INVALID":
        has_scoring_evidence = True
        score += 25
        factors.append({
            "code": "TLS_CERTIFICATE_VERIFICATION_FAILED",
            "source": "TLS",
            "points": 25,
            "description": "The certificate chain or hostname could not be verified.",
        })
        evidence.append({
            "type": "TLS",
            "status": "INVALID",
            "description": "TLS certificate verification failed.",
        })
        recommendations.append(
            "Do not enter sensitive information unless the certificate problem is independently resolved."
        )
    elif ssl_status == "VALID":
        evidence.append({
            "type": "TLS",
            "status": "VALID",
            "description": "A verified certificate was presented on the standard HTTPS port.",
        })
        reducing_factors.append({
            "code": "TLS_CERTIFICATE_VERIFIED",
            "source": "TLS",
            "description": "The TLS certificate chain and hostname were verified for this connection.",
        })
    elif ssl_status not in {"NOT_APPLICABLE", "NOT_CHECKED"}:
        limitations.append(f"TLS inspection was unavailable (status: {ssl_status}).")

    if dns_status not in {"AVAILABLE", "NOT_APPLICABLE"}:
        limitations.append(f"DNS results were incomplete or unavailable (status: {dns_status}).")
    if not recommendations:
        recommendations.append(
            "Use standard browser protections and avoid entering sensitive information based only on this assessment."
        )

    checks_returned = (
        provider_result.status in {ProviderStatus.FOUND, ProviderStatus.NO_RECORD}
        or dns_status in {"AVAILABLE", "NO_RECORDS", "PARTIAL"}
        or ssl_status in {"VALID", "INVALID"}
    )
    if not has_scoring_evidence:
        risk_level = INSUFFICIENT_INFORMATION if checks_returned else "ANALYSIS_UNAVAILABLE"
        numeric_score = None
        if checks_returned:
            explanation = (
                "There was not enough usable evidence to produce a numeric risk score. "
                "Unavailable checks are not treated as proof that the website is safe."
            )
        else:
            explanation = (
                "The analysis services were unavailable, so no evidence-based risk score could be produced."
            )
    else:
        numeric_score = min(score, 100)
        if numeric_score >= 85:
            risk_level = "CRITICAL"
        elif numeric_score >= 60:
            risk_level = "HIGH"
        elif numeric_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        explanation = (
            f"The {SCORING_VERSION} method assigned {numeric_score}/100 from "
            f"{len(factors)} risk-increasing evidence factor(s). A low score is not a safety guarantee."
        )

    return {
        "risk_level": risk_level,
        "risk_score": numeric_score,
        "risk_explanation": explanation,
        "scoring_version": SCORING_VERSION,
        "evidence": evidence,
        "risk_factors": factors,
        "risk_reducing_factors": reducing_factors,
        "limitations": limitations,
        "recommendations": recommendations,
    }
