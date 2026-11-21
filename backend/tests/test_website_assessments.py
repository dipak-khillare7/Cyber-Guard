from datetime import datetime, timezone

from app.core.config import settings
from app.models.user import UserRole
from app.schemas.user import UserCreate
from app.services.user_service import UserService
from app.services.website_intelligence.providers.base import (
    ProviderStatus,
    ThreatIntelResult,
)
from app.services.website_intelligence.dns_analyzer import DnsAnalysis


def _create_viewer_headers(client, db_session, username):
    UserService.create_user(
        db_session,
        UserCreate(
            username=username,
            email=f"{username}@example.com",
            password="ViewerPassword123!",
            role=UserRole.VIEWER,
        ),
    )
    response = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": username, "password": "ViewerPassword123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _request_headers(auth_headers, key):
    return {**auth_headers, "Idempotency-Key": key}


def _mock_website_checks(
    monkeypatch,
    route,
    *,
    dns_status="AVAILABLE",
    non_public=False,
    ssl_status="VALID",
):
    monkeypatch.setattr(
        route,
        "analyze_dns_records",
        lambda host: DnsAnalysis(
            status=dns_status,
            findings={
                "records": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": [], "TXT": []},
                "record_status": {"A": dns_status},
                "addresses": ["93.184.216.34"],
                "spf": [],
                "dmarc": [],
                "registration_status": "NOT_CONFIGURED",
            },
            addresses=("93.184.216.34",),
            contains_non_global_address=non_public,
        ),
    )
    monkeypatch.setattr(
        route,
        "inspect_tls",
        lambda host, **kwargs: (
            ssl_status,
            {
                "checked": True,
                "certificate_valid": ssl_status == "VALID",
                "hostname_match": ssl_status == "VALID",
            },
        ),
    )


def test_website_assessment_persists_provider_evidence_and_scopes_history(
    client,
    db_session,
    monkeypatch,
):
    from app.api.routes import website_assessments
    _mock_website_checks(monkeypatch, website_assessments)

    viewer_one = _create_viewer_headers(client, db_session, "site_viewer_one")
    viewer_two = _create_viewer_headers(client, db_session, "site_viewer_two")
    calls = []

    def mock_get_url_report(self, url, *, consent_to_share):
        calls.append((url, consent_to_share))
        return ThreatIntelResult(
                provider="VIRUSTOTAL",
                indicator_type="URL",
                indicator_hash="hashed-indicator",
                status=ProviderStatus.FOUND,
                retrieved_at=datetime.now(timezone.utc),
                provider_http_status=200,
                data={
                    "reputation": -3,
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 7,
                        "harmless": 5,
                    },
                    "vendor_count": 13,
                    "last_analysis_date": datetime(2026, 11, 20, tzinfo=timezone.utc),
                },
            )

    monkeypatch.setattr(
        website_assessments.VirusTotalProvider,
        "get_url_report",
        mock_get_url_report,
    )
    submitted_url = "https://example.com/private/path?secret=not-persisted"
    response = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=_request_headers(viewer_one, "website-check-request-0001"),
        json={"url": submitted_url, "consent_to_share": True},
    )

    assert response.status_code == 201
    assessment = response.json()
    assert calls == [(submitted_url, True)]
    assert assessment["target_domain"] == "example.com"
    assert assessment["risk_level"] == "HIGH"
    assert assessment["malicious_count"] == 1
    assert assessment["provider_status"] == "FOUND"
    assert assessment["dns_status"] == "AVAILABLE"
    assert assessment["ssl_status"] == "VALID"
    assert assessment["url_origin"] == "https://example.com"
    assert assessment["risk_score"] == 61
    assert assessment["scoring_version"] == "website-risk-v1"
    assert assessment["dns_findings"]["addresses"] == ["93.184.216.34"]
    assert "secret=not-persisted" not in response.text

    own_history = client.get(
        f"{settings.API_PREFIX}/website-assessments",
        headers=viewer_one,
    )
    other_history = client.get(
        f"{settings.API_PREFIX}/website-assessments",
        headers=viewer_two,
    )
    summary = client.get(
        f"{settings.API_PREFIX}/website-assessments/summary",
        headers=viewer_one,
    )
    other_detail = client.get(
        f"{settings.API_PREFIX}/website-assessments/{assessment['id']}",
        headers=viewer_two,
    )

    assert own_history.status_code == 200
    assert own_history.json()["total"] == 1
    assert other_history.json()["total"] == 0
    assert summary.json()["total_assessments"] == 1
    assert summary.json()["risk_distribution"]["HIGH"] == 1
    assert other_detail.status_code == 404


def test_no_consent_invalid_urls_and_private_hosts_never_call_provider(
    client,
    db_session,
    monkeypatch,
):
    from app.api.routes import website_assessments
    _mock_website_checks(monkeypatch, website_assessments)

    viewer = _create_viewer_headers(client, db_session, "site_viewer_privacy")
    calls = []

    def mock_get_url_report(self, url, *, consent_to_share):
        calls.append(url)
        return ThreatIntelResult(
            provider="VIRUSTOTAL",
            indicator_type="URL",
            indicator_hash=None,
            status=ProviderStatus.FOUND,
            data={},
        )

    monkeypatch.setattr(
        website_assessments.VirusTotalProvider,
        "get_url_report",
        mock_get_url_report,
    )
    no_consent = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=_request_headers(viewer, "website-check-request-0002"),
        json={"url": "https://example.com", "consent_to_share": False},
    )
    private_host = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=_request_headers(viewer, "website-check-request-0003"),
        json={"url": "http://127.0.0.1/admin", "consent_to_share": True},
    )
    unsupported_scheme = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=_request_headers(viewer, "website-check-request-0004"),
        json={"url": "ftp://example.com/file", "consent_to_share": True},
    )

    assert no_consent.status_code == 422
    assert private_host.status_code == 422
    assert unsupported_scheme.status_code == 422
    assert calls == []


def test_no_record_and_unavailable_provider_are_insufficient_not_low_risk(
    client,
    db_session,
    monkeypatch,
):
    from app.api.routes import website_assessments
    _mock_website_checks(monkeypatch, website_assessments)

    viewer = _create_viewer_headers(client, db_session, "site_viewer_no_record")
    statuses = iter([ProviderStatus.NO_RECORD, ProviderStatus.NOT_CONFIGURED])

    def mock_get_url_report(self, url, *, consent_to_share):
        return ThreatIntelResult(
            provider="VIRUSTOTAL",
            indicator_type="URL",
            indicator_hash=None,
            status=next(statuses),
        )

    monkeypatch.setattr(
        website_assessments.VirusTotalProvider,
        "get_url_report",
        mock_get_url_report,
    )
    for domain in ("example-one.com", "example-two.com"):
        response = client.post(
            f"{settings.API_PREFIX}/website-assessments",
            headers=_request_headers(viewer, f"website-check-request-{domain}"),
            json={"url": f"https://{domain}", "consent_to_share": True},
        )
        assert response.status_code == 201
        assert response.json()["risk_level"] == "INSUFFICIENT_INFORMATION"
        assert response.json()["risk_score"] is None


def test_private_dns_answers_are_rejected_before_provider_or_tls(
    client,
    db_session,
    monkeypatch,
):
    from app.api.routes import website_assessments

    viewer = _create_viewer_headers(client, db_session, "site_viewer_dns_private")
    _mock_website_checks(
        monkeypatch,
        website_assessments,
        non_public=True,
    )
    provider_calls = []
    monkeypatch.setattr(
        website_assessments.VirusTotalProvider,
        "get_url_report",
        lambda *args, **kwargs: provider_calls.append(args),
    )
    response = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=_request_headers(viewer, "website-check-request-private"),
        json={"url": "https://example.com", "consent_to_share": True},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "NON_PUBLIC_DNS_TARGET"
    assert provider_calls == []


def test_repeated_idempotency_key_returns_saved_assessment_without_reanalysis(
    client,
    db_session,
    monkeypatch,
):
    from app.api.routes import website_assessments

    viewer = _create_viewer_headers(client, db_session, "site_viewer_idempotent")
    _mock_website_checks(monkeypatch, website_assessments)
    provider_calls = []

    def mock_get_url_report(self, url, *, consent_to_share):
        provider_calls.append(url)
        return ThreatIntelResult(
            provider="VIRUSTOTAL",
            indicator_type="URL",
            indicator_hash="hashed-indicator",
            status=ProviderStatus.NO_RECORD,
        )

    monkeypatch.setattr(
        website_assessments.VirusTotalProvider,
        "get_url_report",
        mock_get_url_report,
    )
    headers = _request_headers(viewer, "website-check-idempotency-0001")
    payload = {"url": "https://example.com/path", "consent_to_share": True}
    first = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=headers,
        json=payload,
    )
    second = client.post(
        f"{settings.API_PREFIX}/website-assessments",
        headers=headers,
        json=payload,
    )

    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert provider_calls == [payload["url"]]


def test_viewers_cannot_submit_network_events_to_analyst_routes(client, db_session):
    viewer = _create_viewer_headers(client, db_session, "website_only_viewer")

    event_response = client.post(
        f"{settings.API_PREFIX}/events",
        headers=viewer,
        json={"source_ip": "8.8.8.8", "destination_port": 443},
    )
    analysis_response = client.post(
        f"{settings.API_PREFIX}/detection/analyze",
        headers=viewer,
        json={"source_ip": "8.8.8.8", "destination_port": 443},
    )

    assert event_response.status_code == 403
    assert analysis_response.status_code == 403
