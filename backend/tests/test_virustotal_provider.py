import base64

import httpx

from app.services.website_intelligence.providers.base import ProviderStatus
from app.services.website_intelligence.providers.virustotal import VirusTotalProvider


def _mock_provider(handler, *, api_key="test-key"):
    return VirusTotalProvider(
        api_key=api_key,
        transport=httpx.MockTransport(handler),
    )


def test_domain_report_normalizes_vendor_statistics_without_returning_raw_data():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["api_key"] = request.headers.get("x-apikey")
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "reputation": -3,
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 10,
                            "undetected": 5,
                            "timeout": 0,
                            "unknown_provider_field": 99,
                        },
                        "last_analysis_date": 1_700_000_000,
                        "last_analysis_results": {"vendor": {"result": "malicious"}},
                    }
                }
            },
        )

    result = _mock_provider(handler).get_domain_report(
        "ExAmPle.COM.",
        consent_to_share=True,
    )

    assert result.status == ProviderStatus.FOUND
    assert result.indicator_type == "DOMAIN"
    assert result.indicator_hash is not None
    assert result.data["reputation"] == -3
    assert result.data["last_analysis_stats"]["malicious"] == 2
    assert result.data["vendor_count"] == 18
    assert "last_analysis_date" in result.data
    assert "last_analysis_results" not in result.data
    assert "test-key" not in repr(result)
    assert result.provider_http_status == 200
    assert seen["url"] == "https://www.virustotal.com/api/v3/domains/example.com"
    assert seen["api_key"] == "test-key"


def test_provider_requires_sharing_consent_and_skips_private_indicators():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"data": {"attributes": {}}})

    provider = _mock_provider(handler)

    no_consent = provider.get_domain_report("example.com")
    private_ip = provider.get_ip_report("127.0.0.1", consent_to_share=True)
    private_url = provider.get_url_report(
        "http://192.168.1.10/admin",
        consent_to_share=True,
    )
    credentials_url = provider.get_url_report(
        "https://user:password@example.com/",
        consent_to_share=True,
    )

    assert no_consent.status == ProviderStatus.NOT_QUERIED
    assert private_ip.status == ProviderStatus.INVALID_INDICATOR
    assert private_url.status == ProviderStatus.INVALID_INDICATOR
    assert credentials_url.status == ProviderStatus.INVALID_INDICATOR
    assert requests == []


def test_url_lookup_requires_consent_and_only_calls_fixed_provider_host():
    seen = {}

    def handler(request):
        seen["host"] = request.url.host
        seen["path"] = request.url.path
        return httpx.Response(200, json={"data": {"attributes": {}}})

    provider = _mock_provider(handler)
    not_queried = provider.get_url_report("https://example.com/account?token=redacted")
    queried = provider.get_url_report(
        "https://example.com/account?token=redacted",
        consent_to_share=True,
    )

    url_id = seen["path"].rsplit("/", 1)[-1]
    decoded_url = base64.urlsafe_b64decode(url_id + "=" * (-len(url_id) % 4)).decode()
    assert not_queried.status == ProviderStatus.NOT_QUERIED
    assert queried.status == ProviderStatus.FOUND
    assert seen["host"] == "www.virustotal.com"
    assert decoded_url == "https://example.com/account?token=redacted"
    assert "token=redacted" not in repr(queried)


def test_missing_api_key_does_not_make_a_request():
    requests = []
    provider = _mock_provider(lambda request: requests.append(request), api_key="")

    result = provider.get_ip_report("8.8.8.8", consent_to_share=True)

    assert result.status == ProviderStatus.NOT_CONFIGURED
    assert requests == []


def test_provider_statuses_distinguish_no_record_auth_rate_limit_and_outage():
    responses = {
        404: ProviderStatus.NO_RECORD,
        401: ProviderStatus.AUTHENTICATION_ERROR,
        403: ProviderStatus.PROVIDER_FORBIDDEN,
        429: ProviderStatus.RATE_LIMITED,
        503: ProviderStatus.UNAVAILABLE,
    }

    for status_code, expected in responses.items():
        provider = _mock_provider(
            lambda request, code=status_code: httpx.Response(
                code,
                headers={"Retry-After": "17"} if code == 429 else {},
            )
        )
        result = provider.get_ip_report("8.8.8.8", consent_to_share=True)
        assert result.status == expected
        assert result.provider_http_status == status_code
        assert result.retry_after_seconds == (17 if status_code == 429 else None)


def test_timeout_and_malformed_success_are_not_reported_as_no_match():
    timeout_provider = _mock_provider(
        lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timeout"))
    )
    malformed_provider = _mock_provider(
        lambda request: httpx.Response(200, content=b"not-json")
    )

    timeout = timeout_provider.get_ip_report("8.8.8.8", consent_to_share=True)
    malformed = malformed_provider.get_ip_report("8.8.8.8", consent_to_share=True)

    assert timeout.status == ProviderStatus.TIMEOUT
    assert malformed.status == ProviderStatus.UNAVAILABLE
    assert malformed.error_code == "INVALID_PROVIDER_RESPONSE"


def test_idn_domain_is_normalized_and_unsupported_or_internal_urls_are_rejected():
    seen_paths = []

    def handler(request):
        seen_paths.append(request.url.path)
        return httpx.Response(404)

    provider = _mock_provider(handler)
    idn_result = provider.get_domain_report(
        "münich.example.org",
        consent_to_share=True,
    )
    ftp_result = provider.get_url_report(
        "ftp://example.com/file",
        consent_to_share=True,
    )
    internal_domain = provider.get_domain_report(
        "service.local",
        consent_to_share=True,
    )

    assert idn_result.status == ProviderStatus.NO_RECORD
    assert seen_paths == ["/api/v3/domains/xn--mnich-kva.example.org"]
    assert ftp_result.status == ProviderStatus.INVALID_INDICATOR
    assert internal_domain.status == ProviderStatus.INVALID_INDICATOR


def test_url_normalization_rejects_parser_ambiguity_and_obfuscated_ip_literals():
    assert VirusTotalProvider.normalize_url("https://münich.example.org/path") == (
        "https://xn--mnich-kva.example.org/path"
    )
    assert VirusTotalProvider.normalize_url("https://example.com:") is None
    assert VirusTotalProvider.normalize_url("https://@example.com") is None
    assert VirusTotalProvider.normalize_url("http://127.1/") is None
    assert VirusTotalProvider.normalize_url("http://0x7f000001/") is None
    assert VirusTotalProvider.normalize_url("https://example.com\\@127.0.0.1/") is None
    assert VirusTotalProvider.normalize_url("https://example.com/a b") is None


def test_oversized_provider_response_is_rejected():
    provider = _mock_provider(
        lambda request: httpx.Response(
            200,
            content=b"x" * (VirusTotalProvider.MAX_RESPONSE_BYTES + 1),
        )
    )

    result = provider.get_ip_report("8.8.8.8", consent_to_share=True)

    assert result.status == ProviderStatus.UNAVAILABLE
    assert result.error_code == "PROVIDER_RESPONSE_TOO_LARGE"
