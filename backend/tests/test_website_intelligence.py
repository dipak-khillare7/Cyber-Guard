from app.services.website_intelligence import dns_analyzer
from app.services.website_intelligence.assessment_service import (
    SCORING_VERSION,
    assess_website_evidence,
)
from app.services.website_intelligence.providers.base import ProviderStatus, ThreatIntelResult
from app.services.website_intelligence import tls_analyzer


def _provider_result(status, stats=None):
    data = {"last_analysis_stats": stats} if stats is not None else {}
    return ThreatIntelResult(
        provider="VIRUSTOTAL",
        indicator_type="URL",
        indicator_hash="hashed",
        status=status,
        data=data,
    )


def test_dns_analysis_returns_records_and_provider_policy_indicators(monkeypatch):
    def fake_query(domain, record_type):
        if domain.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"], "AVAILABLE"
        if record_type == "A":
            return ["93.184.216.34"], "AVAILABLE"
        if record_type == "TXT":
            return ["v=spf1 -all"], "AVAILABLE"
        if record_type == "MX":
            return [{"preference": 10, "exchange": "mail.example.com"}], "AVAILABLE"
        if record_type == "NS":
            return ["ns.example.com"], "AVAILABLE"
        return [], "NO_RECORD"

    monkeypatch.setattr(dns_analyzer, "_query_record", fake_query)

    result = dns_analyzer.analyze_dns_records("example.com")

    assert result.status == "AVAILABLE"
    assert result.addresses == ("93.184.216.34",)
    assert result.findings["spf"] == ["v=spf1 -all"]
    assert result.findings["dmarc"] == ["v=DMARC1; p=reject"]
    assert result.findings["record_status"]["AAAA"] == "NO_RECORD"


def test_dns_analysis_blocks_any_non_global_address(monkeypatch):
    def fake_query(domain, record_type):
        if record_type == "A":
            return ["8.8.8.8"], "AVAILABLE"
        if record_type == "AAAA":
            return ["127.0.0.1"], "AVAILABLE"
        return [], "NO_RECORD"

    monkeypatch.setattr(dns_analyzer, "_query_record", fake_query)

    result = dns_analyzer.analyze_dns_records("example.com")

    assert result.status == "BLOCKED_PRIVATE_ADDRESS"
    assert result.contains_non_global_address
    assert result.addresses == ()
    assert result.findings["records"]["A"] == []
    assert result.findings["records"]["AAAA"] == []


def test_dns_txt_redacts_verification_tokens_and_limits_length():
    class TxtRecord:
        strings = [b"google-site-verification=private-value v=spf1 -all"]

    result = dns_analyzer._safe_txt_value(TxtRecord())

    assert "private-value" not in result
    assert "google-site-verification=[redacted]" in result
    assert "v=spf1 -all" in result


def test_website_score_is_versioned_deterministic_and_does_not_double_count():
    provider = _provider_result(
        ProviderStatus.FOUND,
        {
            "malicious": 1,
            "suspicious": 1,
            "undetected": 7,
            "harmless": 5,
        },
    )

    first = assess_website_evidence(
        provider,
        dns_status="AVAILABLE",
        ssl_status="INVALID",
    )
    second = assess_website_evidence(
        provider,
        dns_status="AVAILABLE",
        ssl_status="INVALID",
    )

    assert first == second
    assert first["scoring_version"] == SCORING_VERSION
    assert first["risk_score"] == 86
    assert first["risk_level"] == "CRITICAL"
    assert len(first["risk_factors"]) == 2
    assert first["risk_factors"][0]["points"] == 61


def test_missing_provider_and_incomplete_checks_do_not_receive_numeric_score():
    result = assess_website_evidence(
        _provider_result(ProviderStatus.NOT_CONFIGURED),
        dns_status="UNAVAILABLE",
        ssl_status="UNAVAILABLE",
    )
    partially_available = assess_website_evidence(
        _provider_result(ProviderStatus.NO_RECORD),
        dns_status="AVAILABLE",
        ssl_status="UNAVAILABLE",
    )

    assert result["risk_level"] == "ANALYSIS_UNAVAILABLE"
    assert result["risk_score"] is None
    assert partially_available["risk_level"] == "INSUFFICIENT_INFORMATION"
    assert partially_available["risk_score"] is None


def test_dns_literal_is_not_resolved_as_a_domain():
    result = dns_analyzer.analyze_dns_records("127.0.0.1")

    assert result.status == "NOT_APPLICABLE"
    assert result.contains_non_global_address
    assert result.findings["addresses"] == []


def test_tls_inspection_revalidates_dns_and_connects_to_pinned_public_ip(monkeypatch):
    observed = {}

    class FakeSocket:
        def settimeout(self, timeout):
            observed["timeout"] = timeout

        def connect(self, address):
            observed["address"] = address

        def close(self):
            pass

    class FakeTlsSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def getpeercert(self):
            return {
                "notAfter": "Dec 31 23:59:59 2030 GMT",
                "issuer": ((("commonName", "Test CA"),),),
            }

        def version(self):
            return "TLSv1.3"

    class FakeContext:
        def wrap_socket(self, _sock, *, server_hostname):
            observed["server_hostname"] = server_hostname
            return FakeTlsSocket()

    monkeypatch.setattr(
        tls_analyzer,
        "resolve_public_addresses",
        lambda host: (("8.8.8.8",), False, True),
    )
    monkeypatch.setattr(tls_analyzer.socket, "socket", lambda *_args: FakeSocket())
    monkeypatch.setattr(tls_analyzer.ssl, "create_default_context", FakeContext)

    status, findings = tls_analyzer.inspect_tls("example.com", enabled=True)

    assert status == "VALID"
    assert observed["address"] == ("8.8.8.8", 443)
    assert observed["server_hostname"] == "example.com"
    assert findings["hostname_match"] is True
    assert findings["certificate_valid"] is True
    assert findings["tls_version"] == "TLSv1.3"


def test_tls_inspection_never_connects_when_revalidation_finds_private_address(monkeypatch):
    monkeypatch.setattr(
        tls_analyzer,
        "resolve_public_addresses",
        lambda host: ((), True, True),
    )
    monkeypatch.setattr(
        tls_analyzer.socket,
        "socket",
        lambda *_args: (_ for _ in ()).throw(AssertionError("socket must not be opened")),
    )

    status, findings = tls_analyzer.inspect_tls("example.com", enabled=True)

    assert status == "BLOCKED_PRIVATE_ADDRESS"
    assert findings["checked"] is False

