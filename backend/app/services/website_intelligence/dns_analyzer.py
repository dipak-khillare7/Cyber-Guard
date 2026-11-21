import concurrent.futures
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver

DNS_TIMEOUT_SECONDS = 1.0
DNS_MAX_RECORDS = 20
TXT_MAX_LENGTH = 512
DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
_SENSITIVE_TXT_VALUE = re.compile(
    r"(?i)(^|[\s;])"
    r"(api[_-]?key|access[_-]?token|client[_-]?secret|google-site-verification|"
    r"facebook-domain-verification|apple-domain-verification|atlassian-domain-verification|"
    r"dropbox-domain-verification|stripe-verification|github-challenge|_?acme-challenge|"
    r"acme-challenge|verification(?:[_-]?token)?|dns[_-]?token|_?amazonses|"
    r"ms|password|token|secret|challenge)"
    r"(\s*[=:]\s*)([^;\s,]+)"
)


@dataclass(frozen=True)
class DnsAnalysis:
    status: str
    findings: dict[str, Any]
    addresses: tuple[str, ...]
    contains_non_global_address: bool = False


def _safe_txt_value(record) -> str:
    value = b"".join(record.strings).decode("utf-8", errors="replace")
    value = "".join(char if char.isprintable() else " " for char in value)
    redacted = _SENSITIVE_TXT_VALUE.sub(r"\1\2\3[redacted]", value)
    return redacted[:TXT_MAX_LENGTH]


def _format_record(record_type: str, record) -> Any:
    if record_type in {"A", "AAAA"}:
        return str(ipaddress.ip_address(str(record)))
    if record_type == "MX":
        return {
            "preference": int(record.preference),
            "exchange": str(record.exchange).rstrip(".").lower(),
        }
    if record_type == "NS":
        return str(record.target).rstrip(".").lower()
    return _safe_txt_value(record)


def _query_record(domain: str, record_type: str) -> tuple[list[Any], str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    name = domain.rstrip(".") + "."
    try:
        answer = resolver.resolve(
            name,
            record_type,
            search=False,
            raise_on_no_answer=False,
            lifetime=DNS_TIMEOUT_SECONDS,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], "NO_RECORD"
    except (dns.exception.DNSException, OSError):
        return [], "UNAVAILABLE"

    if answer.rrset is None:
        return [], "NO_RECORD"
    records = [
        _format_record(record_type, record)
        for record in list(answer)[:DNS_MAX_RECORDS]
    ]
    return records, "AVAILABLE"


def resolve_public_addresses(
    domain: str,
) -> tuple[tuple[str, ...], bool, bool]:
    try:
        literal = ipaddress.ip_address(domain)
    except ValueError:
        literal = None
    if literal is not None:
        address = str(literal)
        return (address,), not literal.is_global, True

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            record_type: executor.submit(_query_record, domain, record_type)
            for record_type in ("A", "AAAA")
        }
        results = {record_type: future.result() for record_type, future in futures.items()}

    addresses = tuple(sorted({
        address
        for record_type in ("A", "AAAA")
        for address in results[record_type][0]
    }))
    has_non_global = any(
        not ipaddress.ip_address(address).is_global
        for address in addresses
    )
    resolved = any(
        result_status == "AVAILABLE"
        for _, result_status in results.values()
    )
    return addresses, has_non_global, resolved


def analyze_dns_records(host: str) -> DnsAnalysis:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        address = str(literal)
        return DnsAnalysis(
            status="NOT_APPLICABLE",
            findings={
                "normalized_domain": host.lower(),
                "domain_format_valid": True,
                "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []},
                "record_status": {record_type: "NOT_APPLICABLE" for record_type in DNS_RECORD_TYPES},
                "addresses": [address] if literal.is_global else [],
                "dns_resolution_status": "NOT_APPLICABLE",
                "spf": [],
                "dmarc": [],
                "registration_status": "NOT_CONFIGURED",
            },
            addresses=(address,),
            contains_non_global_address=not literal.is_global,
        )

    query_types = (*DNS_RECORD_TYPES, "DMARC")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(query_types)) as executor:
        futures = {
            record_type: executor.submit(
                _query_record,
                f"_dmarc.{host}" if record_type == "DMARC" else host,
                "TXT" if record_type == "DMARC" else record_type,
            )
            for record_type in query_types
        }
        results = {record_type: future.result() for record_type, future in futures.items()}

    records = {record_type: results[record_type][0] for record_type in DNS_RECORD_TYPES}
    record_status = {
        record_type: results[record_type][1]
        for record_type in DNS_RECORD_TYPES
    }
    dmarc_records = results["DMARC"][0]
    record_status["DMARC"] = results["DMARC"][1]

    addresses = tuple(sorted({
        address
        for record_type in ("A", "AAAA")
        for address in records[record_type]
    }))
    contains_non_global = any(
        not ipaddress.ip_address(address).is_global
        for address in addresses
    )
    if contains_non_global:
        return DnsAnalysis(
            status="BLOCKED_PRIVATE_ADDRESS",
            findings={
                "normalized_domain": host.lower(),
                "domain_format_valid": True,
                "records": {**records, "A": [], "AAAA": []},
                "record_status": record_status,
                "addresses": [],
                "dns_resolution_status": "BLOCKED_PRIVATE_ADDRESS",
                "spf": [],
                "dmarc": [],
                "registration_status": "NOT_CONFIGURED",
            },
            addresses=(),
            contains_non_global_address=True,
        )

    successful_queries = sum(value == "AVAILABLE" for value in record_status.values())
    unavailable_queries = sum(value == "UNAVAILABLE" for value in record_status.values())
    address_query_unavailable = any(
        record_status[record_type] == "UNAVAILABLE"
        for record_type in ("A", "AAAA")
    )
    address_query_completed = any(
        record_status[record_type] in {"AVAILABLE", "NO_RECORD"}
        for record_type in ("A", "AAAA")
    )
    if addresses:
        resolution_status = "RESOLVED"
    elif address_query_unavailable:
        resolution_status = "UNAVAILABLE"
    elif address_query_completed:
        resolution_status = "NO_RECORDS"
    else:
        resolution_status = "UNAVAILABLE"
    if unavailable_queries and successful_queries:
        overall_status = "PARTIAL"
    elif unavailable_queries:
        overall_status = "UNAVAILABLE"
    elif successful_queries:
        overall_status = "AVAILABLE"
    else:
        overall_status = "NO_RECORDS"

    return DnsAnalysis(
        status=overall_status,
        findings={
            "normalized_domain": host.lower(),
            "domain_format_valid": True,
            "records": records,
            "record_status": record_status,
            "addresses": list(addresses),
            "dns_resolution_status": resolution_status,
            "spf": [
                value for value in records["TXT"]
                if value.lower().startswith("v=spf1")
            ],
            "dmarc": [
                value for value in dmarc_records
                if value.lower().startswith("v=dmarc1")
            ],
            "registration_status": "NOT_CONFIGURED",
        },
        addresses=addresses,
    )
