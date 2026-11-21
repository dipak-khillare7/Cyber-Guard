import base64
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import httpx
import idna

from app.core.config import settings
from app.services.website_intelligence.providers.base import (
    ProviderStatus,
    ThreatIntelResult,
)


class VirusTotalProvider:
    """Read-only VirusTotal v3 report lookups; this client never submits scan jobs."""

    PROVIDER = "VIRUSTOTAL"
    API_BASE_URL = "https://www.virustotal.com/api/v3"
    MAX_RESPONSE_BYTES = 1_048_576
    PRIVATE_SUFFIXES = (
        ".localhost",
        ".local",
        ".internal",
        ".test",
        ".example",
        ".invalid",
        ".onion",
        ".home",
        ".lan",
        ".corp",
        ".intranet",
        ".private",
    )
    ANALYSIS_STAT_KEYS = (
        "malicious",
        "suspicious",
        "undetected",
        "harmless",
        "timeout",
        "failure",
    )

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        timeout_seconds: float = 5.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("VirusTotal timeout must be positive.")
        configured_key = (
            settings.VIRUSTOTAL_API_KEY.get_secret_value()
            if api_key is None
            else api_key
        )
        self._api_key = configured_key.strip()
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def get_domain_report(
        self,
        domain: str,
        *,
        consent_to_share: bool = False,
    ) -> ThreatIntelResult:
        normalized = self._normalize_domain(domain)
        if normalized is None:
            return self._result(
                "DOMAIN",
                domain,
                ProviderStatus.INVALID_INDICATOR,
                error_code="INVALID_OR_NON_PUBLIC_DOMAIN",
            )
        if not consent_to_share:
            return self._result("DOMAIN", normalized, ProviderStatus.NOT_QUERIED)
        return self._get_report(
            "DOMAIN",
            normalized,
            f"/domains/{quote(normalized, safe='')}",
        )

    def get_ip_report(
        self,
        ip_address: str,
        *,
        consent_to_share: bool = False,
    ) -> ThreatIntelResult:
        normalized = self._normalize_public_ip(ip_address)
        if normalized is None:
            return self._result(
                "IP",
                ip_address,
                ProviderStatus.INVALID_INDICATOR,
                error_code="INVALID_OR_NON_PUBLIC_IP",
            )
        if not consent_to_share:
            return self._result("IP", normalized, ProviderStatus.NOT_QUERIED)
        return self._get_report(
            "IP",
            normalized,
            f"/ip_addresses/{quote(normalized, safe='')}",
        )

    def get_url_report(
        self,
        url: str,
        *,
        consent_to_share: bool = False,
    ) -> ThreatIntelResult:
        normalized = self.normalize_url(url)
        if normalized is None:
            return self._result(
                "URL",
                url,
                ProviderStatus.INVALID_INDICATOR,
                error_code="INVALID_OR_NON_PUBLIC_URL",
            )
        if not consent_to_share:
            return self._result("URL", normalized, ProviderStatus.NOT_QUERIED)

        url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
        return self._get_report("URL", normalized, f"/urls/{url_id}")

    def _get_report(
        self,
        indicator_type: str,
        indicator: str,
        path: str,
    ) -> ThreatIntelResult:
        if not self._api_key:
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.NOT_CONFIGURED,
                error_code="PROVIDER_NOT_CONFIGURED",
            )

        try:
            with httpx.Client(
                timeout=httpx.Timeout(self._timeout_seconds),
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                with client.stream(
                    "GET",
                    f"{self.API_BASE_URL}{path}",
                    headers={
                        "accept": "application/json",
                        "x-apikey": self._api_key,
                    },
                ) as response:
                    return self._handle_response(
                        response,
                        indicator_type,
                        indicator,
                    )
        except httpx.TimeoutException:
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.TIMEOUT,
                error_code="PROVIDER_TIMEOUT",
            )
        except httpx.RequestError:
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.UNAVAILABLE,
                error_code="PROVIDER_CONNECTION_ERROR",
            )

    def _handle_response(
        self,
        response: httpx.Response,
        indicator_type: str,
        indicator: str,
    ) -> ThreatIntelResult:
        if response.status_code == 404:
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.NO_RECORD,
                provider_http_status=response.status_code,
            )
        if response.status_code in {401, 403, 429} or response.status_code >= 500:
            status_by_code = {
                401: ProviderStatus.AUTHENTICATION_ERROR,
                403: ProviderStatus.PROVIDER_FORBIDDEN,
                429: ProviderStatus.RATE_LIMITED,
            }
            result_status = status_by_code.get(
                response.status_code,
                ProviderStatus.UNAVAILABLE,
            )
            return self._result(
                indicator_type,
                indicator,
                result_status,
                provider_http_status=response.status_code,
                retry_after_seconds=self._retry_after(response),
                error_code=f"PROVIDER_HTTP_{response.status_code}",
            )
        if response.status_code < 200 or response.status_code >= 300:
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.UNAVAILABLE,
                provider_http_status=response.status_code,
                error_code=f"PROVIDER_HTTP_{response.status_code}",
            )

        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > self.MAX_RESPONSE_BYTES:
                return self._result(
                    indicator_type,
                    indicator,
                    ProviderStatus.UNAVAILABLE,
                    provider_http_status=response.status_code,
                    error_code="PROVIDER_RESPONSE_TOO_LARGE",
                )
            body.extend(chunk)

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.UNAVAILABLE,
                provider_http_status=response.status_code,
                error_code="INVALID_PROVIDER_RESPONSE",
            )

        attributes = (
            payload.get("data", {}).get("attributes")
            if isinstance(payload, dict) and isinstance(payload.get("data"), dict)
            else None
        )
        if not isinstance(attributes, dict):
            return self._result(
                indicator_type,
                indicator,
                ProviderStatus.UNAVAILABLE,
                provider_http_status=response.status_code,
                error_code="INVALID_PROVIDER_RESPONSE",
            )

        return self._result(
            indicator_type,
            indicator,
            ProviderStatus.FOUND,
            provider_http_status=response.status_code,
            data=self._normalize_attributes(attributes),
        )

    @classmethod
    def _normalize_attributes(cls, attributes: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        reputation = attributes.get("reputation")
        if isinstance(reputation, int) and not isinstance(reputation, bool):
            normalized["reputation"] = reputation

        stats = attributes.get("last_analysis_stats")
        if isinstance(stats, dict):
            clean_stats = {
                key: value
                for key in cls.ANALYSIS_STAT_KEYS
                if isinstance((value := stats.get(key)), int)
                and not isinstance(value, bool)
                and value >= 0
            }
            if clean_stats:
                normalized["last_analysis_stats"] = clean_stats
                normalized["vendor_count"] = sum(clean_stats.values())

        last_analysis_date = attributes.get("last_analysis_date")
        if isinstance(last_analysis_date, int) and not isinstance(last_analysis_date, bool):
            try:
                normalized["last_analysis_date"] = datetime.fromtimestamp(
                    last_analysis_date,
                    tz=timezone.utc,
                )
            except (OverflowError, OSError, ValueError):
                pass

        return normalized

    @staticmethod
    def _normalize_domain(domain: str) -> Optional[str]:
        if not isinstance(domain, str):
            return None
        candidate = domain.strip().rstrip(".")
        if not candidate or len(candidate) > 253 or any(char in candidate for char in "/:@?#"):
            return None
        try:
            normalized = idna.encode(
                candidate,
                uts46=True,
                std3_rules=True,
            ).decode("ascii").lower()
        except (idna.IDNAError, UnicodeError):
            return None

        if normalized.endswith(VirusTotalProvider.PRIVATE_SUFFIXES):
            return None
        if re.fullmatch(
            r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*",
            normalized,
        ):
            return None
        try:
            ipaddress.ip_address(normalized)
            return None
        except ValueError:
            pass

        labels = normalized.split(".")
        if len(labels) < 2:
            return None
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in labels
        ):
            return None
        return normalized

    @staticmethod
    def _normalize_public_ip(ip_address: str) -> Optional[str]:
        if not isinstance(ip_address, str):
            return None
        try:
            address = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return None
        return str(address) if address.is_global else None

    @classmethod
    def normalize_url(cls, url: str) -> Optional[str]:
        if not isinstance(url, str):
            return None
        candidate = url.strip()
        if (
            not candidate
            or candidate != url
            or "\\" in candidate
            or any(char.isspace() or ord(char) < 32 for char in candidate)
        ):
            return None
        try:
            parts = urlsplit(candidate)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                return None
            if (
                parts.username is not None
                or parts.password is not None
                or "@" in parts.netloc
                or parts.netloc.endswith(":")
            ):
                return None
            port = parts.port
        except ValueError:
            return None

        host = parts.hostname
        if port == 0:
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            normalized_host = cls._normalize_domain(host)
            if normalized_host is None:
                return None
            rendered_host = normalized_host
        else:
            if not address.is_global:
                return None
            rendered_host = f"[{address.compressed}]" if address.version == 6 else str(address)

        if (parts.scheme.lower() == "https" and port == 443) or (
            parts.scheme.lower() == "http" and port == 80
        ):
            port = None
        netloc = rendered_host if port is None else f"{rendered_host}:{port}"
        normalized_parts = SplitResult(
            scheme=parts.scheme.lower(),
            netloc=netloc,
            path=parts.path or "/",
            query=parts.query,
            fragment="",
        )
        return urlunsplit(normalized_parts)

    @classmethod
    def _retry_after(cls, response: httpx.Response) -> Optional[int]:
        value = response.headers.get("Retry-After")
        if value is None:
            return None
        try:
            seconds = int(value)
        except ValueError:
            return None
        return seconds if seconds >= 0 else None

    @classmethod
    def _result(
        cls,
        indicator_type: str,
        indicator: str,
        status: ProviderStatus,
        *,
        provider_http_status: Optional[int] = None,
        retry_after_seconds: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> ThreatIntelResult:
        indicator_hash = (
            hashlib.sha256(indicator.encode("utf-8")).hexdigest()
            if isinstance(indicator, str)
            else None
        )
        return ThreatIntelResult(
            provider=cls.PROVIDER,
            indicator_type=indicator_type,
            indicator_hash=indicator_hash,
            status=status,
            retrieved_at=datetime.now(timezone.utc),
            provider_http_status=provider_http_status,
            retry_after_seconds=retry_after_seconds,
            data=data or {},
            error_code=error_code,
        )
