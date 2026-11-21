import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from app.services.website_intelligence.dns_analyzer import resolve_public_addresses

TLS_TIMEOUT_SECONDS = 3.0
TLS_PORT = 443


def inspect_tls(
    host: str,
    *,
    enabled: bool,
    not_applicable: bool = False,
    disabled_reason: str = "The submitted URL does not use HTTPS.",
) -> tuple[str, dict[str, Any]]:
    if not enabled:
        status = "NOT_APPLICABLE" if not_applicable else "NOT_CHECKED"
        return status, {
            "checked": False,
            "reason": disabled_reason,
        }

    addresses, has_non_global, resolved = resolve_public_addresses(host)
    if has_non_global:
        return "BLOCKED_PRIVATE_ADDRESS", {
            "checked": False,
            "reason": "TLS inspection was blocked because DNS resolved to a non-public address.",
        }
    if not resolved or not addresses:
        return "UNAVAILABLE", {
            "checked": False,
            "reason": "Public DNS resolution was unavailable for the TLS check.",
        }

    address = addresses[0]
    parsed_ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
    raw_socket = socket.socket(family, socket.SOCK_STREAM)
    raw_socket.settimeout(TLS_TIMEOUT_SECONDS)
    try:
        target = (address, TLS_PORT, 0, 0) if parsed_ip.version == 6 else (address, TLS_PORT)
        raw_socket.connect(target)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            certificate = tls_socket.getpeercert()
            expiration = certificate.get("notAfter")
            expiration_utc = (
                datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(expiration),
                    tz=timezone.utc,
                ).isoformat()
                if expiration
                else None
            )
            issuer = ", ".join(
                f"{key}={value}"
                for rdn in certificate.get("issuer", ())
                for key, value in rdn
            )
            return "VALID", {
                "checked": True,
                "port": TLS_PORT,
                "hostname_match": True,
                "certificate_valid": True,
                "expires_at": expiration_utc,
                "issuer": issuer[:256] or None,
                "tls_version": tls_socket.version(),
            }
    except ssl.SSLCertVerificationError:
        return "INVALID", {
            "checked": True,
            "port": TLS_PORT,
            "hostname_match": None,
            "certificate_valid": False,
            "reason": "The certificate chain or hostname could not be verified.",
        }
    except (socket.timeout, TimeoutError):
        return "TIMEOUT", {
            "checked": True,
            "port": TLS_PORT,
            "reason": "The TLS connection timed out.",
        }
    except (OSError, ssl.SSLError):
        return "UNAVAILABLE", {
            "checked": True,
            "port": TLS_PORT,
            "reason": "A TLS connection could not be established.",
        }
    finally:
        raw_socket.close()
