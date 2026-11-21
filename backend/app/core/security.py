import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import jwt
import bcrypt
from app.core.config import settings

NETWORK_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "ICMPV6",
    "HTTP",
    "HTTPS",
    "TLS",
    "DNS",
    "SSH",
    "FTP",
    "SMTP",
    "GRE",
    "ESP",
    "SCTP",
    "QUIC",
    "OTHER",
}


def format_iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """
    Formats a naive or tz-aware Python datetime into an unambiguous ISO 8601 UTC string ending with 'Z'.
    Example: 2026-10-09 06:30:00 -> "2026-10-09T06:30:00Z"
    """
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    return str(dt)


def hash_password(password: str) -> str:
    """
    Hashes password using native bcrypt.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    pwd_bytes = password.encode('utf-8')
    if len(pwd_bytes) > 72:
        pwd_bytes = pwd_bytes[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies plain password against hashed password using native bcrypt.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        pwd_bytes = plain_password.encode('utf-8')
        if len(pwd_bytes) > 72:
            pwd_bytes = pwd_bytes[:72]
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(subject: Any, role: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates JWT access token with payload claims.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": str(subject),
        "role": role,
        "exp": int(expire.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp())
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decodes and validates JWT token. Returns payload dict or None.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, ValueError):
        return None


def sanitize_input_string(value: Optional[str]) -> Optional[str]:
    """
    Sanitizes general input strings to prevent injection vectors.
    """
    if value is None:
        return None
    cleaned = re.sub(r"[<>]", "", value.strip())
    return cleaned


def is_valid_ip(ip_str: Optional[str]) -> bool:
    """
    Validates IPv4 and IPv6 address strings.
    """
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_valid_port(port: Optional[int]) -> bool:
    """
    Validates networking port range (0-65535).
    """
    if port is None:
        return True
    return 0 <= port <= 65535


def normalize_network_protocol(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Unsupported network protocol.")
    normalized = value.strip().upper()
    if normalized in NETWORK_PROTOCOLS:
        return normalized
    if normalized.isdecimal() and len(normalized) <= 3 and 0 <= int(normalized) <= 255:
        return normalized
    raise ValueError("Unsupported network protocol.")
