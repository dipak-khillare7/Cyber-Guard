from typing import Generator, Optional, List
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.config import settings
from app.core.security import decode_access_token
from app.core.rate_limit import enforce_rate_limit
from app.models.user import User, UserRole
from app.services.user_service import UserService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login", auto_error=False)


def enforce_ingestion_ip_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(
        db,
        f"ingestion:ip:{client_ip}",
        limit=120,
        window_seconds=60,
        action="event ingestion",
    )


def get_current_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme)
) -> User:
    """
    Validates JWT access token and returns authenticated user.
    Raises HTTP 401 if missing or invalid.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing subject claim.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identification in token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated. Contact administrator.",
        )
    
    return user


def get_current_user_optional(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[User]:
    """
    Optional authentication dependency. Returns User if valid token present, else None.
    """
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if not payload or not payload.get("sub"):
            return None
        user_id = int(payload.get("sub"))
        user = UserService.get_by_id(db, user_id)
        if user and user.is_active:
            return user
        return None
    except Exception:
        return None


class RoleChecker:
    """
    Role-Based Access Control (RBAC) Dependency.
    Verifies that the authenticated user possesses one of the allowed roles.
    """
    def __init__(self, allowed_roles: List[UserRole]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Role '{current_user.role}' is not authorized to access this resource. Allowed roles: {[r.value for r in self.allowed_roles]}"
            )
        return current_user


# Role-specific helpers
require_admin = RoleChecker([UserRole.ADMIN])
require_analyst = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
