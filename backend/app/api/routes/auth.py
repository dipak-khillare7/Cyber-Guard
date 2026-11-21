import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import (
    AuthMessageResponse,
    LoginRequest,
    RegistrationRequest,
    ResendVerificationRequest,
    TokenResponse,
    UserResponse,
    UserCreate,
    UserUpdate,
    VerificationRequest,
)
from app.services.user_service import UserService
from app.services.audit_service import AuditService
from app.services.email_service import EmailConfigurationError, EmailDeliveryError, EmailService
from app.core.security import create_access_token
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.api.deps import get_current_user, require_admin

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


def _enforce_rate_limit(
    db: Session,
    request: Request,
    action: str,
    limit: int,
    window_seconds: int = 60,
    subject: Optional[str] = None,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    key = f"{action}:subject:{subject}" if subject else f"{action}:ip:{client_ip}"
    enforce_rate_limit(
        db,
        key,
        limit=limit,
        window_seconds=window_seconds,
        action=action,
    )


def _hash_verification_otp(otp: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        otp.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _new_verification_otp() -> tuple[str, str, datetime]:
    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = _hash_verification_otp(otp)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(tzinfo=None)
    return otp, otp_hash, expires_at


def _new_public_username(db: Session, email: str) -> str:
    local_part = email.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9_]+", "_", local_part).strip("_")[:40] or "user"
    if len(base) < 3:
        base = f"{base}user"[:40]
    candidate = base
    suffix = 1
    while UserService.get_by_username(db, candidate):
        candidate = f"{base[:45]}_{suffix}"
        suffix += 1
    return candidate


@router.post(
    "/register",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register an unverified public account",
)
def register(
    registration: RegistrationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(db, request, "register", 5)
    if registration.password != registration.confirm_password:
        raise HTTPException(status_code=422, detail="Password and confirmation do not match.")
    if not EmailService.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification is not configured. Please contact the system administrator.",
        )

    email = str(registration.email).strip().lower()
    if UserService.get_by_email(db, email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    otp, otp_hash, expires_at = _new_verification_otp()
    user_in = UserCreate(
        username=_new_public_username(db, email),
        email=email,
        password=registration.password,
    )
    try:
        user = UserService.create_user(
            db,
            user_in,
            full_name=registration.full_name,
            email_verified=False,
            verification_token_hash=otp_hash,
            verification_expires_at=expires_at,
        )
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email is already registered.") from exc

    try:
        EmailService.send_verification_email(user.email, user.full_name or "", otp)
    except (EmailConfigurationError, EmailDeliveryError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Your account was created, but the verification email could not be sent. Please request another email.",
        ) from exc

    AuditService.log_event(
        db=db,
        action="USER_REGISTERED",
        user_id=user.id,
        username=user.username,
        ip_address=request.client.host if request.client else "unknown",
        status="SUCCESS",
    )
    return AuthMessageResponse(message="Account created. Please check your email for a 6-digit verification code.")


@router.post("/verify-email", response_model=AuthMessageResponse, summary="Verify an email address")
def verify_email(
    verification: VerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(db, request, "verify-email", 10)
    email = str(verification.email).strip().lower()
    email_key = hashlib.sha256(email.encode("utf-8")).hexdigest()
    _enforce_rate_limit(
        db,
        request,
        "verify-email-account",
        5,
        window_seconds=600,
        subject=email_key,
    )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = UserService.get_by_email(db, email)
    if (
        not user
        or user.email_verified
        or not user.email_verification_token_hash
        or not user.email_verification_expires_at
        or user.email_verification_expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code is invalid or has expired. Request a new code.",
        )

    provided_hash = _hash_verification_otp(verification.otp)
    if not hmac.compare_digest(user.email_verification_token_hash, provided_hash):
        db.query(User).filter(
            User.id == user.id,
            User.email_verification_token_hash == user.email_verification_token_hash,
            User.email_verification_expires_at > now,
            User.email_verified.is_(False),
        ).update(
            {User.email_verification_attempts: User.email_verification_attempts + 1},
            synchronize_session=False,
        )
        db.refresh(user)
        if user.email_verification_attempts >= 5:
            db.query(User).filter(
                User.id == user.id,
                User.email_verification_token_hash == user.email_verification_token_hash,
                User.email_verified.is_(False),
            ).update(
                {
                    User.email_verification_token_hash: None,
                    User.email_verification_expires_at: None,
                },
                synchronize_session=False,
            )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code is invalid or has expired. Request a new code.",
        )

    updated = db.query(User).filter(
        User.id == user.id,
        User.email_verification_token_hash == provided_hash,
        User.email_verification_expires_at > now,
        User.email_verified.is_(False),
    ).update(
        {
            User.email_verified: True,
            User.email_verification_token_hash: None,
            User.email_verification_expires_at: None,
            User.email_verification_attempts: 0,
        },
        synchronize_session=False,
    )
    if updated != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code is invalid or has expired. Request a new code.",
        )
    db.commit()
    return AuthMessageResponse(message="Your email has been verified successfully. You can now log in.")


@router.post("/resend-verification", response_model=AuthMessageResponse, summary="Resend email verification")
def resend_verification(
    resend: ResendVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    _enforce_rate_limit(db, request, "resend-verification", 3)
    if not EmailService.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification is not configured. Please contact the system administrator.",
        )

    generic_message = "If the account is eligible, check your inbox for verification instructions."
    user = UserService.get_by_email(db, str(resend.email).strip().lower())
    if not user or user.email_verified or not user.is_active:
        return AuthMessageResponse(message=generic_message)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if user.verification_last_sent_at and (now - user.verification_last_sent_at).total_seconds() < 60:
        return AuthMessageResponse(message=generic_message)

    otp, otp_hash, expires_at = _new_verification_otp()
    user.email_verification_token_hash = otp_hash
    user.email_verification_expires_at = expires_at
    user.email_verification_attempts = 0
    user.verification_last_sent_at = now
    db.commit()

    try:
        EmailService.send_verification_email(user.email, user.full_name or "", otp)
    except (EmailConfigurationError, EmailDeliveryError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The verification email could not be sent. Please try again later.",
        ) from exc
    return AuthMessageResponse(message=generic_message)


@router.post("/login", response_model=TokenResponse, summary="User Authentication & Token Generation")
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticates username/email and password, returning JWT access token and user profile.
    Generates audit log entry for authentication outcome.
    """
    ip_addr = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    _enforce_rate_limit(db, request, "login", 10)
    user = UserService.authenticate_user(db, login_data.username, login_data.password)
    if not user:
        AuditService.log_event(
            db=db,
            action="LOGIN_FAILURE",
            ip_address=ip_addr,
            user_agent=user_agent,
            status="FAILURE",
            metadata={"reason": "Invalid credentials or inactive account"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.email_verified:
        AuditService.log_event(
            db=db,
            action="LOGIN_FAILURE",
            user_id=user.id,
            username=user.username,
            ip_address=ip_addr,
            user_agent=user_agent,
            status="FAILURE",
            metadata={"reason": "Email verification required"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification is required before you can log in.",
        )

    # Generate JWT
    token = create_access_token(subject=user.id, role=user.role.value)

    AuditService.log_event(
        db=db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        username=user.username,
        ip_address=ip_addr,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"role": user.role.value}
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/token", response_model=TokenResponse, include_in_schema=False)
def login_oauth2_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    OAuth2 form-compatible login endpoint for FastAPI Swagger UI login modal.
    """
    login_req = LoginRequest(username=form_data.username, password=form_data.password)
    return login(login_req, request, db)


@router.get("/me", response_model=UserResponse, summary="Get Current Authenticated User Profile")
def get_me(current_user: UserResponse = Depends(get_current_user)):
    """
    Returns profile information of the currently authenticated session.
    """
    return current_user


@router.post("/logout", summary="Session Logout")
def logout(
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logs out current session and records audit event.
    """
    ip_addr = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    AuditService.log_event(
        db=db,
        action="LOGOUT",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=ip_addr,
        user_agent=user_agent,
        status="SUCCESS"
    )
    return {"message": "Session logged out successfully."}


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Create New User (Admin Only)")
def create_user(
    user_in: UserCreate,
    request: Request,
    admin_user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Creates a new user account with specified role. Admin authorization required.
    """
    existing_username = UserService.get_by_username(db, user_in.username)
    if existing_username:
        raise HTTPException(status_code=400, detail="Username is already taken.")
    
    existing_email = UserService.get_by_email(db, user_in.email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email is already registered.")

    new_user = UserService.create_user(db, user_in)
    ip_addr = request.client.host if request.client else "unknown"

    AuditService.log_event(
        db=db,
        action="USER_CREATED",
        user_id=admin_user.id,
        username=admin_user.username,
        resource_type="USER",
        resource_id=str(new_user.id),
        ip_address=ip_addr,
        status="SUCCESS",
        metadata={"created_username": new_user.username, "assigned_role": new_user.role.value}
    )
    return new_user


@router.get("/users", summary="List All Users (Admin Only)")
def list_users(
    page: int = 1,
    limit: int = 20,
    admin_user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Lists users for user management. Admin authorization required.
    """
    items, total = UserService.get_users(db, page=page, limit=limit)
    return {
        "items": [UserResponse.model_validate(u) for u in items],
        "total": total,
        "page": page,
        "limit": limit
    }


@router.patch(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Update a user account or role (Admin Only)",
)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    admin_user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    target_user = UserService.get_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    update_fields = user_update.model_dump(exclude_unset=True)
    updated_email = update_fields.get("email")
    if updated_email is not None:
        existing_email = UserService.get_by_email(db, str(updated_email).strip().lower())
        if existing_email and existing_email.id != target_user.id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    next_role = update_fields.get("role", target_user.role)
    next_active = update_fields.get("is_active", target_user.is_active)
    is_removing_active_admin = (
        target_user.role == UserRole.ADMIN
        and target_user.is_active
        and (next_role != UserRole.ADMIN or not next_active)
    )
    if is_removing_active_admin:
        active_admins = db.query(User.id).filter(
            User.role == UserRole.ADMIN,
            User.is_active.is_(True),
        ).with_for_update().all()
        if len(active_admins) <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The last active administrator cannot be demoted or deactivated.",
            )

    previous_role = target_user.role.value
    previous_active = target_user.is_active
    try:
        updated_user = UserService.update_user(db, target_user, user_update)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User update conflicts with existing account data.",
        ) from exc

    AuditService.log_event(
        db=db,
        action="USER_UPDATED",
        user_id=admin_user.id,
        username=admin_user.username,
        resource_type="USER",
        resource_id=str(updated_user.id),
        ip_address=request.client.host if request.client else "unknown",
        status="SUCCESS",
        metadata={
            "old_role": previous_role,
            "new_role": updated_user.role.value,
            "old_is_active": previous_active,
            "new_is_active": updated_user.is_active,
            "changed_fields": sorted(update_fields.keys()),
        },
    )
    return updated_user
