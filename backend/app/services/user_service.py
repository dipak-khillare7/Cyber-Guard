from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import hash_password, verify_password
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("user_service")


class UserService:
    @staticmethod
    def get_by_id(db: Session, user_id: int) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_by_username(db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def create_user(
        db: Session,
        user_in: UserCreate,
        *,
        full_name: Optional[str] = None,
        email_verified: bool = True,
        verification_token_hash: Optional[str] = None,
        verification_expires_at: Optional[datetime] = None,
    ) -> User:
        hashed_pwd = hash_password(user_in.password)
        db_user = User(
            username=user_in.username.strip(),
            email=user_in.email.strip().lower(),
            full_name=full_name,
            hashed_password=hashed_pwd,
            role=user_in.role,
            is_active=True,
            email_verified=email_verified,
            email_verification_token_hash=verification_token_hash,
            email_verification_expires_at=verification_expires_at,
            verification_last_sent_at=datetime.now(timezone.utc).replace(tzinfo=None)
            if verification_token_hash else None,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        logger.info(f"Created new user '{db_user.username}' with role '{db_user.role}'")
        return db_user

    @staticmethod
    def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
        user = UserService.get_by_username(db, username_or_email)
        if not user:
            user = UserService.get_by_email(db, username_or_email.lower())
        
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        if not user.email_verified:
            return user
        
        # Update last login timestamp
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def seed_initial_admin(db: Session) -> Optional[User]:
        """
        Seeds an initial admin user when a password is configured.
        """
        admin = UserService.get_by_username(db, settings.ADMIN_USERNAME)
        if not admin:
            if not settings.ADMIN_INITIAL_PASSWORD:
                logger.warning(
                    "Skipping initial administrator seed because ADMIN_INITIAL_PASSWORD is not configured."
                )
                return None
            admin_in = UserCreate(
                username=settings.ADMIN_USERNAME,
                email=settings.ADMIN_EMAIL,
                password=settings.ADMIN_INITIAL_PASSWORD,
                role=UserRole.ADMIN
            )
            admin = UserService.create_user(db, admin_in)
            logger.info("Seeded initial administrator account.")
        return admin

    @staticmethod
    def get_users(db: Session, page: int = 1, limit: int = 20) -> tuple[list[User], int]:
        total = db.query(User).count()
        offset = (page - 1) * limit
        items = db.query(User).order_by(User.id.asc()).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def update_user(db: Session, user: User, user_in: UserUpdate) -> User:
        update_data = user_in.model_dump(exclude_unset=True)
        password = update_data.pop("password", None)
        if password is not None:
            user.hashed_password = hash_password(password)
        if "email" in update_data:
            update_data["email"] = str(update_data["email"]).strip().lower()
        for field, value in update_data.items():
            setattr(user, field, value)
        db.commit()
        db.refresh(user)
        logger.info("Updated user id=%s", user.id)
        return user
