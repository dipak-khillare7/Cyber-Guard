import json
from typing import Optional, Any
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.core.logging import get_logger

logger = get_logger("audit_service")


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        action: str,
        user_id: Optional[int] = None,
        owner_user_id: Optional[int] = None,
        username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "SUCCESS",
        metadata: Optional[dict[str, Any]] = None
    ) -> AuditLog:
        """
        Creates an immutable audit log entry in the database.
        """
        try:
            metadata_str = json.dumps(metadata) if metadata else None
            audit_entry = AuditLog(
                owner_user_id=owner_user_id if owner_user_id is not None else user_id,
                user_id=user_id,
                username=username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                user_agent=user_agent,
                status=status,
                metadata_json=metadata_str
            )
            db.add(audit_entry)
            db.commit()
            db.refresh(audit_entry)
            logger.info(f"AUDIT LOG: action={action} user={username or 'Anonymous'} status={status} id={audit_entry.id}")
            return audit_entry
        except Exception as e:
            db.rollback()
            logger.error("Failed to write audit log entry (%s)", type(e).__name__)
            raise e

    @staticmethod
    def get_audit_logs(
        db: Session,
        page: int = 1,
        limit: int = 20,
        action: Optional[str] = None,
        username: Optional[str] = None,
        owner_user_id: Optional[int] = None,
    ) -> tuple[list[AuditLog], int]:
        """
        Retrieves paginated audit logs for administration review.
        """
        query = db.query(AuditLog)
        if owner_user_id is not None:
            query = query.filter(AuditLog.owner_user_id == owner_user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        if username:
            query = query.filter(AuditLog.username.ilike(f"%{username}%"))

        total = query.count()
        offset = (page - 1) * limit
        items = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
        return items, total
