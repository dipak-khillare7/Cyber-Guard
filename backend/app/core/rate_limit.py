import hashlib
import hmac
import threading
import time
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.models.rate_limit_bucket import RateLimitBucket


class RateLimitStorageUnavailable(RuntimeError):
    pass


class DatabaseRateLimiter:
    def __init__(self) -> None:
        self._cleanup_lock = threading.Lock()
        self._checks = 0

    def check(
        self,
        db: Session,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> int:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate-limit values must be positive.")

        now = int(time.time())
        window_start = now - (now % window_seconds)
        digest = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            f"{window_seconds}:{window_start}:{key}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        try:
            dialect = db.get_bind().dialect.name
            values = {
                "bucket_key": digest,
                "window_start": window_start,
                "hit_count": 1,
            }
            if dialect == "sqlite":
                insert_statement = sqlite_insert(RateLimitBucket).values(**values)
                statement = insert_statement.on_conflict_do_update(
                    index_elements=[RateLimitBucket.bucket_key],
                    set_={"hit_count": RateLimitBucket.hit_count + 1},
                )
            elif dialect == "mysql":
                insert_statement = mysql_insert(RateLimitBucket).values(**values)
                statement = insert_statement.on_duplicate_key_update(
                    hit_count=RateLimitBucket.hit_count + 1,
                )
            else:
                raise RateLimitStorageUnavailable("Unsupported rate-limit database.")

            db.execute(statement)
            hit_count = db.execute(
                select(RateLimitBucket.hit_count).where(
                    RateLimitBucket.bucket_key == digest
                )
            ).scalar_one()

            if self._should_cleanup():
                db.execute(
                    delete(RateLimitBucket).where(
                        RateLimitBucket.window_start < now - 3600
                    )
                )
            db.commit()
        except RateLimitStorageUnavailable:
            db.rollback()
            raise
        except SQLAlchemyError as exc:
            db.rollback()
            raise RateLimitStorageUnavailable("Rate-limit storage is unavailable.") from exc

        if hit_count > limit:
            return max(1, window_start + window_seconds - now)
        return 0

    def _should_cleanup(self) -> bool:
        with self._cleanup_lock:
            self._checks += 1
            return self._checks % 256 == 0


rate_limiter = DatabaseRateLimiter()


def enforce_rate_limit(
    db: Session,
    key: str,
    *,
    limit: int,
    window_seconds: int = 60,
    action: str,
) -> None:
    try:
        retry_after = rate_limiter.check(
            db,
            key,
            limit=limit,
            window_seconds=window_seconds,
        )
    except RateLimitStorageUnavailable as exc:
        logger.error("Rate-limit storage unavailable (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail={
                "code": "RATE_LIMIT_UNAVAILABLE",
                "message": "Request cannot be processed at this time.",
            },
        ) from exc

    if retry_after:
        logger.warning("Rate limit exceeded for %s", action)
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
