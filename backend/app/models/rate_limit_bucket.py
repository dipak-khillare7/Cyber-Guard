from sqlalchemy import Column, Integer, String

from app.database.connection import Base


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    bucket_key = Column(String(64), primary_key=True, index=True)
    window_start = Column(Integer, nullable=False, index=True)
    hit_count = Column(Integer, nullable=False, default=0)
