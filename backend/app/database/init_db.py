from sqlalchemy import inspect, text
from app.database.connection import engine, SessionLocal, Base
from app.core.logging import logger
from app.models import SecurityEvent, Alert, Incident, ResponseAction, User, AuditLog
from app.services.user_service import UserService


def init_db() -> None:
    """
    Creates all database tables defined in the ORM models if they do not exist
    and seeds an administrator only when an initial password is configured.
    """
    logger.info("Initializing database tables...")
    try:
        Base.metadata.create_all(bind=engine)
        _upgrade_user_schema()
        _upgrade_website_assessment_schema()
        logger.info("Database tables created/verified successfully.")
        
        # Seed initial admin
        db = SessionLocal()
        try:
            UserService.seed_initial_admin(db)
        finally:
            db.close()
    except Exception as e:
        logger.error("Failed to initialize database (%s)", type(e).__name__)
        raise


def _upgrade_user_schema() -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    additions = {
        "full_name": "VARCHAR(150) NULL",
        "email_verified": "BOOLEAN NOT NULL DEFAULT TRUE",
        "email_verification_token_hash": "VARCHAR(64) NULL",
        "email_verification_expires_at": "DATETIME NULL",
        "email_verification_attempts": "INTEGER NOT NULL DEFAULT 0",
        "verification_last_sent_at": "DATETIME NULL",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))
    ownership_columns = {
        "security_events": "owner_user_id",
        "alerts": "owner_user_id",
        "incidents": "owner_user_id",
    }
    with engine.begin() as connection:
        for table, column in ownership_columns.items():
            table_columns = {item["name"] for item in inspect(engine).get_columns(table)}
            if column not in table_columns:
                connection.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER NULL")
                )


def _upgrade_website_assessment_schema() -> None:
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("website_assessments")
    }
    additions = {
        "url_origin": "VARCHAR(2048) NULL",
        "risk_score": "FLOAT NULL",
        "analysis_status": "VARCHAR(32) NOT NULL DEFAULT 'LEGACY'",
        "engine_version": "VARCHAR(32) NOT NULL DEFAULT 'legacy'",
        "scoring_version": "VARCHAR(32) NOT NULL DEFAULT 'legacy'",
        "dns_status": "VARCHAR(32) NOT NULL DEFAULT 'NOT_CHECKED'",
        "dns_findings_json": "TEXT NULL",
        "ssl_status": "VARCHAR(32) NOT NULL DEFAULT 'NOT_CHECKED'",
        "ssl_findings_json": "TEXT NULL",
        "evidence_json": "TEXT NULL",
        "risk_factors_json": "TEXT NULL",
        "risk_reducing_factors_json": "TEXT NULL",
        "limitations_json": "TEXT NULL",
        "recommendations_json": "TEXT NULL",
        "idempotency_key": "VARCHAR(128) NULL",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(
                    text(f"ALTER TABLE website_assessments ADD COLUMN {name} {definition}")
                )
        from app.models.website_assessment import WebsiteAssessment

        idempotency_index = next(
            index
            for index in WebsiteAssessment.__table__.indexes
            if index.name == "uq_website_assessments_owner_idempotency_key"
        )
        idempotency_index.create(bind=connection, checkfirst=True)
