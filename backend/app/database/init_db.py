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
        "analyst_request_status": "VARCHAR(20) NULL",
        "reviewed_by_user_id": "INTEGER NULL",
        "reviewed_at": "DATETIME NULL",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))
    ownership_columns = {
        "security_events": "owner_user_id",
        "alerts": "owner_user_id",
        "incidents": "owner_user_id",
        "response_actions": "owner_user_id",
        "audit_logs": "owner_user_id",
    }
    with engine.begin() as connection:
        for table, column in ownership_columns.items():
            table_columns = {item["name"] for item in inspect(engine).get_columns(table)}
            if column not in table_columns:
                connection.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER NULL")
                )
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE alerts SET owner_user_id = ("
            "SELECT owner_user_id FROM security_events WHERE security_events.id = alerts.event_id"
            ") WHERE owner_user_id IS NULL AND event_id IS NOT NULL AND EXISTS ("
            "SELECT 1 FROM security_events WHERE security_events.id = alerts.event_id "
            "AND security_events.owner_user_id IS NOT NULL)"
        ))
        connection.execute(text(
            "UPDATE incidents SET owner_user_id = ("
            "SELECT owner_user_id FROM alerts WHERE alerts.id = incidents.alert_id"
            ") WHERE owner_user_id IS NULL AND alert_id IS NOT NULL AND EXISTS ("
            "SELECT 1 FROM alerts WHERE alerts.id = incidents.alert_id "
            "AND alerts.owner_user_id IS NOT NULL)"
        ))
        connection.execute(text(
            "UPDATE response_actions SET owner_user_id = ("
            "SELECT owner_user_id FROM incidents WHERE incidents.id = response_actions.incident_id"
            ") WHERE owner_user_id IS NULL AND EXISTS ("
            "SELECT 1 FROM incidents WHERE incidents.id = response_actions.incident_id "
            "AND incidents.owner_user_id IS NOT NULL)"
        ))
