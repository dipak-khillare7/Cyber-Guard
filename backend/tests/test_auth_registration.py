import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from importlib import import_module

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.models.user import User, UserRole
from app.services.email_service import EmailService


@pytest.fixture
def email_outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(EmailService, "is_configured", staticmethod(lambda: True))

    def capture(email, full_name, otp):
        sent.append({"email": email, "full_name": full_name, "otp": otp})

    monkeypatch.setattr(EmailService, "send_verification_email", staticmethod(capture))
    return sent


@pytest.fixture
def registered_user(client, db_session, email_outbox):
    payload = {
        "full_name": "Test Analyst",
        "email": "new.user@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    response = client.post(f"{settings.API_PREFIX}/auth/register", json=payload)
    assert response.status_code == 201
    user = db_session.query(User).filter_by(email=payload["email"]).one()
    return payload, user, email_outbox


def test_registration_creates_unverified_viewer_and_sends_otp(client, db_session, email_outbox):
    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "New User",
        "email": "viewer@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
        "role": "ADMIN",
    })

    assert response.status_code == 201
    assert "otp" not in response.text.lower()
    user = db_session.query(User).filter_by(email="viewer@example.com").one()
    assert user.email_verified is False
    assert user.role == UserRole.VIEWER
    assert len(email_outbox[0]["otp"]) == 6
    assert email_outbox[0]["otp"].isdigit()
    assert user.email_verification_token_hash == hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        email_outbox[0]["otp"].encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert user.email_verification_token_hash != email_outbox[0]["otp"]
    assert email_outbox[0]["email"] == "viewer@example.com"


def test_email_contains_code_not_verification_link(monkeypatch):
    from app.services import email_service

    sent_messages = []

    class SMTPStub:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def starttls(self, **_):
            pass

        def login(self, *_):
            pass

        def send_message(self, message):
            sent_messages.append(message)
            return {}

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USERNAME", "sender@example.com")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "test-password")
    monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "sender@example.com")
    monkeypatch.setattr(settings, "SMTP_FROM_NAME", "Cyber Guard")
    monkeypatch.setattr(email_service.smtplib, "SMTP", lambda *_, **__: SMTPStub())

    EmailService.send_verification_email("recipient@example.com", "Test User", "012345")

    body = sent_messages[0].get_content()
    assert "Cyber Guard" in body
    assert "012345" in body
    assert "verify-email?" not in body


def test_duplicate_registration_is_rejected(client, registered_user):
    payload, _, _ = registered_user
    response = client.post(f"{settings.API_PREFIX}/auth/register", json=payload)
    assert response.status_code == 409


def test_registration_rejects_invalid_email(client, email_outbox):
    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "Bad Email",
        "email": "not-an-email",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    })
    assert response.status_code == 422
    assert any("email" in error["loc"] for error in response.json()["errors"])
    assert all("input" not in error for error in response.json()["errors"])


def test_registration_rejects_password_mismatch(client, email_outbox):
    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "Mismatch User",
        "email": "mismatch@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "DifferentPassword123!",
    })
    assert response.status_code == 422


def test_registration_fails_safely_without_smtp_configuration(client, db_session, monkeypatch):
    monkeypatch.setattr(EmailService, "is_configured", staticmethod(lambda: False))
    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "No SMTP",
        "email": "nosmtp@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    })
    assert response.status_code == 503
    assert db_session.query(User).filter_by(email="nosmtp@example.com").first() is None


def test_successful_email_verification(client, db_session, registered_user):
    _, user, outbox = registered_user
    response = client.post(
        f"{settings.API_PREFIX}/auth/verify-email",
        json={"email": user.email, "otp": outbox[0]["otp"]},
    )
    db_session.refresh(user)
    assert response.status_code == 200
    assert response.json()["message"] == "Your email has been verified successfully. You can now log in."
    assert user.email_verified is True
    assert user.email_verification_token_hash is None


def test_invalid_verification_code_is_rejected(client, registered_user):
    payload, _, outbox = registered_user
    wrong_otp = "000000" if outbox[0]["otp"] != "000000" else "000001"
    response = client.post(
        f"{settings.API_PREFIX}/auth/verify-email",
        json={"email": payload["email"], "otp": wrong_otp},
    )
    assert response.status_code == 400


def test_expired_verification_token_is_rejected(client, db_session, registered_user):
    payload, user, outbox = registered_user
    user.email_verification_expires_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).replace(tzinfo=None)
    db_session.commit()
    response = client.post(
        f"{settings.API_PREFIX}/auth/verify-email",
        json={"email": payload["email"], "otp": outbox[0]["otp"]},
    )
    assert response.status_code == 400
    db_session.refresh(user)
    assert user.email_verified is False


def test_verification_code_cannot_be_reused(client, registered_user):
    registration, _, outbox = registered_user
    payload = {"email": registration["email"], "otp": outbox[0]["otp"]}
    assert client.post(f"{settings.API_PREFIX}/auth/verify-email", json=payload).status_code == 200
    assert client.post(f"{settings.API_PREFIX}/auth/verify-email", json=payload).status_code == 400


def test_unverified_account_cannot_log_in(client, registered_user):
    payload, _, _ = registered_user
    response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": payload["password"],
    })
    assert response.status_code == 403
    assert "Email verification is required" in response.json()["detail"]


def test_verified_account_can_log_in(client, registered_user):
    payload, _, outbox = registered_user
    client.post(f"{settings.API_PREFIX}/auth/verify-email", json={
        "email": payload["email"],
        "otp": outbox[0]["otp"],
    })
    response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": payload["password"],
    })
    assert response.status_code == 200
    assert response.json()["user"]["email_verified"] is True
    assert response.json()["user"]["role"] == "VIEWER"


def test_invalid_login_credentials_are_rejected(client, registered_user):
    payload, _, _ = registered_user
    response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": "WrongPassword123!",
    })
    assert response.status_code == 401


def test_resending_verification_rotates_the_otp(client, db_session, registered_user, monkeypatch):
    _, user, outbox = registered_user
    user.verification_last_sent_at = (
        datetime.now(timezone.utc) - timedelta(minutes=2)
    ).replace(tzinfo=None)
    db_session.commit()
    replacement_otp = "000000" if outbox[0]["otp"] != "000000" else "000001"
    monkeypatch.setattr(
        "app.api.routes.auth.secrets.randbelow",
        lambda _: int(replacement_otp),
    )

    response = client.post(
        f"{settings.API_PREFIX}/auth/resend-verification",
        json={"email": user.email},
    )

    assert response.status_code == 200
    assert len(outbox) == 2
    assert outbox[1]["otp"] != outbox[0]["otp"]
    db_session.refresh(user)
    assert user.email_verification_token_hash == hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        outbox[1]["otp"].encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def test_wrong_otp_attempts_invalidate_code(client, db_session, registered_user):
    registration, user, outbox = registered_user
    wrong_otp = "000000" if outbox[0]["otp"] != "000000" else "000001"
    for _ in range(5):
        response = client.post(f"{settings.API_PREFIX}/auth/verify-email", json={
            "email": registration["email"],
            "otp": wrong_otp,
        })
        assert response.status_code == 400
    db_session.refresh(user)
    assert user.email_verification_attempts == 5
    assert user.email_verification_token_hash is None
    assert user.email_verified is False


def test_seeded_admin_remains_verified_and_can_log_in(client):
    response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD,
    })
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "ADMIN"
    assert response.json()["user"]["email_verified"] is True


def test_public_registration_cannot_assign_admin_role(client, db_session, email_outbox):
    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "Public Admin",
        "email": "public-admin@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
        "role": "ADMIN",
    })
    user = db_session.query(User).filter_by(email="public-admin@example.com").one()
    assert response.status_code == 201
    assert user.role == UserRole.VIEWER


def test_schema_upgrade_preserves_existing_users_as_verified(monkeypatch):
    legacy_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with legacy_engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY, username VARCHAR(100) NOT NULL, "
            "email VARCHAR(255) NOT NULL, hashed_password VARCHAR(255) NOT NULL, "
            "role VARCHAR(7) NOT NULL, is_active BOOLEAN NOT NULL, "
            "created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, "
            "last_login_at DATETIME)"
        ))
        connection.execute(text(
            "INSERT INTO users (id, username, email, hashed_password, role, is_active, "
            "created_at, updated_at) VALUES "
            "(1, 'legacy', 'legacy@example.com', 'existing-hash', 'VIEWER', 1, "
            "'2025-01-01', '2025-01-01')"
        ))
        for table in ("security_events", "alerts", "incidents"):
            connection.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))

    init_db_module = import_module("app.database.init_db")
    monkeypatch.setattr(init_db_module, "engine", legacy_engine)
    init_db_module._upgrade_user_schema()

    with legacy_engine.connect() as connection:
        migrated_user = connection.execute(text(
            "SELECT email_verified, email_verification_token_hash, email_verification_attempts, full_name "
            "FROM users WHERE id = 1"
        )).one()
    assert bool(migrated_user.email_verified) is True
    assert migrated_user.email_verification_token_hash is None
    assert migrated_user.email_verification_attempts == 0
    assert migrated_user.full_name is None
    for table in ("security_events", "alerts", "incidents"):
        assert "owner_user_id" in {
            column["name"] for column in inspect(legacy_engine).get_columns(table)
        }
    legacy_engine.dispose()
