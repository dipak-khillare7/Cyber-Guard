import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from importlib import import_module

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.models.user import AnalystRequestStatus, User, UserRole
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


def test_registration_creates_unverified_pending_user_and_sends_otp(client, db_session, email_outbox):
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
    assert user.is_active is False
    assert user.analyst_request_status == AnalystRequestStatus.PENDING.value
    assert user.hashed_password != "SecurePassword123!"
    assert len(email_outbox[0]["otp"]) == 6
    assert email_outbox[0]["otp"].isdigit()
    assert user.email_verification_token_hash == hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        email_outbox[0]["otp"].encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert user.email_verification_token_hash != email_outbox[0]["otp"]
    assert email_outbox[0]["email"] == "viewer@example.com"


def test_registration_is_rate_limited(client, email_outbox):
    for index in range(5):
        response = client.post(f"{settings.API_PREFIX}/auth/register", json={
            "full_name": "Rate Limited User",
            "email": f"rate-limited-{index}@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        })
        assert response.status_code == 201

    response = client.post(f"{settings.API_PREFIX}/auth/register", json={
        "full_name": "Rate Limited User",
        "email": "rate-limited-final@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    })
    assert response.status_code == 429


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
    assert "awaiting Admin review" in response.json()["message"]
    assert user.email_verified is True
    assert user.role == UserRole.VIEWER
    assert user.is_active is False
    assert user.analyst_request_status == AnalystRequestStatus.PENDING.value
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
    assert response.status_code == 401


def test_verified_pending_request_cannot_log_in(client, registered_user):
    payload, user, outbox = registered_user
    client.post(f"{settings.API_PREFIX}/auth/verify-email", json={
        "email": payload["email"],
        "otp": outbox[0]["otp"],
    })
    response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": payload["password"],
    })
    assert response.status_code == 401
    assert user.analyst_request_status == AnalystRequestStatus.PENDING.value


def test_admin_approval_assigns_analyst_and_enables_login(
    client, db_session, registered_user, admin_headers
):
    payload, user, outbox = registered_user
    verification_response = client.post(f"{settings.API_PREFIX}/auth/verify-email", json={
        "email": payload["email"],
        "otp": outbox[0]["otp"],
    })
    assert verification_response.status_code == 200

    approval_response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/approve",
        headers=admin_headers,
    )
    db_session.refresh(user)
    admin = db_session.query(User).filter_by(username=settings.ADMIN_USERNAME).one()

    assert approval_response.status_code == 200
    assert approval_response.json()["status"] == "APPROVED"
    assert user.analyst_request_status == AnalystRequestStatus.APPROVED.value
    assert user.role == UserRole.ANALYST
    assert user.is_active is True
    assert user.reviewed_by_user_id == admin.id
    assert user.reviewed_at is not None
    approved_requests = client.get(
        f"{settings.API_PREFIX}/auth/analyst-requests",
        params={"status": "APPROVED"},
        headers=admin_headers,
    )
    pending_requests = client.get(
        f"{settings.API_PREFIX}/auth/analyst-requests",
        params={"status": "PENDING"},
        headers=admin_headers,
    )
    assert approved_requests.status_code == 200
    assert approved_requests.json()["items"][0]["id"] == user.id
    assert pending_requests.json()["total"] == 0

    login_response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": payload["password"],
    })
    assert login_response.status_code == 200
    assert login_response.json()["user"]["role"] == "ANALYST"
    stats_response = client.get(
        f"{settings.API_PREFIX}/statistics",
        headers={"Authorization": f"Bearer {login_response.json()['access_token']}"},
    )
    assert stats_response.status_code == 200

    repeated_approval = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/approve",
        headers=admin_headers,
    )
    assert repeated_approval.status_code == 409


def test_admin_cannot_approve_before_email_verification(client, registered_user, admin_headers):
    _, user, _ = registered_user
    response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/approve",
        headers=admin_headers,
    )
    assert response.status_code == 409
    assert user.analyst_request_status == AnalystRequestStatus.PENDING.value
    assert user.role == UserRole.VIEWER
    assert user.is_active is False


def test_admin_rejection_prevents_login_and_cannot_be_reversed(
    client, db_session, registered_user, admin_headers
):
    payload, user, _ = registered_user
    response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/reject",
        headers=admin_headers,
    )
    db_session.refresh(user)
    admin = db_session.query(User).filter_by(username=settings.ADMIN_USERNAME).one()
    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert user.analyst_request_status == AnalystRequestStatus.REJECTED.value
    assert user.role == UserRole.VIEWER
    assert user.is_active is False
    assert user.reviewed_by_user_id == admin.id
    assert user.reviewed_at is not None
    rejected_requests = client.get(
        f"{settings.API_PREFIX}/auth/analyst-requests",
        params={"status": "REJECTED"},
        headers=admin_headers,
    )
    assert rejected_requests.status_code == 200
    assert rejected_requests.json()["items"][0]["id"] == user.id

    login_response = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": payload["email"],
        "password": payload["password"],
    })
    assert login_response.status_code == 401
    repeated_rejection = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/reject",
        headers=admin_headers,
    )
    assert repeated_rejection.status_code == 409


def test_analyst_cannot_list_or_review_account_requests(client, db_session, registered_user):
    from app.core.security import create_access_token
    from app.schemas.user import UserCreate
    from app.services.user_service import UserService

    analyst = UserService.create_user(
        db_session,
        UserCreate(
            username="existing_analyst",
            email="existing.analyst@example.com",
            password="AnalystPassword123!",
            role=UserRole.ANALYST,
        ),
    )
    headers = {
        "Authorization": f"Bearer {create_access_token(subject=analyst.id, role=analyst.role.value)}"
    }
    request_id = registered_user[1].id
    list_response = client.get(
        f"{settings.API_PREFIX}/auth/analyst-requests",
        headers=headers,
    )
    review_response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{request_id}/reject",
        headers=headers,
    )
    assert list_response.status_code == 403
    assert review_response.status_code == 403


def test_unauthenticated_users_cannot_list_or_review_account_requests(client, registered_user):
    request_id = registered_user[1].id
    list_response = client.get(f"{settings.API_PREFIX}/auth/analyst-requests")
    review_response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{request_id}/approve",
    )
    assert list_response.status_code == 401
    assert review_response.status_code == 401


def test_admin_cannot_review_own_request(client, db_session, admin_headers):
    admin = db_session.query(User).filter_by(username=settings.ADMIN_USERNAME).one()
    admin.analyst_request_status = AnalystRequestStatus.PENDING.value
    db_session.commit()
    response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{admin.id}/reject",
        headers=admin_headers,
    )
    assert response.status_code == 403


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


def test_public_registration_cannot_assign_admin_role(client, db_session, email_outbox, admin_headers):
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

    verification_response = client.post(f"{settings.API_PREFIX}/auth/verify-email", json={
        "email": user.email,
        "otp": email_outbox[0]["otp"],
    })
    db_session.refresh(user)
    assert verification_response.status_code == 200
    assert user.role == UserRole.VIEWER
    assert user.is_active is False

    approval_response = client.post(
        f"{settings.API_PREFIX}/auth/analyst-requests/{user.id}/approve",
        headers=admin_headers,
    )
    db_session.refresh(user)
    assert approval_response.status_code == 200
    assert user.role == UserRole.ANALYST
    assert user.role != UserRole.ADMIN


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
        connection.execute(text("CREATE TABLE security_events (id INTEGER PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE alerts (id INTEGER PRIMARY KEY, event_id INTEGER)"))
        connection.execute(text("CREATE TABLE incidents (id INTEGER PRIMARY KEY, alert_id INTEGER)"))
        connection.execute(text(
            "CREATE TABLE response_actions (id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL)"
        ))
        connection.execute(text("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY)"))

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
    assert {"analyst_request_status", "reviewed_by_user_id", "reviewed_at"} <= {
        column["name"] for column in inspect(legacy_engine).get_columns("users")
    }
    for table in ("security_events", "alerts", "incidents"):
        assert "owner_user_id" in {
            column["name"] for column in inspect(legacy_engine).get_columns(table)
        }
    for table in ("response_actions", "audit_logs"):
        assert "owner_user_id" in {
            column["name"] for column in inspect(legacy_engine).get_columns(table)
        }
    with legacy_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO security_events (id, owner_user_id) VALUES (10, 1), (11, NULL)"
        ))
        connection.execute(text(
            "INSERT INTO alerts (id, event_id, owner_user_id) VALUES "
            "(20, 10, NULL), (21, 11, NULL)"
        ))
        connection.execute(text(
            "INSERT INTO incidents (id, alert_id, owner_user_id) VALUES "
            "(30, 20, NULL), (31, 21, NULL)"
        ))
        connection.execute(text(
            "INSERT INTO response_actions (id, incident_id, owner_user_id) VALUES "
            "(40, 30, NULL), (41, 31, NULL)"
        ))
        connection.execute(text("INSERT INTO audit_logs (id, owner_user_id) VALUES (50, NULL)"))
    init_db_module._upgrade_user_schema()
    with legacy_engine.connect() as connection:
        assert connection.execute(text(
            "SELECT owner_user_id FROM alerts WHERE id = 20"
        )).scalar_one() == 1
        assert connection.execute(text(
            "SELECT owner_user_id FROM alerts WHERE id = 21"
        )).scalar_one() is None
        assert connection.execute(text(
            "SELECT owner_user_id FROM incidents WHERE id = 30"
        )).scalar_one() == 1
        assert connection.execute(text(
            "SELECT owner_user_id FROM response_actions WHERE id = 40"
        )).scalar_one() == 1
        assert connection.execute(text(
            "SELECT owner_user_id FROM response_actions WHERE id = 41"
        )).scalar_one() is None
        assert connection.execute(text(
            "SELECT owner_user_id FROM audit_logs"
        )).scalar_one() is None
    legacy_engine.dispose()
