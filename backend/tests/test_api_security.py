import json
import logging

import pytest
from sqlalchemy import text

from app.core.config import settings
from app.database.connection import engine
from app.core.rate_limit import (
    DatabaseRateLimiter,
    RateLimitStorageUnavailable,
    rate_limiter,
)
from app.core.security import create_access_token
from app.models.user import User, UserRole
from app.schemas.user import UserCreate
from app.services.user_service import UserService


@pytest.mark.parametrize(
    "endpoint",
    ["/api/v1/events", "/api/v1/detection/analyze"],
)
def test_ingestion_requires_authentication(client, endpoint, caplog):
    response = client.post(endpoint, json={})
    assert response.status_code == 401
    assert "Rejected unauthorized ingestion request" in caplog.text


def test_viewer_cannot_ingest_network_events_or_access_admin_operations(
    client, db_session
):
    viewer = UserService.create_user(
        db_session,
        UserCreate(
            username="viewer_security",
            email="viewer.security@example.com",
            password="ViewerPassword123!",
            role=UserRole.VIEWER,
        ),
    )
    headers = {
        "Authorization": (
            "Bearer "
            + create_access_token(subject=viewer.id, role=viewer.role.value)
        )
    }
    ingest_response = client.post(
        "/api/v1/events",
        json={"source_ip": "192.0.2.10", "destination_port": 443},
        headers=headers,
    )
    list_response = client.get("/api/v1/events", headers=headers)
    admin_response = client.get("/api/v1/auth/users", headers=headers)

    assert ingest_response.status_code == 403
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 0
    assert admin_response.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {"source_ip": "999.999.999.999"},
        {"destination_port": 65536},
        {"protocol": "NOT-A-PROTOCOL"},
        {"duration": 86_400_001},
        {"packet_count": 10_000_001},
        {"raw_data": "x" * 4097},
    ],
)
@pytest.mark.parametrize(
    "endpoint",
    ["/api/v1/events", "/api/v1/detection/analyze"],
)
def test_ingestion_rejects_invalid_fields(client, admin_headers, endpoint, payload):
    response = client.post(endpoint, json=payload, headers=admin_headers)
    assert response.status_code == 422
    assert "999.999.999.999" not in response.text


def test_request_body_size_limit_rejects_large_payload(client):
    response = client.post(
        "/api/v1/events",
        content=json.dumps({"raw_data": "x" * 70_000}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "PAYLOAD_TOO_LARGE"


def test_ingestion_rate_limit_is_enforced(client, db_session, admin_headers):
    admin = db_session.query(User).filter_by(username=settings.ADMIN_USERNAME).one()
    key = f"ingestion:user:{admin.id}"
    for _ in range(30):
        assert rate_limiter.check(db_session, key, limit=30, window_seconds=60) == 0

    response = client.post(
        "/api/v1/events",
        json={"source_ip": "192.0.2.20"},
        headers=admin_headers,
    )
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_anonymous_ingestion_is_rate_limited_before_authentication(
    client, db_session
):
    key = "ingestion:ip:testclient"
    for _ in range(120):
        assert rate_limiter.check(db_session, key, limit=120, window_seconds=60) == 0

    response = client.post("/api/v1/events", json={})
    assert response.status_code == 429


def test_rate_limit_counters_are_shared_by_limiter_instances(db_session):
    first_instance = DatabaseRateLimiter()
    second_instance = DatabaseRateLimiter()
    key = "shared-instance-regression"

    assert first_instance.check(db_session, key, limit=2, window_seconds=60) == 0
    assert second_instance.check(db_session, key, limit=2, window_seconds=60) == 0
    assert first_instance.check(db_session, key, limit=2, window_seconds=60) > 0


def test_rate_limit_storage_failure_fails_closed(client, admin_headers, monkeypatch):
    def fail_storage(*_args, **_kwargs):
        raise RateLimitStorageUnavailable("internal database detail")

    monkeypatch.setattr(rate_limiter, "check", fail_storage)
    response = client.post(
        "/api/v1/events",
        json={"source_ip": "192.0.2.20"},
        headers=admin_headers,
    )
    assert response.status_code == 503
    assert "internal database detail" not in response.text


def test_login_rate_limit_is_enforced(client):
    for _ in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "missing-user", "password": "not-a-password"},
        )
        assert response.status_code == 401

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "missing-user", "password": "not-a-password"},
    )
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_detection_failure_does_not_expose_exception_details(
    client, admin_headers, monkeypatch
):
    secret_detail = "internal-database-password"

    def fail_detection(*_args, **_kwargs):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(
        "app.api.routes.detection.DetectionService.analyze_event",
        fail_detection,
    )

    response = client.post(
        "/api/v1/detection/analyze",
        json={},
        headers=admin_headers,
    )
    assert response.status_code == 503
    assert secret_detail not in response.text


def test_database_debug_logs_hide_bound_parameter_values(caplog):
    sensitive_marker = "sensitive-bound-value-regression"
    with caplog.at_level(logging.INFO, logger="sqlalchemy.engine.Engine"):
        with engine.connect() as connection:
            connection.execute(
                text("SELECT :sensitive_value"),
                {"sensitive_value": sensitive_marker},
            ).scalar_one()

    assert sensitive_marker not in caplog.text
