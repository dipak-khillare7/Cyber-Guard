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
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole
from app.schemas.alert import AlertCreate
from app.schemas.user import UserCreate
from app.services.user_service import UserService
from app.services.alert_service import AlertService


def _create_analyst_headers(db_session, username, email):
    analyst = UserService.create_user(
        db_session,
        UserCreate(
            username=username,
            email=email,
            password="AnalystPassword123!",
            role=UserRole.ANALYST,
        ),
    )
    return analyst, {
        "Authorization": (
            "Bearer "
            + create_access_token(subject=analyst.id, role=analyst.role.value)
        )
    }


def test_analyst_data_is_isolated_across_events_alerts_incidents_responses_and_audit(
    client, db_session, admin_headers, monkeypatch
):
    monkeypatch.setattr(
        "app.api.routes.events.predictor.predict",
        lambda *_args, **_kwargs: {"predicted_threat": "NORMAL", "confidence": 0.0},
    )
    analyst_a, headers_a = _create_analyst_headers(
        db_session, "analyst_isolation_a", "analyst.isolation.a@example.com"
    )
    analyst_b, headers_b = _create_analyst_headers(
        db_session, "analyst_isolation_b", "analyst.isolation.b@example.com"
    )

    event_a_response = client.post(
        "/api/v1/events",
        json={
            "source_ip": "192.0.2.41",
            "destination_ip": "198.51.100.41",
            "destination_port": 8443,
            "owner_user_id": analyst_b.id,
        },
        headers=headers_a,
    )
    event_b_response = client.post(
        "/api/v1/events",
        json={
            "source_ip": "192.0.2.42",
            "destination_ip": "198.51.100.42",
            "destination_port": 9443,
        },
        headers=headers_b,
    )
    assert event_a_response.status_code == 201
    assert event_b_response.status_code == 201
    event_a_id = event_a_response.json()["id"]
    event_b_id = event_b_response.json()["id"]
    assert db_session.get(SecurityEvent, event_a_id).owner_user_id == analyst_a.id
    assert db_session.get(SecurityEvent, event_b_id).owner_user_id == analyst_b.id
    event_a = client.get(f"/api/v1/events/{event_a_id}", headers=headers_a)
    assert event_a.status_code == 200
    assert db_session.get(User, analyst_a.id) is not None
    assert client.get(f"/api/v1/events/{event_b_id}", headers=headers_a).status_code == 404

    alerts = {}
    incidents = {}
    for analyst, headers, event_id, suffix in (
        (analyst_a, headers_a, event_a_id, "a"),
        (analyst_b, headers_b, event_b_id, "b"),
    ):
        alert, _ = AlertService.create_alert(
            db_session,
            AlertCreate(
                event_id=event_id,
                threat_type="DOS_DDOS",
                confidence=0.99,
                risk_level="HIGH",
                message=f"Isolation alert {suffix}",
            ),
        )
        alerts[suffix] = alert
        incident_response = client.post(
            "/api/v1/incidents",
            json={
                "alert_id": alert.id,
                "threat_type": "DOS_DDOS",
                "severity": "HIGH",
                "description": f"Isolation incident {suffix}",
            },
            headers=headers,
        )
        assert incident_response.status_code == 201
        incidents[suffix] = incident_response.json()

    events_a = client.get("/api/v1/events?scope=role", headers=headers_a).json()
    events_b = client.get("/api/v1/events?scope=role", headers=headers_b).json()
    assert {item["id"] for item in events_a["items"]} == {event_a_id}
    assert {item["id"] for item in events_b["items"]} == {event_b_id}
    history_a = client.get("/api/v1/detection/history", headers=headers_a).json()
    history_b = client.get("/api/v1/detection/history", headers=headers_b).json()
    assert {item["event_id"] for item in history_a["items"]} == {event_a_id}
    assert {item["event_id"] for item in history_b["items"]} == {event_b_id}
    trend_a = client.get("/api/v1/detection/trend?hours=1", headers=headers_a).json()
    trend_b = client.get("/api/v1/detection/trend?hours=1", headers=headers_b).json()
    assert sum(item["total"] for item in trend_a["trend"]) == 1
    assert sum(item["total"] for item in trend_b["trend"]) == 1

    alerts_a = client.get("/api/v1/alerts", headers=headers_a).json()
    alerts_b = client.get("/api/v1/alerts", headers=headers_b).json()
    assert {item["id"] for item in alerts_a["items"]} == {alerts["a"].id}
    assert {item["id"] for item in alerts_b["items"]} == {alerts["b"].id}
    assert client.get(
        f"/api/v1/alerts/{alerts['b'].id}", headers=headers_a
    ).status_code == 404
    assert client.patch(
        f"/api/v1/alerts/{alerts['b'].id}",
        json={"status": "RESOLVED"},
        headers=headers_a,
    ).status_code == 404

    assert client.get(
        f"/api/v1/incidents/{incidents['b']['id']}", headers=headers_a
    ).status_code == 404
    assert client.patch(
        f"/api/v1/incidents/{incidents['b']['id']}",
        json={"status": "RESOLVED"},
        headers=headers_a,
    ).status_code == 404
    assert client.post(
        f"/api/v1/incidents/{incidents['b']['id']}/response",
        json={
            "incident_id": incidents["b"]["id"],
            "action_type": "LOG",
            "description": "Cross-owner attempt",
        },
        headers=headers_a,
    ).status_code == 404
    assert client.post(
        "/api/v1/incidents",
        json={
            "alert_id": alerts["b"].id,
            "threat_type": "DOS_DDOS",
            "severity": "HIGH",
            "description": "Cross-owner incident attempt",
        },
        headers=headers_a,
    ).status_code == 404

    actions_a = client.get("/api/v1/response-actions", headers=headers_a).json()
    actions_b = client.get("/api/v1/response-actions", headers=headers_b).json()
    assert actions_a["items"]
    assert actions_b["items"]
    assert all(item["incident_id"] == incidents["a"]["id"] for item in actions_a["items"])
    assert all(item["incident_id"] == incidents["b"]["id"] for item in actions_b["items"])

    stats_a = client.get("/api/v1/statistics", headers=headers_a).json()["data"]
    stats_b = client.get("/api/v1/statistics", headers=headers_b).json()["data"]
    admin_stats = client.get("/api/v1/statistics", headers=admin_headers).json()["data"]
    assert stats_a["total_events"] == 1
    assert stats_b["total_events"] == 1
    assert stats_a["total_alerts"] == len(alerts_a["items"])
    assert stats_b["total_alerts"] == len(alerts_b["items"])
    assert stats_a["total_incidents"] == 1
    assert stats_b["total_incidents"] == 1
    assert admin_stats["total_events"] == 2
    assert admin_stats["total_alerts"] == stats_a["total_alerts"] + stats_b["total_alerts"]
    assert admin_stats["total_incidents"] == 2

    audit_a = client.get("/api/v1/audit-logs", headers=headers_a).json()
    audit_b = client.get("/api/v1/audit-logs", headers=headers_b).json()
    assert audit_a["items"]
    assert audit_b["items"]
    assert all(item["username"] == analyst_a.username for item in audit_a["items"])
    assert all(item["username"] == analyst_b.username for item in audit_b["items"])

    admin_events = client.get("/api/v1/events", headers=admin_headers).json()
    assert {item["id"] for item in admin_events["items"]} == {event_a_id, event_b_id}
    assert client.patch(
        f"/api/v1/alerts/{alerts['b'].id}",
        json={"status": "ACKNOWLEDGED"},
        headers=admin_headers,
    ).status_code == 200

    assert client.patch(
        f"/api/v1/events/{event_b_id}",
        json={"raw_data": "attempt"},
        headers=headers_a,
    ).status_code == 405
    assert client.delete(
        f"/api/v1/events/{event_b_id}",
        headers=headers_a,
    ).status_code == 405
    assert client.delete(
        f"/api/v1/alerts/{alerts['b'].id}",
        headers=headers_a,
    ).status_code == 405
    assert client.delete(
        f"/api/v1/incidents/{incidents['b']['id']}",
        headers=headers_a,
    ).status_code == 405


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
    stats_response = client.get("/api/v1/statistics", headers=headers)
    admin_response = client.get("/api/v1/auth/users", headers=headers)

    assert ingest_response.status_code == 403
    assert list_response.status_code == 403
    assert stats_response.status_code == 403
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
