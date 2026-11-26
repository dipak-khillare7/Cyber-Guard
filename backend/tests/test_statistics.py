from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole
from app.core.security import create_access_token
from app.schemas.user import UserCreate
from app.services.user_service import UserService


def _create_analyst_headers(db_session, username):
    user = UserService.create_user(
        db_session,
        UserCreate(
            username=username,
            email=f"{username}@example.com",
            password="AnalystPassword123!",
            role=UserRole.ANALYST,
        ),
    )
    return user, {
        "Authorization": (
            "Bearer " + create_access_token(subject=user.id, role=user.role.value)
        )
    }


def test_statistics_empty_database(client, admin_headers):
    response = client.get("/api/v1/statistics", headers=admin_headers)
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["total_events"] == 0
    assert data["normal_events"] == 0
    assert data["suspicious_events"] == 0
    assert data["total_alerts"] == 0
    assert data["total_incidents"] == 0
    assert data["resolved_incidents"] == 0
    assert data["critical_threats"] == 0
    assert data["threats_by_type"] == {}
    assert data["threats_by_severity"] == {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    trend = client.get("/api/v1/detection/trend", headers=admin_headers).json()
    assert len(trend["trend"]) == 24
    assert len({bucket["time"] for bucket in trend["trend"]}) == 24
    assert all(bucket["total"] == 0 for bucket in trend["trend"])


def test_statistics_populated_database(client, admin_headers):
    # Post events that trigger suspicious activity
    client.post("/api/v1/events", json={"source_ip": "10.0.0.1", "destination_port": 22, "packet_count": 100, "event_type": "NETWORK"}, headers=admin_headers)
    client.post("/api/v1/events", json={"source_ip": "10.0.0.2", "destination_port": 80, "packet_count": 2000, "event_type": "NETWORK"}, headers=admin_headers)

    response = client.get("/api/v1/statistics", headers=admin_headers)
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["total_events"] == 2
    assert data["total_alerts"] >= 1
    assert data["normal_events"] + data["suspicious_events"] == data["total_events"]


def test_statistics_count_unique_suspicious_events_and_resolved_incidents(
    client,
    db_session,
    admin_headers,
):
    admin = db_session.query(User).filter(User.role == UserRole.ADMIN).first()
    normal_event = SecurityEvent(owner_user_id=admin.id, event_type="NETWORK")
    suspicious_event = SecurityEvent(owner_user_id=admin.id, event_type="NETWORK")
    db_session.add_all([normal_event, suspicious_event])
    db_session.flush()

    db_session.add_all([
        Alert(
            owner_user_id=admin.id,
            event_id=suspicious_event.id,
            threat_type="PORT_SCAN",
            confidence=0.9,
            risk_level="HIGH",
            message="Suspicious port scan",
            status="NEW",
        ),
        Alert(
            owner_user_id=admin.id,
            event_id=suspicious_event.id,
            threat_type="PORT_SCAN",
            confidence=0.9,
            risk_level="HIGH",
            message="Repeated suspicious port scan",
            status="NEW",
        ),
        Incident(
            owner_user_id=admin.id,
            threat_type="PORT_SCAN",
            severity="HIGH",
            description="Resolved incident",
            status="RESOLVED",
        ),
        Incident(
            owner_user_id=admin.id,
            threat_type="PORT_SCAN",
            severity="HIGH",
            description="Closed incident",
            status="CLOSED",
        ),
    ])
    db_session.commit()

    response = client.get("/api/v1/statistics", headers=admin_headers)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total_events"] == 2
    assert data["suspicious_events"] == 1
    assert data["normal_events"] == 1
    assert data["resolved_incidents"] == 2


def test_statistics_and_hourly_trends_match_owned_database_records(
    client, db_session, admin_headers
):
    analyst_a, headers_a = _create_analyst_headers(db_session, "chart_analyst_a")
    analyst_b, headers_b = _create_analyst_headers(db_session, "chart_analyst_b")
    now = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)

    events_a = [
        SecurityEvent(owner_user_id=analyst_a.id, timestamp=now - timedelta(minutes=5)),
        SecurityEvent(owner_user_id=analyst_a.id, timestamp=now - timedelta(hours=23)),
        SecurityEvent(owner_user_id=analyst_a.id, timestamp=now - timedelta(hours=47)),
        SecurityEvent(owner_user_id=analyst_a.id, timestamp=now - timedelta(hours=49)),
    ]
    event_b = SecurityEvent(
        owner_user_id=analyst_b.id,
        timestamp=now - timedelta(hours=23),
    )
    db_session.add_all([*events_a, event_b])
    db_session.flush()

    alerts = [
        Alert(
            owner_user_id=analyst_a.id,
            event_id=events_a[0].id,
            threat_type="DOS_DDOS",
            confidence=0.9,
            risk_level="HIGH",
            status="NEW",
            message="High DOS alert",
        ),
        Alert(
            owner_user_id=analyst_a.id,
            event_id=events_a[0].id,
            threat_type="PORT_SCAN",
            confidence=0.8,
            risk_level="CRITICAL",
            status="ACKNOWLEDGED",
            message="Acknowledged port scan",
        ),
        Alert(
            owner_user_id=analyst_a.id,
            event_id=events_a[1].id,
            threat_type="NORMAL",
            confidence=0.0,
            risk_level="LOW",
            status="RESOLVED",
            message="Normal event",
        ),
        Alert(
            owner_user_id=analyst_a.id,
            event_id=events_a[2].id,
            threat_type="MALWARE",
            confidence=0.7,
            risk_level="UNRECOGNIZED",
            status="FALSE_POSITIVE",
            message="Unrecognized risk value",
        ),
        Alert(
            owner_user_id=analyst_b.id,
            event_id=event_b.id,
            threat_type="PORT_SCAN",
            confidence=0.9,
            risk_level="CRITICAL",
            status="INVESTIGATING",
            message="Analyst B alert",
        ),
    ]
    db_session.add_all(alerts)
    db_session.add_all([
        Incident(
            owner_user_id=analyst_a.id,
            threat_type="DOS_DDOS",
            severity="HIGH",
            description="In-progress incident",
            status="IN_PROGRESS",
        ),
        Incident(
            owner_user_id=analyst_a.id,
            threat_type="DOS_DDOS",
            severity="HIGH",
            description="Open incident",
            status="OPEN",
        ),
        Incident(
            owner_user_id=analyst_a.id,
            threat_type="PORT_SCAN",
            severity="CRITICAL",
            description="Resolved incident",
            status="RESOLVED",
        ),
        Incident(
            owner_user_id=analyst_b.id,
            threat_type="PORT_SCAN",
            severity="CRITICAL",
            description="Closed analyst B incident",
            status="CLOSED",
        ),
        Incident(
            owner_user_id=analyst_b.id,
            threat_type="PORT_SCAN",
            severity="CRITICAL",
            description="Other analyst incident",
            status="OPEN",
        ),
    ])
    db_session.commit()

    stats_a = client.get("/api/v1/statistics", headers=headers_a).json()["data"]
    stats_b = client.get("/api/v1/statistics", headers=headers_b).json()["data"]
    admin_stats = client.get(
        "/api/v1/statistics", headers=admin_headers
    ).json()["data"]

    expected_type_counts = {
        "DOS_DDOS": 1,
        "PORT_SCAN": 1,
        "NORMAL": 1,
        "MALWARE": 1,
    }
    assert stats_a["total_events"] == 4
    assert stats_a["total_alerts"] == 4
    assert stats_a["suspicious_events"] == 2
    assert stats_a["normal_events"] == 2
    assert stats_a["threats_by_type"] == expected_type_counts
    assert stats_a["threats_by_severity"] == {
        "LOW": 1,
        "MEDIUM": 0,
        "HIGH": 1,
        "CRITICAL": 1,
        "UNRECOGNIZED": 1,
    }
    assert stats_a["active_alerts"] == 2
    assert stats_a["open_incidents"] == 2
    assert stats_a["resolved_incidents"] == 1
    assert stats_b["total_events"] == 1
    assert stats_b["threats_by_type"] == {"PORT_SCAN": 1}
    assert admin_stats["total_events"] == 5
    assert admin_stats["total_alerts"] == 5
    assert admin_stats["total_incidents"] == 5
    assert admin_stats["open_incidents"] == 3
    assert admin_stats["resolved_incidents"] == 2
    assert admin_stats["threats_by_type"] == {
        "DOS_DDOS": 1,
        "PORT_SCAN": 2,
        "NORMAL": 1,
        "MALWARE": 1,
    }

    trend_a = client.get(
        "/api/v1/detection/trend?hours=48", headers=headers_a
    ).json()
    trend_b = client.get(
        "/api/v1/detection/trend?hours=48", headers=headers_b
    ).json()
    trend_admin = client.get(
        "/api/v1/detection/trend?hours=48", headers=admin_headers
    ).json()

    assert trend_a["timezone"] == "Asia/Kolkata"
    assert len(trend_a["trend"]) == 48
    assert len({bucket["time"] for bucket in trend_a["trend"]}) == 48
    assert sum(bucket["total"] for bucket in trend_a["trend"]) == 3
    assert sum(bucket["threats"] for bucket in trend_a["trend"]) == 2
    assert sum(bucket["normal"] for bucket in trend_a["trend"]) == 1
    assert sum(bucket["total"] for bucket in trend_b["trend"]) == 1
    assert sum(bucket["total"] for bucket in trend_admin["trend"]) == 4
    assert sum(bucket["threats"] for bucket in trend_admin["trend"]) == 3
    assert sum(bucket["normal"] for bucket in trend_admin["trend"]) == 1
