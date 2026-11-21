from app.models.alert import Alert
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole


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
