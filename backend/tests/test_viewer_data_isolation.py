from app.core.config import settings
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import UserRole
from app.schemas.alert import AlertCreate
from app.schemas.enums import AlertStatus, IncidentStatus, RiskLevel, ThreatType
from app.schemas.incident import IncidentCreate
from app.schemas.security_event import SecurityEventCreate
from app.schemas.user import UserCreate
from app.services.alert_service import AlertService
from app.services.event_service import EventService
from app.services.incident_service import IncidentService
from app.services.user_service import UserService


def _create_viewer_headers(client, db_session, username, email):
    UserService.create_user(
        db_session,
        UserCreate(
            username=username,
            email=email,
            password="ViewerPassword123!",
            role=UserRole.VIEWER,
        ),
    )
    response = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": email, "password": "ViewerPassword123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _create_analyst_headers(client, db_session):
    UserService.create_user(
        db_session,
        UserCreate(
            username="soc_analyst",
            email="soc.analyst@example.com",
            password="AnalystPassword123!",
            role=UserRole.ANALYST,
        ),
    )
    response = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": "soc_analyst", "password": "AnalystPassword123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _create_owned_event(db_session, owner_user_id, source_ip):
    event = EventService.create_event(
        db_session,
        SecurityEventCreate(
            source_ip=source_ip,
            destination_port=443,
            event_type="NETWORK",
        ),
        owner_user_id=owner_user_id,
    )
    return event.id


def _create_alert_and_incident(db_session, event_id):
    alert, _ = AlertService.create_alert(
        db_session,
        AlertCreate(
            event_id=event_id,
            threat_type=ThreatType.BOTNET,
            confidence=0.99,
            risk_level=RiskLevel.HIGH,
            message="Test alert",
            status=AlertStatus.NEW,
        ),
    )
    incident = IncidentService.create_incident(
        db_session,
        IncidentCreate(
            alert_id=alert.id,
            threat_type=ThreatType.BOTNET,
            severity=RiskLevel.HIGH,
            description="Test incident",
            status=IncidentStatus.OPEN,
        ),
    )
    return alert.id, incident.id


def test_viewers_can_read_own_assessments_but_not_soc_records(
    client,
    db_session,
    admin_headers,
):
    viewer_one_headers = _create_viewer_headers(
        client, db_session, "viewer_one", "viewer.one@example.com"
    )
    viewer_two_headers = _create_viewer_headers(
        client, db_session, "viewer_two", "viewer.two@example.com"
    )

    event_one_id = _create_owned_event(
        db_session,
        UserService.get_by_username(db_session, "viewer_one").id,
        "10.1.0.1",
    )
    event_two_id = _create_owned_event(
        db_session,
        UserService.get_by_username(db_session, "viewer_two").id,
        "10.1.0.2",
    )
    alert_one_id, incident_one_id = _create_alert_and_incident(db_session, event_one_id)
    alert_two_id, incident_two_id = _create_alert_and_incident(db_session, event_two_id)
    analyst_headers = _create_analyst_headers(client, db_session)

    events = client.get(f"{settings.API_PREFIX}/events", headers=viewer_one_headers).json()
    history = client.get(
        f"{settings.API_PREFIX}/detection/history",
        headers=viewer_one_headers,
    ).json()
    trend = client.get(
        f"{settings.API_PREFIX}/detection/trend?hours=24",
        headers=viewer_one_headers,
    ).json()
    alerts_response = client.get(f"{settings.API_PREFIX}/alerts", headers=viewer_one_headers)
    incidents_response = client.get(f"{settings.API_PREFIX}/incidents", headers=viewer_one_headers)
    responses_response = client.get(
        f"{settings.API_PREFIX}/response-actions",
        headers=viewer_one_headers,
    )
    stats = client.get(
        f"{settings.API_PREFIX}/statistics",
        headers=viewer_one_headers,
    ).json()["data"]
    viewer_one_id = UserService.get_by_username(db_session, "viewer_one").id
    expected_alert_count = db_session.query(Alert).filter(
        Alert.owner_user_id == viewer_one_id
    ).count()
    expected_incident_count = db_session.query(Incident).filter(
        Incident.owner_user_id == viewer_one_id
    ).count()

    assert [item["id"] for item in events["items"]] == [event_one_id]
    assert [item["event_id"] for item in history["items"]] == [event_one_id]
    assert sum(bucket["total"] for bucket in trend["trend"]) == 1
    assert alerts_response.status_code == 403
    assert incidents_response.status_code == 403
    assert responses_response.status_code == 403
    assert stats["total_events"] == 1
    assert stats["total_alerts"] == expected_alert_count
    assert stats["total_incidents"] == expected_incident_count
    assert stats["suspicious_events"] == 1
    assert stats["normal_events"] == 0

    assert client.get(
        f"{settings.API_PREFIX}/events/{event_two_id}",
        headers=viewer_one_headers,
    ).status_code == 404
    assert client.get(
        f"{settings.API_PREFIX}/alerts/{alert_two_id}",
        headers=viewer_one_headers,
    ).status_code == 403
    assert client.get(
        f"{settings.API_PREFIX}/incidents/{incident_two_id}",
        headers=viewer_one_headers,
    ).status_code == 403
    assert client.get(
        f"{settings.API_PREFIX}/alerts/{alert_one_id}",
        headers=viewer_one_headers,
    ).status_code == 403
    assert client.get(
        f"{settings.API_PREFIX}/incidents/{incident_one_id}",
        headers=viewer_one_headers,
    ).status_code == 403

    analyst_alerts = client.get(
        f"{settings.API_PREFIX}/alerts",
        headers=analyst_headers,
    )
    analyst_events = client.get(
        f"{settings.API_PREFIX}/events",
        headers=analyst_headers,
    )
    analyst_incidents = client.get(
        f"{settings.API_PREFIX}/incidents",
        headers=analyst_headers,
    )
    analyst_responses = client.get(
        f"{settings.API_PREFIX}/response-actions",
        headers=analyst_headers,
    )
    expected_platform_alerts = db_session.query(Alert).count()
    expected_platform_incidents = db_session.query(Incident).count()
    assert analyst_alerts.status_code == 200
    assert analyst_alerts.json()["total"] == expected_platform_alerts
    assert analyst_events.status_code == 200
    assert analyst_events.json()["total"] == 2
    assert analyst_incidents.status_code == 200
    assert analyst_incidents.json()["total"] == expected_platform_incidents
    assert analyst_responses.status_code == 200

    admin_events = client.get(f"{settings.API_PREFIX}/events", headers=admin_headers).json()
    admin_stats = client.get(
        f"{settings.API_PREFIX}/statistics",
        headers=admin_headers,
    ).json()["data"]
    assert admin_events["total"] == 2
    assert admin_stats["total_events"] == 2
    assert admin_stats["total_alerts"] >= 2
    assert admin_stats["total_incidents"] == 2
    assert admin_stats["suspicious_events"] == 2
    assert admin_stats["normal_events"] == 0


def test_soc_data_reads_require_authentication(client):
    protected_paths = [
        "/events",
        "/alerts",
        "/incidents",
        "/response-actions",
        "/statistics",
        "/detection/history",
        "/detection/trend",
    ]
    for path in protected_paths:
        response = client.get(f"{settings.API_PREFIX}{path}")
        assert response.status_code == 401, path


def test_own_scope_keeps_staff_user_portal_records_self_scoped(
    client,
    db_session,
    admin_headers,
):
    viewer_headers = _create_viewer_headers(
        client, db_session, "portal_viewer", "portal.viewer@example.com"
    )
    analyst_headers = _create_analyst_headers(client, db_session)
    viewer_event_id = _create_owned_event(
        db_session,
        UserService.get_by_username(db_session, "portal_viewer").id,
        "10.2.0.1",
    )
    analyst_event_id = _create_owned_event(
        db_session,
        UserService.get_by_username(db_session, "soc_analyst").id,
        "10.2.0.2",
    )
    admin_event_id = _create_owned_event(
        db_session,
        UserService.get_by_username(db_session, settings.ADMIN_USERNAME).id,
        "10.2.0.3",
    )

    for headers, expected_event_id in (
        (viewer_headers, viewer_event_id),
        (analyst_headers, analyst_event_id),
        (admin_headers, admin_event_id),
    ):
        events = client.get(
            f"{settings.API_PREFIX}/events?scope=own",
            headers=headers,
        )
        history = client.get(
            f"{settings.API_PREFIX}/detection/history?scope=own",
            headers=headers,
        )

        assert events.status_code == 200
        assert [event["id"] for event in events.json()["items"]] == [expected_event_id]
        assert history.status_code == 200
        assert [item["event_id"] for item in history.json()["items"]] == [expected_event_id]

    analyst_platform_events = client.get(
        f"{settings.API_PREFIX}/events?scope=role",
        headers=analyst_headers,
    )
    assert analyst_platform_events.status_code == 200
    assert analyst_platform_events.json()["total"] == 3

    invalid_scope = client.get(
        f"{settings.API_PREFIX}/events?scope=all",
        headers=analyst_headers,
    )
    assert invalid_scope.status_code == 422
