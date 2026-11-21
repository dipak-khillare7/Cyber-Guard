from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response_action import ResponseAction


def test_database_crud_operations(db_session):
    # 1. Create SecurityEvent
    event = SecurityEvent(source_ip="10.0.0.50", destination_port=80, protocol="TCP", event_type="NETWORK")
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    assert event.id is not None

    # 2. Create Alert linked to event
    alert = Alert(event_id=event.id, threat_type="DOS_DDOS", confidence=0.92, risk_level="HIGH", message="High volume flood detected", status="NEW")
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    assert alert.id is not None
    assert alert.event_id == event.id

    # 3. Create Incident linked to alert
    incident = Incident(alert_id=alert.id, threat_type="DOS_DDOS", severity="HIGH", description="Denial of service attempt against web server", status="OPEN")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    assert incident.id is not None

    # 4. Create ResponseAction linked to incident
    action = ResponseAction(incident_id=incident.id, action_type="SIMULATED_BLOCK", action_status="SIMULATED", description="Simulated firewall rule applied")
    db_session.add(action)
    db_session.commit()
    db_session.refresh(action)
    assert action.id is not None
    assert action.incident_id == incident.id
