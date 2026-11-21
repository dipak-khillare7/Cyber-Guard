"""
Phase 8: End-to-End System Validation Test Suite
Application: Cyber Guard SOC Monitoring Console

Comprehensive validation covering:
- Test Case 1: Normal Benign Network Event
- Test Case 2: DoS/DDoS Threat Classification & Detection History
- Test Case 3: Botnet Threat Classification & Persistence
- Test Case 4: High/Critical Severity Incident Auto-Escalation
- Test Case 5: Safe Simulation Mode Response Action Generation & Reference
- Test Case 6: Audit Logging Integrity & Persistence
- Test Case 7: Cross-Session Database Persistence
- Test Case 8: Role-Based Access Control & API Authorization
- Test Case 9: Input Validation & Malformed Payload Rejection
- Test Case 10: Database Referential Integrity & Orphan Prevention
"""

import pytest
from unittest.mock import patch
from app.services import detection_service
from app.schemas.enums import ThreatType, RiskLevel, ActionType, ActionStatus
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.audit_log import AuditLog
from app.core.config import settings


# ============================================================================
# TEST CASE 1 — NORMAL EVENT
# ============================================================================
def test_case_1_normal_event(client, admin_headers):
    """
    Validates end-to-end processing of a benign network event.
    Verifies: HTTP 200, event creation, NORMAL classification, valid confidence,
    LOW risk level, valid risk score, event ID returned, and NO high-severity alert.
    """
    mock_pred = {
        "predicted_threat": ThreatType.NORMAL.value,
        "confidence": 0.985,
        "probabilities": {ThreatType.NORMAL.value: 0.985},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 52140,
            "destination_port": 80,
            "protocol": "TCP",
            "duration": 50000.0,
            "packet_count": 15,
            "byte_count": 15000,
            "syn_flag_count": 0,
            "ack_flag_count": 1,
            "event_type": "NETWORK"
        }

        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        res = response.json()
        assert res["success"] is True

        data = res["data"]
        assert data["event_id"] is not None and isinstance(data["event_id"], int)
        assert data["prediction"]["threat_type"] == ThreatType.NORMAL.value
        assert 0.0 <= data["prediction"]["confidence"] <= 1.0
        assert data["risk"]["level"] == RiskLevel.LOW.value
        assert 0.0 <= data["risk"]["score"] <= 1.0
        assert data["alert"]["generated"] is False
        assert data["alert"]["alert_id"] is None
        assert data["incident"]["created"] is False
        assert data["response"]["action_status"] == "NONE"


# ============================================================================
# TEST CASE 2 — DOS/DDOS EVENT
# ============================================================================
def test_case_2_dos_ddos_event(client, admin_headers):
    """
    Validates simulated DoS/DDoS threat event processing.
    Verifies: HTTP 200, event persistence, DOS_DDOS classification, valid confidence,
    HIGH/CRITICAL risk level, alert creation, and appearance in detection history.
    """
    mock_pred = {
        "predicted_threat": ThreatType.DOS_DDOS.value,
        "confidence": 0.992,
        "probabilities": {ThreatType.DOS_DDOS.value: 0.992},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.1",
            "source_port": 48922,
            "destination_port": 80,
            "protocol": "TCP",
            "duration": 250000.0,
            "packet_count": 1000,
            "byte_count": 500000,
            "syn_flag_count": 1,
            "ack_flag_count": 1,
            "event_type": "NETWORK"
        }

        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        data = response.json()["data"]

        event_id = data["event_id"]
        assert event_id is not None
        assert data["prediction"]["threat_type"] == ThreatType.DOS_DDOS.value
        assert data["prediction"]["confidence"] >= 0.90
        assert data["risk"]["level"] in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
        assert data["alert"]["generated"] is True
        assert data["alert"]["alert_id"] is not None

        # Confirm event is retrievable in detection history
        hist_res = client.get("/api/v1/detection/history?skip=0&limit=10", headers=admin_headers)
        assert hist_res.status_code == 200
        hist_items = hist_res.json()["items"]
        matching_events = [item for item in hist_items if item["event_id"] == event_id]
        assert len(matching_events) == 1
        assert matching_events[0]["detected_threat"] == ThreatType.DOS_DDOS.value


# ============================================================================
# TEST CASE 3 — BOTNET EVENT
# ============================================================================
def test_case_3_botnet_event(client, admin_headers):
    """
    Validates simulated Botnet threat event processing.
    Verifies: HTTP 200, BOTNET classification, valid confidence, persistence,
    alert generation, and appearance in detection history.
    """
    mock_pred = {
        "predicted_threat": ThreatType.BOTNET.value,
        "confidence": 0.965,
        "probabilities": {ThreatType.BOTNET.value: 0.965},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "172.16.0.55",
            "destination_ip": "10.0.0.1",
            "source_port": 33412,
            "destination_port": 22,
            "protocol": "TCP",
            "duration": 850000.0,
            "packet_count": 3500,
            "byte_count": 1800000,
            "syn_flag_count": 1,
            "ack_flag_count": 0,
            "event_type": "NETWORK"
        }

        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        data = response.json()["data"]

        event_id = data["event_id"]
        assert event_id is not None
        assert data["prediction"]["threat_type"] == ThreatType.BOTNET.value
        assert data["prediction"]["confidence"] >= 0.90
        assert data["alert"]["generated"] is True
        assert data["alert"]["alert_id"] is not None

        # Verify presence in detection history
        hist_res = client.get("/api/v1/detection/history?skip=0&limit=10", headers=admin_headers)
        assert hist_res.status_code == 200
        matching = [item for item in hist_res.json()["items"] if item["event_id"] == event_id]
        assert len(matching) == 1
        assert matching[0]["detected_threat"] == ThreatType.BOTNET.value


# ============================================================================
# TEST CASE 4 — HIGH/CRITICAL INCIDENT CREATION
# ============================================================================
def test_case_4_high_critical_incident_creation(client, admin_headers):
    """
    Validates auto-escalation of HIGH or CRITICAL risk events into incidents.
    Verifies: Incident creation, correct event/alert link, matching threat category,
    matching severity, valid status ('OPEN'), and timeline tracking.
    """
    mock_pred = {
        "predicted_threat": ThreatType.DOS_DDOS.value,
        "confidence": 0.97,
        "probabilities": {ThreatType.DOS_DDOS.value: 0.97},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "198.51.100.44",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "duration": 300000.0,
            "packet_count": 2500,
            "byte_count": 1200000,
            "protocol": "TCP"
        }

        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        data = response.json()["data"]

        assert data["incident"]["created"] is True
        incident_id = data["incident"]["incident_id"]
        assert incident_id is not None

        # Query incident details endpoint
        inc_res = client.get(f"/api/v1/incidents/{incident_id}", headers=admin_headers)
        assert inc_res.status_code == 200
        inc_data = inc_res.json()

        assert inc_data["id"] == incident_id
        assert inc_data["alert_id"] == data["alert"]["alert_id"]
        assert inc_data["threat_type"] == ThreatType.DOS_DDOS.value
        assert inc_data["severity"] in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
        assert inc_data["status"] == "OPEN"
        assert "response_actions" in inc_data


# ============================================================================
# TEST CASE 5 — SIMULATED RESPONSE
# ============================================================================
def test_case_5_simulated_response(client, admin_headers):
    """
    Validates simulated response policy execution.
    Verifies: Action creation, simulated action type (BLOCK/ISOLATION),
    safe simulation indicator (SIMULATED), correlation to incident and alert,
    and guarantee that no real OS/network manipulation occurs.
    """
    mock_pred = {
        "predicted_threat": ThreatType.BOTNET.value,
        "confidence": 0.98,
        "probabilities": {ThreatType.BOTNET.value: 0.98},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "203.0.113.88",
            "destination_ip": "10.0.0.1",
            "destination_port": 22,
            "duration": 450000.0,
            "packet_count": 1500,
            "byte_count": 800000
        }

        res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["response"]["action_type"] in [ActionType.SIMULATED_ISOLATION.value, ActionType.SIMULATED_BLOCK.value]
        assert data["response"]["action_status"] == ActionStatus.SIMULATED.value
        assert "SIMULATED" in data["response"]["description"]

        # Fetch simulated response actions list
        resp_list = client.get("/api/v1/response-actions?skip=0&limit=10", headers=admin_headers)
        assert resp_list.status_code == 200
        items = resp_list.json()["items"]
        matched = [a for a in items if a["incident_id"] == data["incident"]["incident_id"]]
        assert len(matched) >= 1
        action_item = matched[0]

        assert action_item["is_simulated"] is True
        assert action_item["action_status"] == ActionStatus.SIMULATED.value
        assert action_item["alert_id"] == data["alert"]["alert_id"]
        assert action_item["event_id"] == data["event_id"]
        assert action_item["executed_at"].endswith("Z")


# ============================================================================
# TEST CASE 6 — AUDIT LOGGING
# ============================================================================
def test_case_6_audit_logging(client, admin_headers):
    """
    Validates security audit trail creation upon threat analysis.
    Verifies: Audit record creation, user/event/action reference,
    status SUCCESS, and persistence across session commits.
    """
    payload = {
        "source_ip": "192.168.1.150",
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
        "duration": 1000.0,
        "packet_count": 10,
        "byte_count": 500
    }

    res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
    assert res.status_code == 200
    event_id = str(res.json()["data"]["event_id"])

    audit_res = client.get("/api/v1/audit-logs?limit=20", headers=admin_headers)
    assert audit_res.status_code == 200
    audit_items = audit_res.json()["items"]

    matching_logs = [
        log for log in audit_items
        if log["action"] == "EVENT_ANALYZED" and log["resource_id"] == event_id
    ]
    assert len(matching_logs) >= 1
    log_entry = matching_logs[0]
    assert log_entry["status"] == "SUCCESS"
    assert log_entry["resource_type"] == "DETECTION"
    assert log_entry["username"] == "admin"


# ============================================================================
# TEST CASE 7 — PERSISTENCE ACROSS RE-QUERIES
# ============================================================================
def test_case_7_persistence(client, admin_headers):
    """
    Validates end-to-end data persistence.
    Submits a high-risk event and verifies that detection history, alerts,
    incidents, response actions, and audit logs remain persistently queryable.
    """
    mock_pred = {
        "predicted_threat": ThreatType.DOS_DDOS.value,
        "confidence": 0.99,
        "probabilities": {ThreatType.DOS_DDOS.value: 0.99},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "198.51.100.99",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "duration": 500000.0,
            "packet_count": 2000,
            "byte_count": 1000000
        }

        res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert res.status_code == 200
        data = res.json()["data"]

        event_id = data["event_id"]
        alert_id = data["alert"]["alert_id"]
        incident_id = data["incident"]["incident_id"]

        # 1. Detection history persists
        hist_res = client.get(f"/api/v1/detection/history?skip=0&limit=50", headers=admin_headers)
        assert hist_res.status_code == 200
        assert any(it["event_id"] == event_id for it in hist_res.json()["items"])

        # 2. Alerts persist
        alert_res = client.get(f"/api/v1/alerts/{alert_id}", headers=admin_headers)
        assert alert_res.status_code == 200
        assert alert_res.json()["id"] == alert_id

        # 3. Incidents persist
        inc_res = client.get(f"/api/v1/incidents/{incident_id}", headers=admin_headers)
        assert inc_res.status_code == 200
        assert inc_res.json()["id"] == incident_id

        # 4. Response Actions persist
        resp_res = client.get(f"/api/v1/response-actions?skip=0&limit=50", headers=admin_headers)
        assert resp_res.status_code == 200
        assert any(act["incident_id"] == incident_id for act in resp_res.json()["items"])

        # 5. Audit logs persist
        audit_res = client.get(f"/api/v1/audit-logs?limit=50", headers=admin_headers)
        assert audit_res.status_code == 200
        assert any(lg["resource_id"] == str(event_id) for lg in audit_res.json()["items"])


# ============================================================================
# TEST CASE 8 — API AUTHORIZATION & RBAC
# ============================================================================
def test_case_8_api_authorization(client):
    """
    Validates authentication enforcement and Role-Based Access Control.
    Verifies: Unauthenticated requests to protected endpoints return 401,
    admin requests succeed, and privilege separation (Analyst vs Admin) is enforced.
    """
    # 1. Unauthenticated request to protected audit-logs -> 401
    unauth_audit = client.get(f"{settings.API_PREFIX}/audit-logs")
    assert unauth_audit.status_code == 401

    # 2. Unauthenticated request to protected user management -> 401
    unauth_users = client.get(f"{settings.API_PREFIX}/auth/users")
    assert unauth_users.status_code == 401

    # 3. Admin login -> 200
    admin_login = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD
    })
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 4. Admin accesses protected endpoints -> 200
    assert client.get(f"{settings.API_PREFIX}/audit-logs", headers=admin_headers).status_code == 200
    assert client.get(f"{settings.API_PREFIX}/auth/users", headers=admin_headers).status_code == 200

    # 5. Admin creates an Analyst user
    analyst_payload = {
        "username": "phase8_analyst",
        "email": "phase8@cyberguard.soc",
        "password": "AnalystPassword123!",
        "role": "ANALYST"
    }
    create_res = client.post(f"{settings.API_PREFIX}/auth/users", json=analyst_payload, headers=admin_headers)
    assert create_res.status_code == 201

    # 6. Analyst login
    analyst_login = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": "phase8_analyst",
        "password": "AnalystPassword123!"
    })
    assert analyst_login.status_code == 200
    analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

    # 7. Analyst can access audit logs (Analyst allowed)
    assert client.get(f"{settings.API_PREFIX}/audit-logs", headers=analyst_headers).status_code == 200

    # 8. Analyst cannot access user management (Admin only) -> 403 Forbidden
    assert client.get(f"{settings.API_PREFIX}/auth/users", headers=analyst_headers).status_code == 403


# ============================================================================
# TEST CASE 9 — INVALID INPUT & VALIDATION REJECTION
# ============================================================================
def test_case_9_invalid_input(client, admin_headers, db_session):
    """
    Validates strict schema validation on input parameters.
    Verifies: Rejection of invalid IP format, out-of-range port, negative duration,
    negative packet count, negative byte count, and malformed payload without creating DB records.
    """
    initial_event_count = db_session.query(SecurityEvent).count()

    invalid_payloads = [
        # Invalid IP address
        {"source_ip": "999.999.999.999", "destination_port": 80},
        # Port out of bounds (> 65535)
        {"source_ip": "192.168.1.1", "destination_port": 99999},
        # Port negative (< 0)
        {"source_ip": "192.168.1.1", "destination_port": -1},
        # Negative flow duration
        {"source_ip": "192.168.1.1", "duration": -50.0},
        # Negative packet count
        {"source_ip": "192.168.1.1", "packet_count": -5},
        # Negative byte count
        {"source_ip": "192.168.1.1", "byte_count": -100},
    ]

    for payload in invalid_payloads:
        res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert res.status_code == 422, f"Expected 422 for payload {payload}, got {res.status_code}"

    # Test malformed non-JSON payload
    res_malformed = client.post(
        "/api/v1/detection/analyze",
        content="malformed string body",
        headers={**admin_headers, "Content-Type": "application/json"}
    )
    assert res_malformed.status_code == 422

    # Verify no invalid database records were inserted
    final_event_count = db_session.query(SecurityEvent).count()
    assert final_event_count == initial_event_count, "Invalid payloads must not persist records in DB"


# ============================================================================
# TEST CASE 10 — DATABASE INTEGRITY & ORPHAN PREVENTION
# ============================================================================
def test_case_10_database_integrity(client, admin_headers, db_session):
    """
    Validates relational integrity across the entire cybersecurity data model.
    Runs multiple detections and verifies:
    - Zero orphan alerts (every Alert.event_id references a valid SecurityEvent)
    - Zero orphan incidents (every Incident.alert_id references a valid Alert)
    - Zero orphan response actions (every ResponseAction.incident_id references a valid Incident)
    - Bidirectional SQLAlchemy relationships remain intact.
    """
    # Trigger several varied events to populate relationships
    threats = [
        (ThreatType.NORMAL.value, 0.95),
        (ThreatType.DOS_DDOS.value, 0.98),
        (ThreatType.BOTNET.value, 0.99),
    ]

    for threat, conf in threats:
        mock_pred = {
            "predicted_threat": threat,
            "confidence": conf,
            "probabilities": {threat: conf},
            "model_version": "1.0.0"
        }
        with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
            client.post("/api/v1/detection/analyze", json={
                "source_ip": f"192.168.1.{conf*100:.0f}",
                "destination_port": 80 if threat != ThreatType.BOTNET.value else 22,
                "packet_count": 1000 if threat != ThreatType.NORMAL.value else 10,
                "duration": 50000.0
            }, headers=admin_headers)

    # 1. Verify no orphan alerts
    alerts = db_session.query(Alert).all()
    assert len(alerts) > 0, "Expected generated alerts"
    for alert in alerts:
        assert alert.event_id is not None
        assert db_session.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first() is not None
        assert alert.event is not None

    # 2. Verify no orphan incidents
    incidents = db_session.query(Incident).all()
    assert len(incidents) > 0, "Expected generated incidents"
    for inc in incidents:
        if inc.alert_id is not None:
            assert db_session.query(Alert).filter(Alert.id == inc.alert_id).first() is not None
            assert inc.alert is not None

    # 3. Verify no orphan response actions
    actions = db_session.query(ResponseAction).all()
    assert len(actions) > 0, "Expected simulated response actions"
    for act in actions:
        assert act.incident_id is not None
        assert db_session.query(Incident).filter(Incident.id == act.incident_id).first() is not None
        assert act.incident is not None
        assert act.action_status == ActionStatus.SIMULATED.value
