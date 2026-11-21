from unittest.mock import patch
from app.models.incident import Incident
from app.services.response_service import ResponseService
from app.services import detection_service
from app.schemas.response_action import ResponseActionCreate
from app.schemas.enums import ActionType, ActionStatus, ThreatType, RiskLevel


def test_simulated_response_action_execution(db_session):
    # Setup incident first
    incident = Incident(threat_type="BRUTE_FORCE", severity="HIGH", description="SSH Brute force attempt", status="OPEN")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    # Execute simulated block action
    action_in = ResponseActionCreate(
        incident_id=incident.id,
        action_type=ActionType.SIMULATED_BLOCK,
        description="Block source IP address 192.168.1.50 in virtual firewall"
    )

    action = ResponseService.execute_simulated_action(db_session, action_in)
    assert action.id is not None
    assert action.incident_id == incident.id
    assert action.action_status == ActionStatus.SIMULATED.value
    assert "Block source IP" in action.description


def test_qualifying_high_risk_event_generates_response(client, admin_headers):
    """
    Qualifying Event: DOS_DDOS threat with high risk score.
    Expected: Alert created, Incident created, ResponseAction created and retrieved via API.
    """
    mock_pred = {
        "predicted_threat": ThreatType.DOS_DDOS.value,
        "confidence": 0.99,
        "probabilities": {ThreatType.DOS_DDOS.value: 0.99},
        "model_version": "1.0.0"
    }
    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "duration": 250000.0,
            "packet_count": 1000,
            "byte_count": 500000
        }
        res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["alert"]["generated"] is True
        assert data["incident"]["created"] is True
        assert data["response"]["action_type"] in [ActionType.SIMULATED_BLOCK.value, ActionType.SIMULATED_ISOLATION.value]
        assert data["response"]["action_status"] == ActionStatus.SIMULATED.value

    # Verify GET /api/v1/response-actions endpoint returns the response record
    res_resp = client.get("/api/v1/response-actions?skip=0&limit=10", headers=admin_headers)
    assert res_resp.status_code == 200
    resp_body = res_resp.json()
    assert resp_body["success"] is True
    assert resp_body["total"] >= 1
    actions = resp_body["items"]
    matched = [a for a in actions if a["incident_id"] == data["incident"]["incident_id"]]
    assert len(matched) >= 1
    matched_action = matched[0]
    assert matched_action["id"] is not None
    assert matched_action["incident_id"] == data["incident"]["incident_id"]
    assert matched_action["alert_id"] == data["alert"]["alert_id"]
    assert matched_action["event_id"] == data["event_id"]
    assert matched_action["action_status"] == ActionStatus.SIMULATED.value
    assert matched_action["status"] == ActionStatus.SIMULATED.value
    assert matched_action["is_simulated"] is True
    assert matched_action["executed_at"].endswith("Z")
    assert matched_action["reason"] is not None


def test_response_action_filtering_and_retrieval(client, admin_headers):
    """
    Test filtering response actions by action_type.
    """
    res_all = client.get("/api/v1/response-actions?skip=0&limit=50", headers=admin_headers)
    assert res_all.status_code == 200
    items = res_all.json()["items"]
    if items:
        target_type = items[0]["action_type"]
        res_filtered = client.get(f"/api/v1/response-actions?action_type={target_type}", headers=admin_headers)
        assert res_filtered.status_code == 200
        filtered_items = res_filtered.json()["items"]
        assert all(it["action_type"] == target_type for it in filtered_items)


def test_non_qualifying_normal_event_generates_no_response(client, admin_headers):
    """
    Non-Qualifying Event: NORMAL benign network flow.
    Expected: NORMAL threat, LOW risk, no Alert, no Incident, no ResponseAction.
    """
    mock_pred = {
        "predicted_threat": ThreatType.NORMAL.value,
        "confidence": 0.98,
        "probabilities": {ThreatType.NORMAL.value: 0.98},
        "model_version": "1.0.0"
    }
    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 80,
            "duration": 50000.0,
            "packet_count": 15,
            "byte_count": 15000
        }
        res = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["alert"]["generated"] is False
        assert data["incident"]["created"] is False
        assert data["response"]["action_status"] == "NONE"

