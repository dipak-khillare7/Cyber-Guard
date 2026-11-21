import pytest
from unittest.mock import patch
from app.schemas.enums import ThreatType, RiskLevel, ActionType
from app.services import detection_service


def test_1_normal_event_detection(client, admin_headers):
    """
    Test 1: Normal benign network flow analysis.
    Expected: NORMAL threat, LOW risk, no alert generated.
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
            "byte_count": 15000,
            "syn_flag_count": 0,
            "ack_flag_count": 1
        }
        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        res = response.json()
        assert res["success"] is True
        data = res["data"]
        assert data["prediction"]["threat_type"] == ThreatType.NORMAL.value
        assert data["risk"]["level"] == RiskLevel.LOW.value
        assert data["alert"]["generated"] is False
        assert data["incident"]["created"] is False


def test_2_malicious_event_detection(client, admin_headers):
    """
    Test 2: Known malicious threat flow analysis.
    Expected: Non-NORMAL threat detected, HIGH or CRITICAL risk.
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
            "byte_count": 500000,
            "syn_flag_count": 1,
            "ack_flag_count": 1
        }
        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        res = response.json()
        assert res["success"] is True
        data = res["data"]
        assert data["prediction"]["threat_type"] != ThreatType.NORMAL.value
        assert data["risk"]["level"] in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
        assert data["alert"]["generated"] is True
        assert data["incident"]["created"] is True


def test_3_invalid_input_validation(client, admin_headers):
    """
    Test 3: Invalid input payload (impossible port 99999 or bad IP).
    Expected: 422 Validation Error.
    """
    payload = {
        "source_ip": "999.999.999.999",
        "destination_port": 99999
    }
    response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
    assert response.status_code == 422


def test_4_model_unavailable_error_handling(client, admin_headers):
    """
    Test 4: Model predictor failure / unavailable state.
    Expected: 503 Controlled Service Error (does NOT classify silently as NORMAL).
    """
    with patch.object(detection_service.ml_predictor, "predict", side_effect=RuntimeError("Model file corrupted")):
        payload = {"destination_port": 80, "packet_count": 10}
        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 503
        res = response.json()
        assert res["detail"]["code"] == "DETECTION_ENGINE_UNAVAILABLE"


def test_5_high_risk_pipeline_execution(client, admin_headers):
    """
    Test 5: High-risk threat prediction workflow.
    Expected: Alert created, Incident created, Simulated response recorded in DB.
    """
    mock_pred = {
        "predicted_threat": ThreatType.BOTNET.value,
        "confidence": 0.95,
        "probabilities": {ThreatType.BOTNET.value: 0.95},
        "model_version": "1.0.0"
    }

    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        payload = {
            "source_ip": "172.16.0.55",
            "destination_ip": "10.0.0.1",
            "destination_port": 22,
            "duration": 5000.0,
            "packet_count": 30,
            "byte_count": 2400
        }
        response = client.post("/api/v1/detection/analyze", json=payload, headers=admin_headers)
        assert response.status_code == 200
        data = response.json()["data"]

        # Verify DB records
        assert data["event_id"] is not None
        assert data["alert"]["alert_id"] is not None
        assert data["incident"]["incident_id"] is not None
        assert data["response"]["action_status"] == "SIMULATED"


def test_6_end_to_end_detection_and_history(client, admin_headers):
    """
    Test 6: End-to-end integration and detection history verification.
    """
    mock_pred = {
        "predicted_threat": ThreatType.NORMAL.value,
        "confidence": 0.95,
        "probabilities": {ThreatType.NORMAL.value: 0.95},
        "model_version": "1.0.0"
    }
    with patch.object(detection_service.ml_predictor, "predict", return_value=mock_pred):
        # 1. Post event to /analyze
        res_post = client.post("/api/v1/detection/analyze", json={"source_ip": "10.0.0.99", "destination_port": 80}, headers=admin_headers)
        assert res_post.status_code == 200
        event_id = res_post.json()["data"]["event_id"]

    # 2. Query /history
    res_hist = client.get("/api/v1/detection/history?skip=0&limit=10", headers=admin_headers)
    assert res_hist.status_code == 200
    hist_data = res_hist.json()
    assert hist_data["success"] is True
    assert hist_data["total"] >= 1
    found = any(item["event_id"] == event_id for item in hist_data["items"])
    assert found is True
