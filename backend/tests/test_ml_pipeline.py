import os
import pytest
import pandas as pd
from ml.preprocessing.label_mapping import normalize_raw_label, map_dataframe_labels
from ml.preprocessing.clean_data import clean_dataset
from ml.inference.predictor import ThreatPredictor
from app.schemas.enums import ThreatType


def test_label_mapping_normalization():
    assert normalize_raw_label("BENIGN") == ThreatType.NORMAL.value
    assert normalize_raw_label("DoS Hulk") == ThreatType.DOS_DDOS.value
    assert normalize_raw_label("PortScan") == ThreatType.PORT_SCAN.value
    assert normalize_raw_label("FTP-Patator") == ThreatType.BRUTE_FORCE.value
    assert normalize_raw_label("UNKNOWN_ATTACK") == ThreatType.NORMAL.value


def test_label_mapping_dataframe():
    df = pd.DataFrame({"Label": ["BENIGN", "DDoS", "Bot"]})
    df_mapped = map_dataframe_labels(df)
    assert "standardized_label" in df_mapped.columns
    assert list(df_mapped["standardized_label"]) == [
        ThreatType.NORMAL.value,
        ThreatType.DOS_DDOS.value,
        ThreatType.BOTNET.value
    ]


def test_ml_predictor_inference():
    predictor = ThreatPredictor()
    sample_flow = {
        "destination_port": 80,
        "duration": 50000.0,
        "packet_count": 100,
        "byte_count": 50000,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1
    }
    result = predictor.predict(sample_flow)
    assert "predicted_threat" in result
    assert "confidence" in result
    assert "probabilities" in result
    assert "model_version" in result
    assert isinstance(result["confidence"], float)
    assert 0.0 <= result["confidence"] <= 1.0


def test_event_ingestion_with_ml_detection(client, admin_headers):
    # Post a suspicious event that triggers DDoS classification
    payload = {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 50000,
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 200000.0,
        "packet_count": 500,
        "byte_count": 400000,
        "event_type": "NETWORK"
    }
    response = client.post("/api/v1/events", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["id"] is not None

    # Check that alert was generated for non-normal threat
    res_alerts = client.get("/api/v1/alerts", headers=admin_headers)
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()["items"]
    assert len(alerts) >= 1
