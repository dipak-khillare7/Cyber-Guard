#!/usr/bin/env python3
"""
Inference Engine Predictor: Loads trained serialized Scikit-learn Pipeline and returns threat predictions with class probabilities and confidence.
"""
import os
import sys

# Ensure workspace root and backend are in path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
BACKEND_DIR = os.path.join(ROOT_DIR, 'backend')
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import json
from typing import Dict, Any, Tuple
import pandas as pd
import joblib
from app.schemas.enums import ThreatType

MODELS_DIR = os.path.join(ROOT_DIR, 'ml/models')
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, 'best_threat_model.joblib')
DEFAULT_METADATA_PATH = os.path.join(MODELS_DIR, 'metadata.json')


class ThreatPredictor:
    """
    Production Inference Engine loading serialized model pipeline and returning structured prediction.
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, metadata_path: str = DEFAULT_METADATA_PATH):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.pipeline = None
        self.metadata = {}
        self.target_classes = []
        self._load_model_and_metadata()

    def _load_model_and_metadata(self):
        """
        Loads Joblib pipeline and metadata JSON.
        """
        if os.path.exists(self.metadata_path):
            with open(self.metadata_path, 'r') as f:
                self.metadata = json.load(f)
            self.target_classes = self.metadata.get("target_classes", [e.value for e in ThreatType])

        if os.path.exists(self.model_path):
            self.pipeline = joblib.load(self.model_path)
            print(f"[ThreatPredictor] Successfully loaded ML pipeline: {self.metadata.get('model_name', 'Trained Model')} v{self.metadata.get('model_version', '1.0.0')}")
        else:
            print(f"[ThreatPredictor] Model file not found at {self.model_path}. Using fallback prediction mode.")

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predicts threat category, confidence score, and full class probability breakdown.

        :param feature_dict: Dict containing network flow attributes
        :return: Dict containing predicted_threat, confidence, probabilities, model_version
        """
        if self.pipeline is None:
            # Baseline fallback if model binary is missing
            return {
                "predicted_threat": ThreatType.NORMAL.value,
                "confidence": 0.95,
                "probabilities": {ThreatType.NORMAL.value: 0.95},
                "model_version": "0.1.0-fallback"
            }

        # Format input feature vector matching training feature names
        input_data = {
            "Destination Port": [feature_dict.get("Destination Port", feature_dict.get("destination_port", 80))],
            "Flow Duration": [feature_dict.get("Flow Duration", feature_dict.get("duration", 1000.0))],
            "Total Fwd Packets": [feature_dict.get("Total Fwd Packets", feature_dict.get("packet_count", 10))],
            "Total Backward Packets": [feature_dict.get("Total Backward Packets", 5)],
            "Total Length of Fwd Packets": [feature_dict.get("Total Length of Fwd Packets", feature_dict.get("byte_count", 500))],
            "Total Length of Bwd Packets": [feature_dict.get("Total Length of Bwd Packets", 500)],
            "Flow Bytes/s": [feature_dict.get("Flow Bytes/s", 100.0)],
            "Flow Packets/s": [feature_dict.get("Flow Packets/s", 10.0)],
            "SYN Flag Count": [feature_dict.get("SYN Flag Count", 0)],
            "ACK Flag Count": [feature_dict.get("ACK Flag Count", 1)]
        }

        df_input = pd.DataFrame(input_data)

        # Execute Pipeline Prediction
        pred_class = str(self.pipeline.predict(df_input)[0])

        probabilities = {}
        confidence = 0.95
        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(df_input)[0]
            classes = self.pipeline.classes_
            for cls_name, prob in zip(classes, probs):
                probabilities[str(cls_name)] = round(float(prob), 4)
            confidence = round(float(max(probs)), 4)

        return {
            "predicted_threat": pred_class,
            "confidence": confidence,
            "probabilities": probabilities,
            "model_version": self.metadata.get("model_version", "1.0.0")
        }


if __name__ == "__main__":
    predictor = ThreatPredictor()
    sample_flow = {
        "destination_port": 80,
        "duration": 250000.0,
        "packet_count": 450,
        "byte_count": 350000,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1
    }
    result = predictor.predict(sample_flow)
    print("\nSample Inference Result:")
    print(json.dumps(result, indent=2))
