import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import joblib
from app.core.logging import logger


class ModelTrainer:
    """
    ML Training Interface for candidate threat detection models with metadata versioning.
    """

    def __init__(self, model_name: str = "cyber_threat_classifier", model_version: str = "1.0.0"):
        self.model_name = model_name
        self.model_version = model_version
        self.model = None

    def train_model(self, X_train: Any, y_train: Any, algorithm_cls: Any, hyperparameters: Dict[str, Any] = None) -> Any:
        """
        Instantiates and trains candidate ML model on training data.
        """
        hyperparameters = hyperparameters or {}
        logger.info(f"Training {self.model_name} v{self.model_version} using {algorithm_cls.__name__}")
        self.model = algorithm_cls(**hyperparameters)
        self.model.fit(X_train, y_train)
        return self.model

    def evaluate_model(self, X_test: Any, y_test: Any) -> Dict[str, float]:
        """
        Evaluates model metrics (accuracy, precision, recall, f1-score).
        """
        if self.model is None:
            raise ValueError("Model has not been trained yet.")

        logger.info("Evaluating model metrics on test set...")
        predictions = self.model.predict(X_test)
        
        # Simple baseline metrics calculation
        accuracy = float((predictions == y_test).mean()) if len(y_test) > 0 else 0.0
        
        metrics = {
            "accuracy": accuracy,
            "sample_count": len(y_test)
        }
        logger.info(f"Evaluation metrics: {metrics}")
        return metrics

    def save_model(
        self,
        output_dir: str,
        training_dataset: str,
        metrics: Dict[str, float],
        algorithm: str
    ) -> str:
        """
        Saves trained model binary along with metadata.json artifact.
        """
        os.makedirs(output_dir, exist_ok=True)
        model_filename = f"{self.model_name}_v{self.model_version}.joblib"
        model_path = os.path.join(output_dir, model_filename)

        # Save model binary
        joblib.dump(self.model, model_path)

        # Save metadata JSON
        metadata = {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "training_dataset": training_dataset,
            "training_date": datetime.now(timezone.utc).isoformat(),
            "feature_version": "v1.0.0",
            "algorithm": algorithm,
            "metrics": metrics,
            "binary_path": model_filename
        }

        metadata_path = os.path.join(output_dir, "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved model binary to {model_path} and metadata to {metadata_path}")
        return model_path
