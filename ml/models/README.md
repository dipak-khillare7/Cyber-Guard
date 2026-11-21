# Serialized ML Models & Metadata Directory

This directory stores serialized end-to-end Scikit-learn Pipeline binaries (`.joblib`) and model metadata (`metadata.json`).

## Serialized Artifacts

* `best_threat_model.joblib`: Serialized `HistGradientBoostingClassifier` pipeline (includes `RobustScaler` preprocessor + classifier).
* `metadata.json`: Machine-readable metadata record containing model version, dataset provenance, metrics, target classes, and algorithm specifications.

## Traceability Policy
Do not save unexplained `model.pkl` binaries without an accompanying `metadata.json` file.
