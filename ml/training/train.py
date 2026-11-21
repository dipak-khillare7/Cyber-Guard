#!/usr/bin/env python3
"""
Model Training & Evaluation Script:
Trains multiple candidate multi-class cybersecurity models, evaluates metrics, compares performance,
generates confusion matrices, and serializes the best end-to-end pipeline with full metadata.
"""
import os
import sys

# Ensure root workspace and backend directories are in Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
BACKEND_DIR = os.path.join(ROOT_DIR, 'backend')
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import time
import json
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, accuracy_score
from sklearn.pipeline import Pipeline

from ml.preprocessing.clean_data import clean_dataset, PROCESSED_DATA_PATH
from ml.preprocessing.feature_pipeline import create_preprocessor_pipeline, prepare_features_and_target, FEATURE_COLUMNS

EVAL_DIR = os.path.join(ROOT_DIR, 'ml/evaluation')
REPORTS_DIR = os.path.join(EVAL_DIR, 'reports')
FIGURES_DIR = os.path.join(EVAL_DIR, 'figures')
MODELS_DIR = os.path.join(ROOT_DIR, 'ml/models')


def train_and_evaluate_all_models():
    print("=" * 80)
    print(" CYBERSECURITY THREAT DETECTION — ML TRAINING & EVALUATION PIPELINE")
    print("=" * 80)

    # 1. Clean & Load Processed Dataset
    if not os.path.exists(PROCESSED_DATA_PATH):
        df_clean = clean_dataset()
    else:
        df_clean = pd.read_csv(PROCESSED_DATA_PATH)

    # 2. Extract Features (X) and Target Labels (y)
    X, y = prepare_features_and_target(df_clean)
    print(f"\n[1] Data Loaded: {X.shape[0]} records, {X.shape[1]} features.")
    print(f"    Target Classes ({len(np.unique(y))} unique): {list(np.unique(y))}")

    # 3. Stratified Train / Validation / Test Split (70% Train, 15% Val, 15% Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\n[2] Data Split (Stratified, Seed=42):")
    print(f"    - Training Set  : {len(X_train)} samples ({len(X_train)/len(X)*100:.1f}%)")
    print(f"    - Validation Set: {len(X_val)} samples ({len(X_val)/len(X)*100:.1f}%)")
    print(f"    - Test Set      : {len(X_test)} samples ({len(X_test)/len(X)*100:.1f}%)")

    # 4. Define Candidate Models
    candidate_models = {
        "LogisticRegression": LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
        "DecisionTree": DecisionTreeClassifier(max_depth=15, class_weight='balanced', random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=15, class_weight='balanced', random_state=42, n_jobs=-1),
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=100, random_state=42)
    }

    results = []
    trained_pipelines = {}

    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"\n[3] Training & Evaluating Candidate Models:")
    print("-" * 80)

    for name, clf in candidate_models.items():
        preprocessor = create_preprocessor_pipeline(list(X.columns))
        pipeline = Pipeline(steps=[
            ("preprocessor", preprocessor),
            ("classifier", clf)
        ])

        # Train pipeline (fitted ONLY on training data split to prevent leakage)
        t0 = time.time()
        pipeline.fit(X_train, y_train)
        train_time = round(time.time() - t0, 4)

        # Predict on Test set
        t1 = time.time()
        y_pred = pipeline.predict(X_test)
        inference_time = round((time.time() - t1) / len(X_test) * 1000, 4) # ms per sample

        # Calculate metrics
        acc = float(accuracy_score(y_test, y_pred))
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(y_test, y_pred, average='macro', zero_division=0)
        _, _, weighted_f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)

        result_row = {
            "model_name": name,
            "accuracy": round(acc, 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "train_time_sec": train_time,
            "inference_time_ms_per_sample": inference_time
        }
        results.append(result_row)
        trained_pipelines[name] = pipeline

        print(f"  > {name:<22} | Acc: {acc:.4f} | Macro F1: {macro_f1:.4f} | Macro Rec: {macro_rec:.4f} | Train Time: {train_time:.2f}s")

    # 5. Save Experiment Results Comparison Table
    df_results = pd.DataFrame(results)
    exp_csv_path = os.path.join(EVAL_DIR, "experiment_results.csv")
    df_results.to_csv(exp_csv_path, index=False)
    print(f"\n[4] Saved experiment comparison table to {exp_csv_path}")

    # 6. Select Best Model Based on Macro F1 Score
    best_row = df_results.sort_values(by="macro_f1", ascending=False).iloc[0]
    best_name = best_row["model_name"]
    best_pipeline = trained_pipelines[best_name]

    print(f"\n[5] Selected Winner Model: '{best_name}' (Macro F1: {best_row['macro_f1']})")

    # 7. Generate & Save Confusion Matrix Plot and Classification Report
    y_test_pred = best_pipeline.predict(X_test)
    labels_order = sorted(list(np.unique(y)))

    cm = confusion_matrix(y_test, y_test_pred, labels=labels_order)
    
    # Save Confusion Matrix Figure
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels_order, yticklabels=labels_order)
    plt.title(f'Confusion Matrix — {best_name}')
    plt.xlabel('Predicted Threat Class')
    plt.ylabel('True Threat Class')
    plt.tight_layout()
    fig_path = os.path.join(FIGURES_DIR, "confusion_matrix.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"    - Saved Confusion Matrix figure to {fig_path}")

    # Save Classification Report JSON
    cls_report = classification_report(y_test, y_test_pred, output_dict=True, zero_division=0)
    report_json_path = os.path.join(REPORTS_DIR, "classification_report.json")
    with open(report_json_path, "w") as f:
        json.dump(cls_report, f, indent=2)
    print(f"    - Saved Classification Report to {report_json_path}")

    # 8. Serialize Best End-to-End Pipeline & Metadata
    model_joblib_path = os.path.join(MODELS_DIR, "best_threat_model.joblib")
    joblib.dump(best_pipeline, model_joblib_path)

    metadata = {
        "model_name": best_name,
        "model_version": "1.0.0",
        "training_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": "CIC-IDS2017 Benchmark Subset",
        "dataset_version": "2017-flow-v1",
        "feature_version": "v1.0.0",
        "label_version": "standardized-7-class",
        "algorithm": best_name,
        "feature_columns": list(X.columns),
        "target_classes": labels_order,
        "metrics": {
            "accuracy": float(best_row["accuracy"]),
            "macro_precision": float(best_row["macro_precision"]),
            "macro_recall": float(best_row["macro_recall"]),
            "macro_f1": float(best_row["macro_f1"]),
            "weighted_f1": float(best_row["weighted_f1"])
        },
        "binary_path": "best_threat_model.joblib"
    }

    metadata_path = os.path.join(MODELS_DIR, "metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[6] Model Serialization Complete:")
    print(f"    - Serialized Pipeline: {model_joblib_path}")
    print(f"    - Model Metadata   : {metadata_path}")

    print("\n" + "=" * 80)
    print(" ML Training & Evaluation Finished Successfully!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    train_and_evaluate_all_models()
