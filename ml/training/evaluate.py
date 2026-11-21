#!/usr/bin/env python3
"""
Standalone Model Evaluation Module: Generates evaluation metrics and confusion matrix visual artifacts.
"""
import os
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support


def evaluate_model_performance(y_true, y_pred, labels_order, model_name="Model"):
    """
    Computes metrics and returns formatted evaluation dictionary.
    """
    acc = float(accuracy_score(y_true, y_pred))
    macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average='macro', zero_division=0)
    _, _, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted', zero_division=0)

    report_dict = classification_report(y_true, y_pred, output_dict=True, zero_division=0)

    metrics = {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "macro_precision": round(float(macro_prec), 4),
        "macro_recall": round(float(macro_rec), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "classification_report": report_dict
    }
    return metrics


def plot_and_save_confusion_matrix(y_true, y_pred, labels_order, output_path, title="Confusion Matrix"):
    """
    Generates and saves Seaborn confusion matrix heatmap.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cm = confusion_matrix(y_true, y_pred, labels=labels_order)

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels_order, yticklabels=labels_order)
    plt.title(title)
    plt.xlabel('Predicted Threat Class')
    plt.ylabel('True Threat Class')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path
