#!/usr/bin/env python3
"""
Feature Pipeline Module: Scikit-learn preprocessor pipeline ensuring zero data leakage between train and test splits.
"""
from typing import Tuple, List
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.pipeline import Pipeline
from ml.preprocessing.label_mapping import map_dataframe_labels

FEATURE_COLUMNS: List[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count"
]


def create_preprocessor_pipeline(numerical_features: List[str] = None) -> ColumnTransformer:
    """
    Creates Scikit-learn ColumnTransformer for numerical scaling.
    """
    numerical_features = numerical_features or FEATURE_COLUMNS
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", RobustScaler(), numerical_features)
        ],
        remainder="passthrough"
    )
    return preprocessor


def prepare_features_and_target(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Extracts feature matrix X and standardized target vector y.
    """
    df_mapped = map_dataframe_labels(df, label_col="Label")

    available_features = [col for col in FEATURE_COLUMNS if col in df_mapped.columns]
    X = df_mapped[available_features].copy()
    y = df_mapped["standardized_label"].copy()
    return X, y
