from typing import Any, Tuple
import pandas as pd
import numpy as np
from app.core.logging import logger


class DataPreprocessor:
    """
    Interface & baseline implementation for cybersecurity dataset preprocessing.
    """

    def __init__(self, feature_version: str = "v1.0.0"):
        self.feature_version = feature_version

    def load_data(self, file_path: str) -> pd.DataFrame:
        """
        Loads raw dataset from file path (CSV, Parquet, JSON).
        """
        logger.info(f"Loading raw dataset from {file_path}")
        if file_path.endswith(".csv"):
            return pd.read_csv(file_path)
        elif file_path.endswith(".parquet"):
            return pd.read_parquet(file_path)
        else:
            raise ValueError(f"Unsupported dataset format: {file_path}")

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Cleans missing values, strips whitespace, and removes duplicate rows.
        """
        logger.info("Cleaning raw dataset...")
        df_cleaned = df.copy()
        df_cleaned = df_cleaned.drop_duplicates()
        df_cleaned = df_cleaned.ffill().bfill()
        return df_cleaned

    def transform_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforms network features (e.g. log scaling for duration/bytes, encoding categorical features).
        """
        logger.info("Transforming dataset features...")
        df_trans = df.copy()
        numeric_cols = df_trans.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if df_trans[col].min() >= 0:
                df_trans[f"{col}_log"] = np.log1p(df_trans[col])
        return df_trans

    def prepare_features(self, df: pd.DataFrame, target_column: str = "label") -> Tuple[pd.DataFrame, pd.Series]:
        """
        Separates feature matrix (X) and target labels (y).
        """
        logger.info(f"Preparing X and y with target column '{target_column}'")
        df_cleaned = self.clean_data(df)
        df_transformed = self.transform_features(df_cleaned)

        if target_column in df_transformed.columns:
            X = df_transformed.drop(columns=[target_column])
            y = df_transformed[target_column]
        else:
            X = df_transformed
            y = pd.Series([], dtype=object)

        return X, y
