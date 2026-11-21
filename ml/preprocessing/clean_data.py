#!/usr/bin/env python3
"""
Data Cleaning Module: Reproducibly cleans missing values, infinite values, duplicate records, and invalid ranges.
"""
import os
import sys
import numpy as np
import pandas as pd

RAW_DATA_PATH = os.path.join(os.path.dirname(__file__), '../../dataset/raw/cicids2017_subset.csv')
PROCESSED_DATA_PATH = os.path.join(os.path.dirname(__file__), '../../dataset/processed/clean_dataset.csv')


def clean_dataset(input_path: str = RAW_DATA_PATH, output_path: str = PROCESSED_DATA_PATH) -> pd.DataFrame:
    """
    Cleans raw dataset and outputs a reproducible processed CSV artifact.
    """
    print(f"Cleaning raw dataset from {input_path}...")
    df = pd.read_csv(input_path)
    initial_rows = len(df)

    # 1. Deduplication
    df = df.drop_duplicates()
    dedup_rows = len(df)
    print(f"  - Deduplicated: {initial_rows - dedup_rows} duplicate rows removed.")

    # 2. Infinite Values Handling (+inf / -inf)
    num_cols = df.select_dtypes(include=[np.number]).columns
    for col in num_cols:
        inf_mask = np.isinf(df[col])
        if inf_mask.sum() > 0:
            # Replace +inf / -inf with NaN first for uniform imputation
            df.loc[inf_mask, col] = np.nan

    # 3. Missing Values (NaN) Imputation
    null_counts = df.isnull().sum()
    for col in num_cols:
        if df[col].isnull().sum() > 0:
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)
            print(f"  - Imputed missing/infinite values in '{col}' with median ({median_val:.2f})")

    # 4. Range & Invalid Values Validation
    if "Destination Port" in df.columns:
        df["Destination Port"] = df["Destination Port"].clip(0, 65535)
    if "Flow Duration" in df.columns:
        df["Flow Duration"] = df["Flow Duration"].clip(lower=0.0)

    # Clean label whitespace
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Cleaned dataset saved to {output_path} (Final rows: {len(df)}).")
    return df

if __name__ == "__main__":
    in_p = sys.argv[1] if len(sys.argv) > 1 else RAW_DATA_PATH
    out_p = sys.argv[2] if len(sys.argv) > 2 else PROCESSED_DATA_PATH
    clean_dataset(in_p, out_p)
