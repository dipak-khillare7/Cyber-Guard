#!/usr/bin/env python3
"""
Dataset Inspection Script: Performs read-only statistical analysis on raw cybersecurity datasets.
"""
import os
import sys
import numpy as np
import pandas as pd

DEFAULT_RAW_PATH = os.path.join(os.path.dirname(__file__), '../../dataset/raw/cicids2017_subset.csv')

def inspect_dataset(file_path: str = DEFAULT_RAW_PATH) -> dict:
    """
    Performs comprehensive, read-only inspection of target cybersecurity dataset.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    print("=" * 80)
    print(f" CYBERSECURITY DATASET INSPECTION REPORT")
    print(f" Source File: {os.path.abspath(file_path)}")
    print("=" * 80)

    df = pd.read_csv(file_path)

    n_rows, n_cols = df.shape
    print(f"\n[1] Basic Dimensions:")
    print(f"  - Total Rows: {n_rows}")
    print(f"  - Total Columns: {n_cols}")

    print(f"\n[2] Feature Columns & Data Types:")
    for col in df.columns:
        dtype = df[col].dtype
        print(f"  - {col:<32}: {dtype}")

    # Missing & Infinite Values
    null_counts = df.isnull().sum()
    total_nulls = null_counts.sum()
    
    # Check numeric columns for inf
    num_cols = df.select_dtypes(include=[np.number]).columns
    inf_counts = {}
    for col in num_cols:
        inf_cnt = np.isinf(df[col]).sum()
        if inf_cnt > 0:
            inf_counts[col] = inf_cnt

    print(f"\n[3] Missing & Infinite Values:")
    print(f"  - Total Null/NaN Cells: {total_nulls}")
    if total_nulls > 0:
        for col, count in null_counts[null_counts > 0].items():
            print(f"    * {col}: {count} missing ({count/n_rows*100:.2f}%)")
    
    print(f"  - Columns with Infinity (+inf / -inf): {len(inf_counts)}")
    for col, count in inf_counts.items():
        print(f"    * {col}: {count} infinite values ({count/n_rows*100:.2f}%)")

    # Duplicate Records
    dup_count = df.duplicated().sum()
    print(f"\n[4] Duplicate Records:")
    print(f"  - Duplicate Rows: {dup_count} ({dup_count/n_rows*100:.2f}%)")

    # Label & Target Distribution
    label_col = "Label" if "Label" in df.columns else df.columns[-1]
    print(f"\n[5] Target Class Distribution (Column: '{label_col}'):")
    class_counts = df[label_col].value_counts()
    for label, count in class_counts.items():
        pct = (count / n_rows) * 100.0
        print(f"  - {str(label):<30}: {count:>6} samples ({pct:>6.2f}%)")

    report = {
        "n_rows": n_rows,
        "n_cols": n_cols,
        "null_count": int(total_nulls),
        "inf_columns": inf_counts,
        "duplicate_count": int(dup_count),
        "class_counts": class_counts.to_dict(),
        "columns": list(df.columns)
    }

    print("\n" + "=" * 80)
    print(" Inspection complete. Raw dataset remains unmodified.")
    print("=" * 80 + "\n")
    return report

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RAW_PATH
    inspect_dataset(path)
