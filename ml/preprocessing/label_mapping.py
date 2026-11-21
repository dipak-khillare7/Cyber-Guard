#!/usr/bin/env python3
"""
Label Mapping Module: Standardizes raw dataset threat labels to project ThreatType Enum categories.
"""
from typing import Dict, List
import pandas as pd
from app.schemas.enums import ThreatType

# Explicit mapping dictionary from dataset raw labels to standardized ThreatType Enum strings
DATASET_LABEL_MAPPING: Dict[str, str] = {
    "BENIGN": ThreatType.NORMAL.value,
    "NORMAL": ThreatType.NORMAL.value,
    "DOS HULK": ThreatType.DOS_DDOS.value,
    "DOS SLOWLORIS": ThreatType.DOS_DDOS.value,
    "DOS GOLDENEYE": ThreatType.DOS_DDOS.value,
    "DDOS": ThreatType.DOS_DDOS.value,
    "PORTSCAN": ThreatType.PORT_SCAN.value,
    "PORT SCAN": ThreatType.PORT_SCAN.value,
    "FTP-PATATOR": ThreatType.BRUTE_FORCE.value,
    "SSH-PATATOR": ThreatType.BRUTE_FORCE.value,
    "BRUTE FORCE": ThreatType.BRUTE_FORCE.value,
    "WEB ATTACK – BRUTE FORCE": ThreatType.WEB_ATTACK.value,
    "WEB ATTACK - BRUTE FORCE": ThreatType.WEB_ATTACK.value,
    "WEB ATTACK – XSS": ThreatType.WEB_ATTACK.value,
    "WEB ATTACK – SQL INJECTION": ThreatType.WEB_ATTACK.value,
    "WEB ATTACK": ThreatType.WEB_ATTACK.value,
    "BOT": ThreatType.BOTNET.value,
    "BOTNET": ThreatType.BOTNET.value,
    "INFILTRATION": ThreatType.INFILTRATION.value,
}

PLANNED_THREAT_CATEGORIES: List[str] = [e.value for e in ThreatType]


def normalize_raw_label(raw_label: str) -> str:
    """
    Normalizes a single raw label string to a standardized ThreatType category.
    """
    if not isinstance(raw_label, str):
        return ThreatType.NORMAL.value
    cleaned = raw_label.strip().upper()
    return DATASET_LABEL_MAPPING.get(cleaned, ThreatType.NORMAL.value)


def map_dataframe_labels(df: pd.DataFrame, label_col: str = "Label") -> pd.DataFrame:
    """
    Applies label normalization to a target DataFrame column.
    """
    df_mapped = df.copy()
    if label_col in df_mapped.columns:
        df_mapped["standardized_label"] = df_mapped[label_col].apply(normalize_raw_label)
    else:
        df_mapped["standardized_label"] = ThreatType.NORMAL.value
    return df_mapped


def get_label_mapping_report() -> Dict[str, List[str]]:
    """
    Returns explicit mapping metadata and unsupported category analysis.
    """
    supported_categories = sorted(list(set(DATASET_LABEL_MAPPING.values())))
    unsupported_categories = [c for c in PLANNED_THREAT_CATEGORIES if c not in supported_categories]
    return {
        "supported_categories": supported_categories,
        "unsupported_categories": unsupported_categories,
        "mapping_dictionary": DATASET_LABEL_MAPPING
    }
