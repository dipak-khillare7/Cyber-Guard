"""
Centralized Configuration for Risk Engine Assessment.
Defines baseline threat weights, critical port factors, and risk level thresholds.
"""
from typing import Dict
from app.schemas.enums import ThreatType, RiskLevel

# Baseline severity score (0-100) per threat category
THREAT_BASELINE_WEIGHTS: Dict[str, float] = {
    ThreatType.NORMAL.value: 0.0,
    ThreatType.PORT_SCAN.value: 35.0,
    ThreatType.BRUTE_FORCE.value: 65.0,
    ThreatType.WEB_ATTACK.value: 70.0,
    ThreatType.CREDENTIAL_ATTACK.value: 75.0,
    ThreatType.DOS_DDOS.value: 85.0,
    ThreatType.BOTNET.value: 88.0,
    ThreatType.MALWARE.value: 90.0,
    ThreatType.INFILTRATION.value: 95.0,
    ThreatType.DATA_EXFILTRATION.value: 98.0,
}

# Critical infrastructure destination ports requiring elevated risk weighting
CRITICAL_PORTS = {22, 3389, 443, 80, 53, 3306, 5432, 21, 23}

# Risk Level Thresholds (Score range 0.0 to 1.0)
RISK_LEVEL_THRESHOLDS = {
    RiskLevel.CRITICAL.value: 0.85,
    RiskLevel.HIGH.value: 0.65,
    RiskLevel.MEDIUM.value: 0.35,
    RiskLevel.LOW.value: 0.0,
}
