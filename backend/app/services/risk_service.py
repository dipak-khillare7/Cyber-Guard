from typing import Dict, Any, Tuple
from app.schemas.enums import ThreatType, RiskLevel
from app.core.risk_config import THREAT_BASELINE_WEIGHTS, CRITICAL_PORTS, RISK_LEVEL_THRESHOLDS
from app.core.logging import logger


def calculate_risk(
    threat_type: ThreatType,
    confidence: float,
    context: Dict[str, Any] = None
) -> Tuple[RiskLevel, float, str]:
    """
    Calculates numerical risk score (0.0 - 1.0), RiskLevel enum, and explainable reason.

    :param threat_type: Classified threat category.
    :param confidence: ML detection confidence probability (0.0 - 1.0).
    :param context: Additional event context (destination_port, packet_count, etc.)
    :return: Tuple of (RiskLevel, risk_score_float, reason_string)
    """
    context = context or {}
    threat_val = threat_type.value if hasattr(threat_type, "value") else str(threat_type)

    if threat_val == ThreatType.NORMAL.value:
        return RiskLevel.LOW, 0.0, "Normal network traffic pattern detected with no security anomaly."

    # 1. Base score from threat category baseline weight
    base_weight = THREAT_BASELINE_WEIGHTS.get(threat_val, 50.0) / 100.0

    # 2. Confidence scaling factor (higher ML confidence increases risk score)
    confidence_factor = max(0.0, min(1.0, confidence))

    # 3. Contextual modifiers (Critical port targeting, high packet rate)
    context_modifier = 0.0
    reasons_list = [f"ML Model identified '{threat_val}' with confidence {confidence_factor*100:.1f}%."]

    dst_port = context.get("destination_port") or context.get("Destination Port")
    if dst_port in CRITICAL_PORTS:
        context_modifier += 0.08
        reasons_list.append(f"Targeting critical service port {dst_port}.")

    packet_count = context.get("packet_count") or context.get("Total Fwd Packets", 0)
    if packet_count > 1000:
        context_modifier += 0.07
        reasons_list.append(f"High volume packet flow detected ({packet_count} packets).")

    # Combine factors: 50% threat baseline + 40% confidence + 10% context
    raw_score = (0.50 * base_weight) + (0.40 * confidence_factor) + context_modifier
    risk_score = round(max(0.0, min(1.0, raw_score)), 4)

    # Determine Risk Level based on thresholds
    if risk_score >= RISK_LEVEL_THRESHOLDS[RiskLevel.CRITICAL.value]:
        level = RiskLevel.CRITICAL
    elif risk_score >= RISK_LEVEL_THRESHOLDS[RiskLevel.HIGH.value]:
        level = RiskLevel.HIGH
    elif risk_score >= RISK_LEVEL_THRESHOLDS[RiskLevel.MEDIUM.value]:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    explanation = " ".join(reasons_list) + f" Calculated Risk Score: {risk_score:.2f}/1.00 ({level.value})."

    logger.debug(f"Risk Engine: Threat={threat_val}, Confidence={confidence:.2f}, Score={risk_score}, Level={level.value}")
    return level, risk_score, explanation
