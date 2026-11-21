from app.services.risk_service import calculate_risk
from app.schemas.enums import ThreatType, RiskLevel


def test_calculate_risk_normal_threat():
    level, score, reason = calculate_risk(ThreatType.NORMAL, confidence=0.99)
    assert level == RiskLevel.LOW
    assert score == 0.0
    assert "Normal network traffic" in reason


def test_calculate_risk_critical_threat():
    level, score, reason = calculate_risk(ThreatType.DATA_EXFILTRATION, confidence=0.95, context={"destination_port": 443})
    assert level == RiskLevel.CRITICAL
    assert score >= 0.85
    assert "DATA_EXFILTRATION" in reason


def test_calculate_risk_score_bounds():
    level, score, reason = calculate_risk(ThreatType.DOS_DDOS, confidence=1.5)
    assert score <= 1.0
