# AI Threat Detection & Risk Engine Documentation (Phase 3)

## 1. Architecture Overview

```text
               SECURITY EVENT (POST /api/v1/detection/analyze)
                                      │
                                      ↓
                             ┌────────────────┐
                             │ Input Validator│ (Pydantic V2 AnalyzeEventRequest)
                             └───────┬────────┘
                                     ↓
                             ┌────────────────┐
                             │ Feature Mapper │ (Feature Compatibility Layer)
                             └───────┬────────┘
                                     ↓
                             ┌────────────────┐
                             │  ML Predictor  │ (HistGradientBoosting v1.0.0 Joblib Pipeline)
                             └───────┬────────┘
                                     ↓
                        Threat Classification & Confidence
                                     ↓
                             ┌────────────────┐
                             │  Risk Engine   │ (Transparent Risk Score 0.0 - 1.0)
                             └───────┬────────┘
                                     ↓
                             ┌────────────────┐
                             │ Alert Engine   │ (Alert Generation & Deduplication)
                             └───────┬────────┘
                                     ↓
                             ┌────────────────┐
                             │ Incident Engine│ (Created for HIGH / CRITICAL Risk)
                             └───────┬────────┘
                                     ↓
                             ┌────────────────┐
                             │Response Policy │ (Safe Simulation Mode: SIMULATED_BLOCK, etc.)
                             └───────┬────────┘
                                     ↓
                            Database Persistence
```

---

## 2. Risk Engine Evaluation Methodology

The Risk Engine calculates a transparent numerical risk score ($0.0 \le \text{Score} \le 1.0$) based on three distinct factors:

$$\text{Risk Score} = 0.50 \times \text{BaseWeight} + 0.40 \times \text{MLConfidence} + \text{ContextModifier}$$

### Risk Level Thresholds
* **CRITICAL**: Score $\ge 0.85$
* **HIGH**: Score $\ge 0.65$
* **MEDIUM**: Score $\ge 0.35$
* **LOW**: Score $< 0.35$

---

## 3. Alert Deduplication Strategy
To prevent alert fatigue:
* Incoming alerts with identical `source_ip` and `threat_type` within a **5-minute rolling window** are automatically deduplicated.
* Repeat activity notes are appended to the active alert message rather than creating redundant database rows.

---

## 4. Response Simulation Policy

| Risk Level | Threat Category | Action Type | Action Status | Description |
|---|---|---|---|---|
| `LOW` | `NORMAL` | `LOG` | `SIMULATED` | Logged to audit stream for routine monitoring |
| `MEDIUM` | `PORT_SCAN` / `BRUTE_FORCE` | `ALERT` | `SIMULATED` | High priority notification sent to SOC queue |
| `HIGH` | `WEB_ATTACK` / `DOS_DDOS` | `SIMULATED_BLOCK` | `SIMULATED` | Virtual firewall buffer block rule generated |
| `CRITICAL` | `BOTNET` / `INFILTRATION` | `SIMULATED_ISOLATION` | `SIMULATED` | Target host flagged for virtual isolation & escalation |

---

## 5. Performance Latency Benchmarks
* **Average End-to-End Latency**: $86.19\text{ ms}$
* **Median Latency**: $76.39\text{ ms}$
* **Minimum Latency**: $61.30\text{ ms}$
