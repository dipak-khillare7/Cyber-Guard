# System Architecture Overview

## Data Flow Pipeline

```text
Security Event Ingestion
       ↓
Preprocessing & Data Validation (Pydantic / DataPreprocessor)
       ↓
ML Threat Detection (ThreatPredictor Interface)
       ↓
Threat Category Classification (ThreatType Enum)
       ↓
Risk & Severity Calculation (Risk Engine / calculate_risk)
       ↓
Security Alert Generation (Alert Service)
       ↓
Incident Creation & Management (Incident Service)
       ↓
Simulated Mitigation Response (Response Engine / ResponseService)
       ↓
Persistent Storage (MySQL / SQLite via SQLAlchemy 2.0 ORM)
       ↓
Web Monitoring Dashboard (React + Vite + Axios)
```

## Architecture Principles

1. **Decoupled Components**: Business logic, API routes, database models, ML inference, and response simulation are strictly separated.
2. **Academic Transparency**: Hard-coded heuristics are clearly labeled as baseline fallbacks; ML predictions and risk assessments maintain distinct boundaries.
3. **Safe Response Simulation**: Response actions run in simulation mode to allow safe, reproducible academic demonstrations without executing real destructive OS commands.
