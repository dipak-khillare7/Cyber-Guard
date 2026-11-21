# AI-Based Cybersecurity Threat Detection and Response System

A modular, secure, and maintainable academic prototype developed for a B.Tech Computer Engineering final-year project. The platform ingests security network events, performs validation, evaluates threat risk using a trained machine learning model (CIC-IDS2017), manages security alerts and incidents, triggers safe simulated response actions, and presents real-time analytics through an interactive Security Operations Center (SOC) dashboard.

---

## 1. Architecture Overview

```text
Security Event Ingestion (FastAPI / POST /api/v1/detection/analyze)
      ↓
Preprocessing & Data Validation (Pydantic / DataPreprocessor)
      ↓
ML Threat Classification (Scikit-learn Model / ThreatPredictor Interface)
      ↓
Dynamic Threat Category Mapping (BENIGN, DOS, BRUTE_FORCE, WEB_ATTACK, etc.)
      ↓
Risk & Severity Assessment (Risk Engine / calculate_risk)
      ↓
Alert Generation (Alert Service)
      ↓
Incident Management (Incident Service)
      ↓
Simulated Response Engine (ResponseService / SIMULATED_BLOCK, SIMULATED_ISOLATION)
      ↓
Persistent Storage (MySQL / SQLite via SQLAlchemy 2.0 ORM)
      ↓
SOC Web Dashboard (React 18 + Vite + Recharts + Lucide)
```

---

## 2. Technology Stack

* **Backend**: Python 3.12+, FastAPI, Pydantic V2, SQLAlchemy 2.0 ORM, PyMySQL, Uvicorn
* **Database**: MySQL (production) / SQLite (local dev fallback)
* **Machine Learning Engine**: Scikit-Learn, Pandas, NumPy, Joblib (Trained on CIC-IDS2017 feature vector)
* **Frontend**: React 18, Vite, React Router DOM v6, Axios, Recharts, Lucide Icons, Custom SOC Dark Theme
* **Testing**: Pytest, FastAPI TestClient

---

## 3. Project Directory Structure

```text
AI-Cyber-Threat-Detection/
├── backend/
│   ├── app/
│   │   ├── api/            # Versioned API routes (/api/v1/health, detection, alerts, incidents, statistics, response-actions)
│   │   ├── core/           # Configuration settings, logging with redaction, security utilities
│   │   ├── database/       # SQLAlchemy engine, session factory, table creation scripts
│   │   ├── ml/             # DataPreprocessor, ModelTrainer, ThreatPredictor interfaces
│   │   ├── models/         # ORM entities (SecurityEvent, Detection, Alert, Incident, ResponseAction)
│   │   ├── schemas/        # Pydantic V2 validation schemas & threat enums
│   │   ├── services/       # Decoupled business logic (Event, Alert, Incident, Risk, Response)
│   │   └── main.py         # FastAPI application entry point
│   ├── tests/              # Pytest automated test suite (24 tests)
│   ├── requirements.txt    # Python dependencies
│   └── pytest.ini          # Pytest path configuration
├── frontend/
│   ├── src/
│   │   ├── components/     # Reusable SOC UI components (Dashboard, Detections, Alerts, Incidents, Modals, Recharts)
│   │   ├── pages/          # Dashboard, Detections, Alerts, Incidents, ResponseActions, Settings
│   │   ├── services/       # Centralized Axios API client & service endpoints
│   │   ├── hooks/          # React hooks for statistics, detections, alerts, incidents
│   │   ├── utils/          # Date & formatting utilities
│   │   ├── App.jsx         # Router layout setup
│   │   └── main.jsx        # React root entry
│   ├── package.json        # Frontend dependencies
│   └── README.md           # Frontend setup documentation
├── dataset/
│   ├── raw/                # Unprocessed CSV datasets
│   └── processed/          # Preprocessed feature-engineered datasets
├── ml/
│   ├── training/           # Model training scripts (train.py, evaluate.py)
│   ├── preprocessing/      # Feature pipeline scripts
│   └── models/             # Serialized model binaries (threat_model.joblib, metadata.json)
└── README.md
```

---

## 4. Installation & Setup

### Prerequisites

* Python 3.12+
* Node.js 18+ and npm
* Git

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd AI-Cyber-Threat-Detection
```

### Step 2: Backend Setup

```bash
cd backend
python -m venv venv

# On Windows:
.\venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### Step 3: Frontend Setup

```bash
cd ../frontend
npm install
```

---

## 5. Running the Project

### Running Backend API Server

```bash
cd backend
.\venv\Scripts\activate  # Windows
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

FastAPI Interactive API Documentation:
* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`

### Running Frontend SOC Dashboard

```bash
cd frontend
npm run dev
```

Open your browser at `http://localhost:5173`.

### Email verification configuration

Copy `backend/.env.example` to `backend/.env` and configure `SMTP_HOST`, `SMTP_PORT`,
and `SMTP_FROM_EMAIL` before accepting registrations. SMTP username
and password must either both be set or both be empty (for an unauthenticated relay).
Port 465 uses implicit TLS; other configured ports use STARTTLS. Use real deployment
secrets in environment configuration only; never commit them. Without a configured
SMTP relay, registration and resend requests return a configuration error and no
verification code is exposed by the API.

The first-party registration page is `/register` (also the application root). Public
accounts receive the Viewer role and cannot sign in until they enter the emailed
6-digit code. Verification codes expire after 10 minutes and can only be used once.
Existing admin-created accounts and the seeded administrator remain verified.

Viewer accounts can read only security events, alerts, incidents, response actions,
and summary metrics owned by their account. Analyst and Admin roles retain system-wide
visibility. Existing records without an owner remain available to Analyst/Admin
accounts and are not exposed to Viewers.

---

## 6. Running Test Suite

To run the automated backend & ML test suite:

```bash
cd backend
.\venv\Scripts\activate
pytest -v
```

All 24 unit, ML inference, and API integration tests will run cleanly against an isolated in-memory SQLite database instance.

To run the frontend production build verification:

```bash
cd frontend
npm run build
```

---

## 7. Current Project Status

- **Phase 1 Complete**: Base Architecture, Database ORM schemas, Core API.
- **Phase 2 Complete**: ML Pipeline, Feature Extraction, Model Training & Evaluation (CIC-IDS2017).
- **Phase 3 Complete**: AI Detection Engine, Threat Classifier, Risk Engine, Alert & Incident Engine, Response Simulation.
- **Phase 4 Complete**: SOC Security Monitoring Web Dashboard (React + Vite + Recharts + Real API Data Integration).

---

## 8. Next Recommended Phase

**Phase 5 — Authentication, Authorization, Security Hardening, Audit Logging, and Production Readiness**
