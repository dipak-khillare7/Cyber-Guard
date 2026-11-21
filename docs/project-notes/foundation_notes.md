# Project Foundation Phase Notes

## Key Design Achievements
* Monorepo architecture established with separate `backend/`, `frontend/`, `dataset/`, `ml/`, `docs/`, and `scripts/`.
* Abstracted SQLAlchemy 2.0 database layer fully supporting both MySQL (`mysql+pymysql`) and SQLite (`sqlite:///`).
* Pydantic V2 schemas for thorough IP address format, port range (0-65535), and enum input validation.
* Decoupled Risk Engine (`risk_service.py`) returning calculated risk score (0-100), risk level (LOW/MEDIUM/HIGH/CRITICAL), and explanation string.
* Decoupled Response Engine (`response_service.py`) running in safe SIMULATION mode.
* ML Architecture skeleton (`DataPreprocessor`, `ModelTrainer`, `ThreatPredictor`) with versioned metadata (`metadata.json`).
* React + Vite Frontend Dashboard retrieving real statistics from `GET /api/v1/statistics` (displays 0 for empty database without generating fake metrics).
* Pytest backend suite with 100% test pass rate across 14 tests.
