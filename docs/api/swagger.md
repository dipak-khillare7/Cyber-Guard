# API Endpoints Specification (v1)

FastAPI automatically serves interactive Swagger UI at `/docs` and ReDoc at `/redoc`.

## Base Endpoint URL
`http://localhost:8000/api/v1`

## Key Endpoints

### Health Check
* `GET /api/v1/health`: Returns backend operational status and database connection state.

### Security Events
* `GET /api/v1/events?skip=0&limit=50&event_type=NETWORK`: Requires `ADMIN` or `ANALYST`; paginated list of ingested events.
* `POST /api/v1/events`: Requires `ADMIN` or `ANALYST`; ingests and validates a security event.
* `GET /api/v1/events/{id}`: Requires `ADMIN` or `ANALYST`; retrieves a single event by ID.

### Threat Detection
* `POST /api/v1/detection/analyze`: Requires `ADMIN` or `ANALYST`; analyzes and stores a network event and returns its detection/risk result.
* Detection history, trends, and statistics also require `ADMIN` or `ANALYST`.
* Both ingestion POST endpoints share limits of 120 requests per client IP and 30 requests per authenticated user per fixed 60-second window.
* Request bodies are limited to 65,536 bytes. IP addresses, ports, protocols, numeric flow values, and `raw_data` are validated; `raw_data` is limited to 4,096 characters.

### Authentication & Rate Limits
* Public registration and email verification remain unauthenticated.
* Database-backed limits are shared through the configured database: registration (5/minute per client IP), login (10/minute per client IP), email verification (10/minute per IP and 5 attempts per email per 10 minutes), and verification resend (3/minute per IP).
* A rate-limit store failure returns `503` (fail-closed); throttled requests return `429` with `Retry-After`.

### Threat Alerts
* `GET /api/v1/alerts?skip=0&limit=50&risk_level=HIGH`: Paginated list of threat alerts.
* `GET /api/v1/alerts/{id}`: Retrieves single alert details.
* `PATCH /api/v1/alerts/{id}`: Updates alert status (NEW, ACKNOWLEDGED, RESOLVED, IGNORED).

### Incidents & Response
* `GET /api/v1/incidents`: List all security incidents.
* `GET /api/v1/incidents/{id}`: Get single incident including response history.
* `POST /api/v1/incidents/{id}/response`: Executes safe simulated response action.

### Statistics & Metrics
* `GET /api/v1/statistics`: Returns real database-derived counts, critical threat counts, and category breakdowns.
