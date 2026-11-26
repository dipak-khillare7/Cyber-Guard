# API Endpoints Specification (v1)

FastAPI automatically serves interactive Swagger UI at `/docs` and ReDoc at `/redoc`.

## Base Endpoint URL
`http://localhost:8000/api/v1`

## Key Endpoints

### Health Check
* `GET /api/v1/health`: Returns backend operational status and database connection state.

### Security Events
* `GET /api/v1/events?skip=0&limit=50&event_type=NETWORK`: Requires `ADMIN` or `ANALYST`; Analyst results are always scoped to the authenticated Analyst's own events. Admins retain platform-wide visibility.
* `POST /api/v1/events`: Requires `ADMIN` or `ANALYST`; ingests and validates a security event.
* `GET /api/v1/events/{id}`: Requires `ADMIN` or `ANALYST`; retrieves a single event by ID.

### Threat Detection
* `POST /api/v1/detection/analyze`: Requires `ADMIN` or `ANALYST`; analyzes and stores a network event and returns its detection/risk result.
* Detection history, trends, and statistics also require `ADMIN` or `ANALYST`; Analyst results are ownership-scoped.
* Both ingestion POST endpoints share limits of 120 requests per client IP and 30 requests per authenticated user per fixed 60-second window.
* Request bodies are limited to 65,536 bytes. IP addresses, ports, protocols, numeric flow values, and `raw_data` are validated; `raw_data` is limited to 4,096 characters.

### Authentication & Rate Limits
* Public registration and email verification remain unauthenticated. Applicants must verify the emailed OTP and receive Admin approval before login; approval assigns `ANALYST` on the backend. Public role fields are ignored, and registration cannot create `ADMIN` accounts.
* `GET /api/v1/auth/analyst-requests?status=PENDING|APPROVED|REJECTED` lists requests for Admins. `POST /api/v1/auth/analyst-requests/{id}/approve` and `/reject` review a pending request and record the Admin and review timestamp.
* Database-backed limits are shared through the configured database: registration (5/minute per client IP), login (10/minute per client IP), email verification (10/minute per IP and 5 attempts per email per 10 minutes), and verification resend (3/minute per IP).
* A rate-limit store failure returns `503` (fail-closed); throttled requests return `429` with `Retry-After`.

### Threat Alerts
* `GET /api/v1/alerts?skip=0&limit=50&risk_level=HIGH`: Paginated list of threat alerts.
* `GET /api/v1/alerts/{id}`: Retrieves single alert details.
* `PATCH /api/v1/alerts/{id}`: Updates alert status (NEW, ACKNOWLEDGED, RESOLVED, IGNORED).
* Analyst list/detail/update operations only include the authenticated Analyst's alerts; requests for another Analyst's alert return `404`.

### Incidents & Response
* `GET /api/v1/incidents`: List all security incidents.
* `GET /api/v1/incidents/{id}`: Get single incident including response history.
* `POST /api/v1/incidents/{id}/response`: Executes safe simulated response action.
* Analyst incident and response-action operations are scoped to owned records. Admins retain platform-wide visibility and management.

### Data Ownership
* Ownership is assigned server-side from the authenticated account and carried from events to alerts, incidents, and response actions.
* Existing records without an identifiable owner remain unowned and are hidden from Analyst endpoints. Startup migration only propagates an owner where a parent record already has a known owner.

### Statistics & Metrics
* `GET /api/v1/statistics`: Returns real database-derived counts, critical threat counts, and category breakdowns.
