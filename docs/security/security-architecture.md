# Security Architecture Specification

## 1. System Defense-in-Depth Model

```text
SOC Analyst / Admin / Unapproved account
            ↓
React 18 Web Dashboard (Client Display Boundary & Auth Context)
            ↓
HTTP Security Headers & CORS Controls Middleware
            ↓
Request Body Size Limit (65,536 bytes)
            ↓
Authentication Layer (OAuth2 Bearer JWT Validation / Password Verification)
            ↓
Authorization Layer (Role-Based Access Control: ADMIN, ANALYST; legacy VIEWER is denied)
            ↓
Shared SQL-Backed Rate Limiter (authentication & event ingestion)
            ↓
FastAPI Versioned REST API Controller (/api/v1)
            ↓
Input Validation & Sanitization (Pydantic V2 / IP & Port Rules)
            ↓
Service Logic Layer (Detection Engine, Risk Engine, Alert Service, Incident Service, Response Engine)
            ↓
Audit Logging Engine (Immutable Database Audit Trail)
            ↓
SQLAlchemy 2.0 ORM Parameterized Query Interface
            ↓
Database Layer (MySQL Production / SQLite Dev Storage)
            ↳ rate_limit_buckets (HMAC-keyed fixed-window counters)
```

## 2. Core Security Boundaries

1. **Client Control vs Server Authority**: The React frontend provides UI controls and client-side role display filtering for user convenience. The FastAPI backend independently validates authentication tokens and enforces object-level access control on every incoming API request.
2. **Predictive Integrity Protection**: Prediction models, confidence scores, and risk values are computed server-side in Python. Clients cannot submit custom risk levels or bypass classification rules.
3. **Simulated Response Mode**: All response actions (`SIMULATED_BLOCK`, `SIMULATED_ISOLATION`) run in safe simulation mode, ensuring no real operating system network rules or live endpoints are disrupted.
4. **Data Redaction & Secret Shielding**: Application logs redact matching sensitive key/value entries. SQLAlchemy bound parameters are hidden in debug SQL output. Ingestion validation and rate-limit logs omit request bodies, credentials, and tokens.

## 3. Cryptographic Controls

- **Password Hashing**: Native bcrypt with salt generation (`bcrypt.hashpw`).
- **Token Signing**: JSON Web Tokens (JWT) signed with `HS256` using server-managed secret keys (`SECRET_KEY`).
- **Token Expiration**: Configurable lifetime via `ACCESS_TOKEN_EXPIRE_MINUTES` (Default: 480 minutes / 8 hours).
