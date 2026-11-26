# Authentication System Documentation

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Authentication Architecture
The system uses JSON Web Tokens (JWT) for stateless, secure user authentication across API routes.

```text
User Submits Credentials (username, password)
       ↓
POST /api/v1/auth/login
       ↓
Verify User Active Status & Bcrypt Hash
       ↓
Generate Access Token (JWT signed with SECRET_KEY)
       ↓
Client Stores Token (e.g. Session Storage) & Attaches Bearer Token to Requests
       ↓
FastAPI Dependency (get_current_user) Decodes & Validates JWT
```

---

## 2. Password Security
- **Algorithm**: `bcrypt` (salted password hashing).
- **Storage**: Only the computed `hashed_password` is saved in the `users` table. Plaintext passwords are never logged, cached, or returned via any API endpoint.
- **Policy Enforcement**: Public registration requires at least 12 characters with upper/lowercase letters, a digit, and a special character. Managed user creation requires at least 8 characters. Passwords are capped at 72 characters/UTF-8 bytes where accepted.

---

## 3. JWT Token Specification
- **Signing Algorithm**: HMAC-SHA256 (`HS256`).
- **Secret Key**: Configured via environment variable `SECRET_KEY`.
- **Claims**:
  - `sub`: User ID string (`id`).
  - `role`: Operational role (`ADMIN`, `ANALYST`) or the legacy `VIEWER` value, which is denied protected access.
  - `iat`: Issued at timestamp (UTC).
  - `exp`: Expiration timestamp (UTC), controlled by `ACCESS_TOKEN_EXPIRE_MINUTES`.
- **Expiration Policy**: Default access tokens expire after 480 minutes (8 hours).

---

## 4. Public Authentication and Rate Limits
- Registration, email verification, and verification resend are public routes and remain usable without a Bearer token. A new account remains inactive until an Admin approves its request; email OTP verification is also required before login. Approval assigns `ANALYST`, and Analyst login routes to `/analyst/dashboard`. Public role fields do not affect the assigned role, and public registration cannot create `ADMIN` accounts.
- Verification codes are emailed, expire after 10 minutes, are single-use, and are invalidated after 5 failed attempts.
- Shared SQL-backed fixed-window limits apply: registration (5/minute per client IP), login (10/minute per client IP), verification (10/minute per IP and 5 attempts per email per 10 minutes), and resend (3/minute per IP).
- Rate-limit database failures reject the request with a safe `503`; throttled requests return `429` and `Retry-After`.

## 5. Initial Seed Administrator
For initial setup in development/lab environments:
- Seeded via `UserService.seed_initial_admin(db)`.
- Credentials configured through environment variables:
  - `ADMIN_USERNAME` (default: `admin`)
  - `ADMIN_INITIAL_PASSWORD` (no default; configure explicitly to seed the account)
- Production startup requires a configured seed password; no built-in password is used.
