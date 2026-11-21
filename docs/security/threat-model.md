# Application Threat Model

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Overview
This document presents the application threat model for the AI-Based Cybersecurity Threat Detection and Response System. The threat model follows STRIDE principles (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) tailored to application security risks.

---

## 2. Threat Matrix & Mitigations

### 2.1 Authentication Threats
| Threat Category | Risk Description | Severity | Mitigation Implemented |
| :--- | :--- | :--- | :--- |
| **Brute-Force & Credential Stuffing** | Attackers repeatedly attempt logins to guess credentials | HIGH | Bcrypt password hashing, shared database-backed rate limiting on authentication routes, generic authentication failure responses |
| **Weak Passwords** | Users create simple, easily guessable passwords | MEDIUM | Strong password policy enforcement (minimum 8 characters, complex validation rules) |
| **Token Theft & Misuse** | JWT access tokens intercepted or stolen from storage | HIGH | Short-lived JWT expiration (`ACCESS_TOKEN_EXPIRE_MINUTES`), HTTP-only cookie support option, Bearer token verification |

### 2.2 Authorization & Access Control Threats
| Threat Category | Risk Description | Severity | Mitigation Implemented |
| :--- | :--- | :--- | :--- |
| **Privilege Escalation** | Low-privilege users attempt administrative endpoints | CRITICAL | Mandatory backend RBAC enforcement (`ADMIN`, `ANALYST`, `VIEWER`), FastAPI dependency guards |
| **BOLA / IDOR** | Manipulating resource IDs to access unauthorized objects | HIGH | Object-level permission checks in backend routes (`GET /alerts/{id}`, `PATCH /incidents/{id}`) |
| **Frontend Bypass** | Client-side role tampering in React | HIGH | Backend is the single authoritative security boundary; client state checks are for UX only |

### 2.3 API & Data Integrity Threats
| Threat Category | Risk Description | Severity | Mitigation Implemented |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Malicious SQL syntax in query parameters or payloads | CRITICAL | SQLAlchemy ORM parameterized queries; strict typing; regex sanitizers |
| **Mass Assignment** | Clients submit protected fields (`model_version`, `risk_score`) | HIGH | Strict input schema separation (`Create`, `Update`, `Response` models) |
| **Malformed Payload & Oversized Requests** | Denial of service via huge JSON blobs | MEDIUM | Pydantic strict field validation and request body size limits |

### 2.4 ML & Security Record Integrity Threats
| Threat Category | Risk Description | Severity | Mitigation Implemented |
| :--- | :--- | :--- | :--- |
| **ML Model Tampering** | Client forces `risk_level="LOW"` or alters predictions | CRITICAL | ML prediction, risk scoring, and model version strictly server-side calculated |
| **Audit Log Repudiation** | Users edit or delete historical audit entries | HIGH | Immutable append-only audit trail logging system with restricted database access |
| **Simulated Action Escalation** | Real-world execution of destructive network actions | CRITICAL | All automated response actions explicitly forced into `SIMULATED` execution mode |

---

## 3. Security Boundary Verification
```text
[ React SOC Frontend ] 
       │ (TLS HTTP/JSON with JWT Bearer Token)
       ▼
[ Security Middleware & Headers ]
       │
       ▼
[ FastAPI Authentication & RBAC Guard ]
       │
       ▼
[ Service Orchestration Layer ]
       ├── ML Inference Engine (Read-Only Artifacts)
       ├── Risk Assessment Engine (Server Controlled)
       └── Audit Logging Engine (Append-Only)
       │
       ▼
[ Database Layer (Parameterized Queries / ORM) ]
```
