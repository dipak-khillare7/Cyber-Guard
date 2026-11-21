# Audit Logging System

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Audit Logging Architecture
The audit logging engine provides an append-only audit trail recording all security-sensitive actions performed within the application.

```text
User / API Action
       ↓
Service Function (e.g. login, create user, analyze event)
       ↓
AuditService.log_event(db, action, user_id, username, resource_type, resource_id, ip_address, status, metadata)
       ↓
Persisted to `audit_logs` Database Table
```

---

## 2. Audit Event Categories
The following security actions generate persistent audit entries:

- `LOGIN_SUCCESS`: User successfully authenticated.
- `LOGIN_FAILURE`: Authentication attempt failed.
- `LOGOUT`: User session terminated.
- `USER_CREATED`: Administrator registered a new platform user.
- `USER_UPDATED`: User profile or active status modified.
- `EVENT_ANALYZED`: Security flow passed through AI Detection engine.
- `ALERT_UPDATED`: Alert status or assignee updated.
- `INCIDENT_UPDATED`: Incident severity or status modified.
- `RESPONSE_EXECUTED`: Simulated mitigation response recorded.

---

## 3. Schema & Data Model
```text
AuditLog
├── id (Integer, Primary Key)
├── user_id (Integer, Foreign Key to users.id, Optional)
├── username (String(100), Required)
├── action (String(100), Indexed)
├── resource_type (String(100), Optional)
├── resource_id (String(100), Optional)
├── ip_address (String(45), Optional)
├── user_agent (String(255), Optional)
├── status (String(50), Default "SUCCESS")
├── metadata_json (Text / JSON, Optional)
└── timestamp (DateTime UTC, Indexed)
```

---

## 4. Integrity & Retention
- **Append-Only Pattern**: Audit records can only be inserted by application services. No update or delete endpoints exist for audit logs.
- **Separation of Concepts**: Application audit logs (`audit_logs` table) record user/operator actions against the system. Security event logs (`security_events` table) record incoming network telemetry for threat detection.
