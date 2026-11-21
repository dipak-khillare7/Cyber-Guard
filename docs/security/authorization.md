# Authorization & Role-Based Access Control (RBAC)

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Role Hierarchy & Matrix
The system implements explicit Role-Based Access Control (RBAC) with three distinct operational roles:

| Role | Permissions & Capabilities |
| :--- | :--- |
| **`ADMIN`** | User management (create, list, update role/account status), platform-wide SOC operations, audit-log access, and alert/incident/response-action management. |
| **`ANALYST`** | Platform-wide SOC access: investigate events, view and update alerts/incidents, view simulated response actions, and view audit logs. Cannot manage users. |
| **`VIEWER`** | Normal User access: submit events and view only their own events, detection history/trends, and statistics. Cannot access SOC alert, incident, response-action, audit-log, or user-management endpoints. |

`VIEWER` remains the stored role for Normal Users, so existing accounts and records need no role migration.

---

## 2. Backend Enforcement Mechanism
Role permissions are strictly enforced at the FastAPI router level using dependency injections:

```python
# Example Admin Guard Dependency
def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Requires ADMIN permissions."
        )
    return current_user
```

### Protection Rules
- `GET /api/v1/auth/users`, `POST /api/v1/auth/users`, `PATCH /api/v1/auth/users/{id}`: Requires `ADMIN`
- `GET /api/v1/alerts` and `GET /api/v1/alerts/{id}`: Requires `ADMIN` or `ANALYST`
- `GET /api/v1/incidents` and `GET /api/v1/incidents/{id}`: Requires `ADMIN` or `ANALYST`
- `GET /api/v1/response-actions`: Requires `ADMIN` or `ANALYST`
- `GET /api/v1/audit-logs`: Requires `ADMIN` or `ANALYST`
- Alert updates, incident operations, and simulated response execution: Requires `ADMIN` or `ANALYST`
- `GET /api/v1/detection/history`, event reads, and statistics: Requires an authenticated user; `VIEWER` results are owner-scoped
- `POST /api/v1/events`: Requires any active authenticated role; Viewer-owned events remain scoped to that Viewer
- `POST /api/v1/detection/analyze`: Requires any active authenticated role; resulting event ownership is scoped for Viewers
- Public registration and email verification remain unauthenticated.

---

## 3. Object-Level Authorization (BOLA Defense)
Normal User event and detection-result lookups are scoped by the authenticated user's ID; requests for another user's event do not disclose the record. SOC alert and incident endpoints are not available to `VIEWER` at all. Analysts and Admins have platform-wide access to those SOC records, subject to authentication and role checks.

An Admin-only user update operation supports role/account changes. The API rejects empty or null update fields and prevents demoting or deactivating the last active Admin. Role changes are recorded in the audit log without recording submitted passwords.

The current backend does not expose a runtime platform-configuration endpoint. Configuration remains outside this RBAC surface until a concrete, non-secret settings allowlist is implemented.
