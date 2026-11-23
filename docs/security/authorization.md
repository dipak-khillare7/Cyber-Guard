# Authorization & Role-Based Access Control (RBAC)

## Project
**AI-Based Cybersecurity Threat Detection and Response System**

---

## 1. Role Hierarchy & Matrix
The system enforces role-based access control for the two operational roles:

| Role | Permissions & Capabilities |
| :--- | :--- |
| **`ADMIN`** | User management (create, list, update role/account status), platform-wide SOC operations, audit-log access, and alert/incident/response-action management. |
| **`ANALYST`** | Platform-wide SOC access: investigate events, view and update alerts/incidents, view simulated response actions, and view audit logs. Cannot manage users. |
| **`VIEWER`** | Legacy role retained for existing user records. It has no access to SOC or user-only application endpoints. |

Public registrations continue to receive `VIEWER`; public input cannot choose a role or grant Analyst/Admin privileges. An Administrator must explicitly assign an operational role. Existing role records are retained without a database migration.

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
- Event reads and ingestion, detection analysis/history/trends, statistics: Requires `ADMIN` or `ANALYST`
- Public registration and email verification remain unauthenticated.

---

## 3. Legacy Account Handling
Existing `VIEWER` accounts remain in the users table and can authenticate, but receive Access Denied in the frontend and `403` for SOC APIs. The website-checker and Viewer-specific access-request endpoints are removed. Existing event ownership columns and related records are retained; they are not modified or deleted.

An Admin-only user update operation supports role/account changes. The API rejects empty or null update fields and prevents demoting or deactivating the last active Admin. Role changes are recorded in the audit log without recording submitted passwords.

The current backend does not expose a runtime platform-configuration endpoint. Configuration remains outside this RBAC surface until a concrete, non-secret settings allowlist is implemented.
